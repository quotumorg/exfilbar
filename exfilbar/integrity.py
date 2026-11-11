"""Offline integrity for minimized decision metadata, not delivery receipts."""
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets

FIELDS = ('session', 'time', 'tool', 'paths', 'paths_truncated',
          'destination', 'decision', 'rule')


def canonical(value):
    """Version 1: UTF-8 JSON, sorted keys, no whitespace, ASCII escapes."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('utf-8')


def local_key(db, *, create=False):
    directory = Path(db.execute('PRAGMA database_list').fetchone()[2]).parent
    path = directory / 'integrity.key'
    if create:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, 'wb') as output:
                output.write(secrets.token_bytes(32))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        key = source.read(33)
    if len(key) != 32:
        raise ValueError('invalid local integrity key')
    return key


def append_records(db, rows, signed=False):
    # The caller holds BEGIN IMMEDIATE. SQLite serializes the anchor, key
    # creation and head update across processes as well as the local queue.
    meta = dict(db.execute("SELECT key,value FROM meta WHERE key LIKE 'chain_%'"))
    if 'chain_install' not in meta:
        install = secrets.token_hex(32)
        legacy = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        meta = dict(chain_install=install, chain_legacy=str(legacy),
                    chain_count='0', chain_head=sha256(canonical(
                        dict(version=1, install=install, legacy=legacy))).hexdigest(),
                    chain_signed='0')
    count, prev = int(meta['chain_count']), meta['chain_head']
    tail = db.execute('SELECT id,hash FROM decision_chain ORDER BY id DESC LIMIT 1').fetchone()
    if (tail is None and count) or (tail is not None and tuple(tail) != (count, prev)):
        raise ValueError('decision chain head mismatch')
    signed = signed or meta['chain_signed'] == '1'
    key = local_key(db, create=meta['chain_signed'] != '1') if signed else None
    if meta['chain_signed'] == '1':
        last = db.execute('SELECT payload,hmac FROM decision_chain WHERE id=?', (count,)).fetchone()
        if last is None or not hmac.compare_digest(
                hmac.new(key, last['payload'].encode('utf-8'), sha256).hexdigest(), last['hmac']):
            raise ValueError('local integrity key mismatch')
    for row in rows:
        cursor = db.execute('INSERT INTO events(session,time,tool,paths,paths_truncated,destination,decision,rule) VALUES (?,?,?,?,?,?,?,?)', row)
        count += 1
        record = dict(zip(FIELDS, row))
        record['paths'] = json.loads(record['paths'])
        payload = canonical(dict(version=1, install=meta['chain_install'],
            legacy=int(meta['chain_legacy']), index=count, event_id=cursor.lastrowid,
            prev=prev, signed=signed, record=record))
        digest = sha256(payload).hexdigest()
        mac = hmac.new(key, payload, sha256).hexdigest() if signed else ''
        db.execute('INSERT INTO decision_chain VALUES (?,?,?,?,?,?)',
                   (count, cursor.lastrowid, payload.decode('utf-8'), prev, digest, mac))
        prev = digest
    meta.update(chain_count=str(count), chain_head=prev, chain_signed='1' if signed else '0')
    db.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', meta.items())


def verify(db, *, require_hmac=False):
    """Stream the authoritative history in one read snapshot; never create keys."""
    result = dict(intact=True, records=0, legacy=0, signed=0, broken=None)
    if db is None:
        return result
    # Version 0.5.4 stores have no chain schema. Verification never migrates.
    if db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='decision_chain'").fetchone() is None:
        if db.execute("SELECT 1 FROM meta WHERE key LIKE 'chain_%' LIMIT 1").fetchone() is not None:
            return dict(result, intact=False, broken=1)
        result['legacy'] = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        return result
    meta = dict(db.execute("SELECT key,value FROM meta WHERE key LIKE 'chain_%'"))
    if 'chain_install' not in meta:
        if not meta and db.execute('SELECT 1 FROM decision_chain LIMIT 1').fetchone() is None:
            result['legacy'] = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            return result
        return dict(result, intact=False, broken=1)
    index, key = 1, None
    try:
        result['legacy'] = int(meta['chain_legacy'])
        prev = sha256(canonical(dict(version=1, install=meta['chain_install'],
                                    legacy=result['legacy']))).hexdigest()
        for row in db.execute('SELECT * FROM decision_chain ORDER BY id'):
            payload = json.loads(row['payload'])
            encoded = canonical(payload)
            if (row['id'] != index or row['prev'] != prev or payload['prev'] != prev or
                    payload['version'] != 1 or payload['index'] != index or
                    payload['install'] != meta['chain_install'] or
                    payload['legacy'] != result['legacy'] or
                    payload['event_id'] != row['event_id'] or
                    row['payload'].encode('utf-8') != encoded or
                    sha256(encoded).hexdigest() != row['hash']):
                raise ValueError('broken record')
            if payload['signed']:
                if key is None:
                    key = local_key(db)
                if not hmac.compare_digest(hmac.new(key, encoded, sha256).hexdigest(), row['hmac']):
                    raise ValueError('broken authentication')
                result['signed'] += 1
            elif row['hmac'] or result['signed']:
                raise ValueError('authentication downgrade')
            # The feed is a cache of this history. Detect edits to retained rows
            # too, without requiring evicted metadata to remain in the feed.
            event = db.execute('SELECT ' + ','.join(FIELDS) + ' FROM events WHERE id=?',
                               (row['event_id'],)).fetchone()
            if event is not None:
                record = dict(event)
                record['paths'] = json.loads(record['paths'])
                if record != payload['record']:
                    raise ValueError('feed record mismatch')
            prev = row['hash']
            result['records'] += 1
            index += 1
        if (int(meta['chain_count']) != result['records'] or meta['chain_head'] != prev or
                (meta['chain_signed'] == '1') != bool(result['signed'])):
            raise ValueError('broken head')
        if require_hmac and result['records'] and not result['signed']:
            index = 1
            raise ValueError('authentication required')
    except (ValueError, KeyError, TypeError, OSError):
        result.update(intact=False, broken=index)
    return result


def format_verification(result):
    if result['intact']:
        text = f"{result['records']} records, chain intact"
    else:
        text = f"chain broken at index {result['broken']}"
    if result['legacy']:
        text += f"; {result['legacy']} legacy records precede the chain (unverified)"
    if result['signed']:
        text += f"; {result['signed']} HMAC records checked with the local key"
    return text
