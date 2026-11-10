"""Bounded metadata ledger shared by hooks, slash commands and API readers."""
from contextlib import closing, contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from threading import Lock
from time import monotonic
from weakref import WeakValueDictionary
from .report import clean, destination, egress_destination, feed_labels

MAX_EVENTS = 128
MAX_SESSIONS = 32
MAX_PATHS = 32
WRITE_TIMEOUT = 0.025
WRITE_BUDGET = 0.050
READ_TIMEOUT = 1.0
_write_deadline = ContextVar('exfilbar_write_deadline', default=None)
_writer_locks = WeakValueDictionary()
_writer_locks_guard = Lock()


class WriterBusy(sqlite3.OperationalError):
    # Preserve the SQLite contention contract for off-hook callers that retry.
    # Python <3.11 runs the standalone demo but lacks named SQLite codes.
    sqlite_errorcode = getattr(sqlite3, 'SQLITE_BUSY', 5)
    sqlite_errorname = 'SQLITE_BUSY'


def writer_lock(directory):
    # Share a gate across Ledger instances, without retaining visited profiles.
    key = str(directory.resolve() / 'egress.db')
    with _writer_locks_guard:
        gate = _writer_locks.get(key)
        if gate is None:
            gate = Lock()
            _writer_locks[key] = gate
        return gate


def data_directory():
    # Public Hermes storage API, resolved per call to follow the active profile.
    # This helper may create an empty directory, but never opens a database.
    from plugins.plugin_storage import plugin_data_dir
    return plugin_data_dir('exfilbar')


def session_key(session):
    if not isinstance(session, str) or not session or len(session) > 4096:
        return ''
    return sha256(session.encode('utf-8')).hexdigest()


class Ledger:
    def __init__(self, directory=None, clock=None):
        self.directory = Path(directory) if directory is not None else None
        self.clock = clock or (lambda: datetime.now(timezone.utc).isoformat(timespec='seconds'))

    def connect(self, *, read_only=False, directory=None, timeout=WRITE_TIMEOUT):
        if directory is None:
            directory = self.directory if self.directory is not None else data_directory()
        path = directory / 'egress.db'
        if read_only:
            try:
                path.stat()
            except FileNotFoundError:
                return None
            db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=READ_TIMEOUT)
        else:
            directory.mkdir(parents=True, exist_ok=True)
            directory.chmod(0o700)
            db = sqlite3.connect(path, timeout=timeout)
        try:
            db.row_factory = sqlite3.Row
            if read_only:
                db.execute('PRAGMA query_only=ON')
                return db
            path.chmod(0o600)
            db.execute('PRAGMA secure_delete=ON')
            db.execute('PRAGMA max_page_count=8192')
            # Keep rollback journaling: WAL would retain evicted metadata in
            # sidecars outside secure_delete and the database allocation cap.
            if db.execute('PRAGMA user_version').fetchone()[0] != 1:
                self.initialize(db)
            return db
        except BaseException:
            db.close()
            raise

    @contextmanager
    def write_budget(self):
        # One writer-admission deadline per hook, including mirror failures.
        # Context-local state prevents simultaneous calls sharing a deadline.
        token = None
        if _write_deadline.get() is None:
            token = _write_deadline.set(monotonic() + WRITE_BUDGET)
        try:
            yield
        finally:
            if token is not None:
                _write_deadline.reset(token)

    @contextmanager
    def writer(self):
        with self.write_budget():
            directory = self.directory if self.directory is not None else data_directory()
            gate = writer_lock(directory)
            remaining = lambda: max(0, _write_deadline.get() - monotonic())
            if not gate.acquire(timeout=remaining()):
                raise WriterBusy('writer queue timeout')
            try:
                # Hold through setup, transaction commit/rollback and close.
                # Other processes still arbitrate through SQLite's <=25 ms wait.
                with closing(self.connect(directory=directory, timeout=min(WRITE_TIMEOUT, remaining()))) as db, db:
                    yield db
            finally:
                gate.release()

    @contextmanager
    def reader(self):
        db = self.connect(read_only=True)
        try:
            yield db
        finally:
            if db is not None:
                db.close()

    @staticmethod
    def initialize(db):
        db.executescript('''
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS sessions (session TEXT PRIMARY KEY, touched INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL,
                time TEXT NOT NULL, tool TEXT NOT NULL, paths TEXT NOT NULL,
                paths_truncated INTEGER NOT NULL, destination TEXT NOT NULL,
                decision TEXT NOT NULL, rule TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_session ON events(session, id);
            CREATE TABLE IF NOT EXISTS routes (position INTEGER PRIMARY KEY, paths TEXT NOT NULL, hosts TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            PRAGMA user_version=1;
            COMMIT;
        ''')

    def publish_routes(self, routes):
        """Mirror the configured routes for the read-only page: paths and allowed hosts only."""
        rows, details = [], []
        for i, (paths, targets) in enumerate(routes[:128], 1):
            raw_hosts = [destination(t, None).split('://', 1)[-1] for t in targets]
            hosts = list(dict.fromkeys(raw_hosts))
            kept_paths = list(paths[:MAX_PATHS])
            kept_hosts = hosts[:MAX_PATHS]
            # Broad permissions must survive a summary cap.
            if '*' in paths and '*' not in kept_paths:
                kept_paths[-1:] = ['*']
            if '*' in hosts and '*' not in kept_hosts:
                kept_hosts[-1:] = ['*']
            paths_shortened = sum(len(p) > 256 or not p.isprintable() for p in paths)
            hosts_shortened = sum(len(h) > 96 or not h.isprintable() for h in raw_hosts)
            details.append(dict(paths_truncated=len(paths) > MAX_PATHS or bool(paths_shortened),
                                hosts_truncated=len(hosts) > MAX_PATHS or bool(hosts_shortened),
                                paths_omitted=max(0, len(paths) - len(kept_paths)),
                                hosts_omitted=max(0, len(hosts) - len(kept_hosts)),
                                paths_shortened=paths_shortened,
                                hosts_shortened=hosts_shortened))
            rows.append((i, json.dumps([clean(p, 256) for p in kept_paths]), json.dumps([clean(h) for h in kept_hosts])))
        encoded = json.dumps(details)
        with self.writer() as db:
            db.execute('BEGIN IMMEDIATE')
            current = [tuple(r) for r in db.execute('SELECT position,paths,hosts FROM routes ORDER BY position')]
            meta = dict(db.execute('SELECT key,value FROM meta'))
            if meta.get('routes_valid') == '1' and current == rows and meta.get('routes_details') == encoded:
                return
            db.execute('DELETE FROM routes')
            db.executemany('INSERT INTO routes VALUES (?,?,?)', rows)
            db.executemany('INSERT OR REPLACE INTO meta VALUES (?,?)', [
                ('routes_updated', clean(self.clock(), 40)), ('routes_valid', '1'),
                ('routes_details', encoded)])

    def invalidate_routes(self):
        """Keep the last valid policy and its timestamp, but mark it stale."""
        with self.writer() as db:
            db.execute("INSERT OR REPLACE INTO meta VALUES ('routes_valid', '0')")

    def routes(self):
        with self.reader() as db:
            if db is None:
                return {'known': False, 'updated': None, 'valid': False, 'routes': []}
            db.execute('BEGIN')
            rows = db.execute('SELECT position,paths,hosts FROM routes ORDER BY position').fetchall()
            meta = dict(db.execute('SELECT key,value FROM meta'))
        details = json.loads(meta.get('routes_details', '[]'))
        return {'known': 'routes_updated' in meta, 'updated': meta.get('routes_updated'),
                'valid': meta.get('routes_valid') == '1',
                'routes': [dict(position=r['position'], paths=json.loads(r['paths']), hosts=json.loads(r['hosts']),
                                **(details[i] if i < len(details) else {})) for i, r in enumerate(rows)]}

    def record(self, session, tool, inspection):
        key = session_key(session)
        if not key or not inspection:
            return
        rows = []
        for transfer, paths, verdict in inspection[-MAX_EVENTS:]:
            known = list(dict.fromkeys(p for p in paths if p is not None))
            decision = 'blocked' if verdict.blocked else ('allowed by route' if verdict.route else 'allowed')
            # No command, code, file contents, URL paths, credentials or queries.
            rule = verdict.reason
            if verdict.route:
                rule += '; ' + verdict.route
            if verdict.pattern:
                rule += '; rule=' + (destination(verdict.pattern) if '://' in verdict.pattern else clean(verdict.pattern))
            rows.append((key, clean(self.clock(), 40), tool, json.dumps([clean(p, 256) for p in known[:MAX_PATHS]]),
                         int(len(known) > MAX_PATHS or any(len(p) > 256 for p in known)),
                         egress_destination(transfer.destination, transfer.family), decision, clean(rule, 512)))
        # Only the retained tail is inserted, even for a huge compound call.
        with self.writer() as db:
            db.executemany('INSERT INTO events(session,time,tool,paths,paths_truncated,destination,decision,rule) VALUES (?,?,?,?,?,?,?,?)', rows)
            last = db.execute('SELECT MAX(id) FROM events').fetchone()[0]
            db.execute('INSERT OR REPLACE INTO sessions VALUES (?,?)', (key, last))
            db.execute('DELETE FROM events WHERE session=? AND id NOT IN (SELECT id FROM events WHERE session=? ORDER BY id DESC LIMIT ?)', (key, key, MAX_EVENTS))
            db.execute('DELETE FROM sessions WHERE session NOT IN (SELECT session FROM sessions ORDER BY touched DESC LIMIT ?)', (MAX_SESSIONS,))
            db.execute('DELETE FROM events WHERE session NOT IN (SELECT session FROM sessions)')

    def read(self, session, *, hashed=False):
        key = session if hashed else session_key(session)
        result = {'events': [], 'out': 0, 'blocked': 0, 'limit': MAX_EVENTS,
                  'notice': 'Inspected attempts only. Delivery is not confirmed.'}
        if not key:
            return result
        with self.reader() as db:
            if db is None:
                return result
            rows = db.execute('SELECT time,tool,paths,paths_truncated,destination,decision,rule FROM events WHERE session=? ORDER BY id DESC LIMIT ?', (key, MAX_EVENTS)).fetchall()
        for row in reversed(rows):
            event = dict(row)
            event['paths'] = json.loads(event['paths'])
            event['paths_truncated'] = bool(event['paths_truncated'])
            event['decision'], event['rule'] = feed_labels(event['decision'], event['rule'])
            result['events'].append(event)
            result['blocked' if event['decision'] == 'blocked' else 'out'] += 1
        return result

    def sessions(self):
        with self.reader() as db:
            if db is None:
                return []
            return [dict(row) for row in db.execute(
                'SELECT s.session AS key, MAX(e.time) AS time FROM sessions s JOIN events e ON e.session=s.session GROUP BY s.session ORDER BY s.touched DESC LIMIT ?',
                (MAX_SESSIONS,)).fetchall()]


def format_feed(feed):
    lines = [f"Session feed: {len(feed['events'])} recent transfers; {feed['out']} out; {feed['blocked']} blocked. Retained limit {feed['limit']}.", feed['notice']]
    for event in feed['events']:
        paths = ', '.join(event['paths']) or 'unresolved'
        if event['paths_truncated']:
            paths += ' (truncated)'
        decision, rule = feed_labels(event['decision'], event['rule'])
        label = decision + (' · ' + rule if rule else '')
        lines.append(' | '.join((event['time'], event['tool'], paths, event['destination'], label)))
    return '\n'.join(lines)
