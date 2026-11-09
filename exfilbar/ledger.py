"""Bounded metadata ledger shared by hooks, slash commands and API readers."""
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from .report import clean, destination, egress_destination, feed_labels

MAX_EVENTS = 128
MAX_SESSIONS = 32
MAX_PATHS = 32


def data_directory():
    # Public Hermes storage API, resolved per call to follow the active profile.
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

    def connect(self):
        directory = self.directory if self.directory is not None else data_directory()
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o700)
        db = sqlite3.connect(directory / 'egress.db', timeout=0.025)
        (directory / 'egress.db').chmod(0o600)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA secure_delete=ON')
        db.execute('PRAGMA max_page_count=8192')
        if db.execute('PRAGMA user_version').fetchone()[0] == 1:
            return db
        self.initialize(db)
        return db

    @staticmethod
    def initialize(db):
        db.executescript('''
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
        with closing(self.connect()) as db, db:
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
        with closing(self.connect()) as db, db:
            db.execute("INSERT OR REPLACE INTO meta VALUES ('routes_valid', '0')")

    def routes(self):
        with closing(self.connect()) as db, db:
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
        with closing(self.connect()) as db, db:
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
        with closing(self.connect()) as db:
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
        with closing(self.connect()) as db:
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
