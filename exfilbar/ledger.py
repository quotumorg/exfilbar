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
        db = sqlite3.connect(directory / 'egress.db', timeout=2)
        (directory / 'egress.db').chmod(0o600)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA secure_delete=ON')
        db.execute('PRAGMA max_page_count=8192')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS sessions (session TEXT PRIMARY KEY, touched INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT NOT NULL,
                time TEXT NOT NULL, tool TEXT NOT NULL, paths TEXT NOT NULL,
                paths_truncated INTEGER NOT NULL, destination TEXT NOT NULL,
                decision TEXT NOT NULL, rule TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_session ON events(session, id);
        ''')
        return db

    def record(self, session, tool, inspection):
        key = session_key(session)
        if not key or not inspection:
            return
        rows = []
        for transfer, paths, verdict in inspection:
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
            db.executemany('INSERT INTO events(session,time,tool,paths,paths_truncated,destination,decision,rule) VALUES (?,?,?,?,?,?,?,?)', rows[-MAX_EVENTS:])
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
