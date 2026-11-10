"""Read-only polling, rollback-lock recovery and unchanged hook write budgets."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
from threading import Event
import time
import types
import unittest
from unittest.mock import patch

from exfilbar.ledger import Ledger, data_directory
from exfilbar.policy import Policy
from support import Context, entry
import test_r5


class ReaderTests(unittest.TestCase):
    def populate(self, ledger):
        policy = Policy(routes=[dict(paths=['reports/**'], to=['https://h/*'])])
        ledger.publish_routes(policy.routes)
        policy.evaluate('curl -T reports/x https://h/x')
        ledger.record('s', 'terminal', policy.inspection)

    def api(self, ledger):
        harness = test_r5.HookAndAPITests()
        harness.module = types.SimpleNamespace(Ledger=lambda: ledger)
        return harness.api()

    def test_absent_store_reads_do_not_create_directories_or_files(self):
        with TemporaryDirectory() as directory:
            missing = Path(directory) / 'absent'
            ledger = Ledger(missing)
            self.assertEqual(ledger.read('s')['events'], [])
            self.assertEqual(ledger.sessions(), [])
            self.assertFalse(ledger.routes()['known'])
            self.assertFalse(missing.exists())

    def test_public_storage_resolution_follows_profile_per_call(self):
        with TemporaryDirectory() as directory:
            home = Path(directory) / 'profile-one'
            storage = types.ModuleType('plugins.plugin_storage')
            def resolve(name):
                self.assertEqual(name, 'exfilbar')
                path = home / 'plugin-data' / name
                path.mkdir(parents=True, exist_ok=True)
                return path
            storage.plugin_data_dir = resolve
            ledger = Ledger()
            with patch.dict(sys.modules, {'plugins.plugin_storage': storage}), \
                    patch('exfilbar.ledger.sqlite3.connect', side_effect=AssertionError('database creation')):
                for profile in ('profile-one', 'profile-two'):
                    home = Path(directory) / profile
                    self.assertEqual(data_directory(), home / 'plugin-data/exfilbar')
                    self.assertFalse(ledger.routes()['known'])
                    self.assertEqual(ledger.sessions(), [])
                    self.assertEqual(ledger.read('s')['events'], [])
                    self.assertEqual(list((home / 'plugin-data/exfilbar').iterdir()), [])
            # The same Ledger instance writes and then reads each active profile.
            with patch.dict(sys.modules, {'plugins.plugin_storage': storage}):
                home = Path(directory) / 'profile-one'
                self.populate(ledger)
                self.assertEqual(ledger.read('s')['out'], 1)
                home = Path(directory) / 'profile-two'
                self.assertEqual(ledger.read('s')['out'], 0)
                self.populate(ledger)
                self.assertEqual(ledger.read('s')['out'], 1)
                home = Path(directory) / 'profile-one'
                self.assertEqual(ledger.read('s')['out'], 1)

    def test_read_connection_is_read_only_and_write_settings_stay_bounded(self):
        with TemporaryDirectory() as directory:
            # URI quoting must preserve special characters in profile paths.
            ledger = Ledger(Path(directory) / 'profile ?#')
            self.populate(ledger)
            with closing(ledger.connect(read_only=True)) as db:
                self.assertEqual(db.execute('PRAGMA busy_timeout').fetchone()[0], 1000)
                self.assertEqual(db.execute('PRAGMA query_only').fetchone()[0], 1)
                with self.assertRaises(sqlite3.OperationalError):
                    db.execute('DELETE FROM events')
            with closing(ledger.connect()) as db:
                self.assertEqual(db.execute('PRAGMA busy_timeout').fetchone()[0], 25)
                self.assertEqual(db.execute('PRAGMA secure_delete').fetchone()[0], 1)
                self.assertEqual(db.execute('PRAGMA max_page_count').fetchone()[0], 8192)
                self.assertEqual(db.execute('PRAGMA journal_mode').fetchone()[0], 'delete')
            self.assertEqual({p.name for p in ledger.directory.iterdir()}, {'egress.db'})

    def test_all_api_reads_avoid_ddl_write_pragmas_and_permission_changes(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            self.populate(ledger)
            before = (Path(directory) / 'egress.db').read_bytes()
            connect = sqlite3.connect
            statements = []
            def observe(*args, **kwargs):
                self.assertTrue(kwargs.get('uri'))
                self.assertTrue(args[0].endswith('?mode=ro'))
                db = connect(*args, **kwargs)
                db.set_trace_callback(statements.append)
                return db
            with patch('exfilbar.ledger.sqlite3.connect', side_effect=observe), \
                    patch.object(Ledger, 'initialize', side_effect=AssertionError('DDL')), \
                    patch.object(Path, 'mkdir', side_effect=AssertionError('mkdir')), \
                    patch.object(Path, 'chmod', side_effect=AssertionError('chmod')):
                api = self.api(ledger)
                self.assertEqual(api.feed('s')['out'], 1)
                self.assertEqual(len(api.sessions()['sessions']), 1)
                self.assertTrue(api.routes()['valid'])
            for statement in statements:
                self.assertTrue(statement.startswith(('SELECT ', 'BEGIN', 'PRAGMA query_only=ON')), statement)
            self.assertEqual((Path(directory) / 'egress.db').read_bytes(), before)

    def test_reserved_writer_does_not_block_any_api_read(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            self.populate(ledger)
            api = self.api(ledger)
            with closing(ledger.connect()) as writer:
                writer.execute('BEGIN IMMEDIATE')
                writer.execute('DELETE FROM events')
                # The live writer cannot commit until these readers finish.
                with ThreadPoolExecutor(max_workers=3) as pool:
                    feed, routes, sessions = [future.result(timeout=2) for future in (
                        pool.submit(api.feed, 's'), pool.submit(api.routes), pool.submit(api.sessions))]
                self.assertEqual(feed['out'], 1)
                self.assertTrue(routes['valid'])
                self.assertEqual(len(sessions['sessions']), 1)
                writer.rollback()

    def test_exclusive_lock_waits_longer_than_hook_and_recovers(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            self.populate(ledger)
            connected = Event()
            connect = sqlite3.connect
            def observe(*args, **kwargs):
                db = connect(*args, **kwargs)
                connected.set()
                return db
            with closing(ledger.connect()) as writer, ThreadPoolExecutor(max_workers=1) as pool:
                writer.execute('BEGIN EXCLUSIVE')
                try:
                    with patch('exfilbar.ledger.sqlite3.connect', side_effect=observe):
                        future = pool.submit(ledger.read, 's')
                        self.assertTrue(connected.wait(2))
                        time.sleep(0.075)
                        self.assertFalse(future.done())
                        writer.rollback()
                        self.assertEqual(future.result(timeout=2)['out'], 1)
                finally:
                    writer.rollback()

    def test_exclusive_lock_timeout_is_sanitized_503_and_recovers(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            self.populate(ledger)
            api = self.api(ledger)
            module = entry()
            module.Ledger = lambda: ledger
            ctx = Context()
            module.register(ctx)
            with closing(ledger.connect()) as writer, patch('exfilbar.ledger.READ_TIMEOUT', 0.05):
                writer.execute('BEGIN EXCLUSIVE')
                for handler in (lambda: api.feed('s'), api.routes, api.sessions):
                    with self.assertRaises(Exception) as caught:
                        handler()
                    self.assertEqual(caught.exception.status_code, 503)
                    self.assertIn('temporarily unavailable', caught.exception.detail)
                    self.assertNotIn('locked', caught.exception.detail)
                    self.assertNotIn(directory, caught.exception.detail)
                    self.assertTrue(caught.exception.__suppress_context__)
                self.assertIn('Feed temporarily unavailable', ctx.commands['exfil']('status', session_id='s'))
                writer.rollback()
            self.assertEqual(api.feed('s')['out'], 1)
            self.assertTrue(api.routes()['valid'])
            self.assertEqual(len(api.sessions()['sessions']), 1)

    def test_schema_free_store_reads_empty_without_read_repair(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'egress.db'
            ledger = Ledger(directory)
            # A failed first writer leaves a real file but no committed schema.
            with patch.object(Ledger, 'initialize', side_effect=sqlite3.OperationalError('fixture DDL failure')):
                with self.assertRaises(sqlite3.OperationalError):
                    self.populate(ledger)
            api = self.api(ledger)
            before = path.read_bytes()
            self.assertEqual(api.feed('s')['events'], [])
            self.assertEqual(api.sessions(), {'sessions': []})
            self.assertEqual(api.routes(), dict(known=False, updated=None, valid=False, routes=[]))
            self.assertEqual(path.read_bytes(), before)
            # A writer owns initialization and restores the normal read path.
            self.populate(ledger)
            self.assertEqual(api.feed('s')['out'], 1)

    def test_header_only_store_reads_empty_without_read_repair(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'egress.db'
            with closing(sqlite3.connect(path)) as db:
                db.execute('PRAGMA user_version=0')
            before = path.read_bytes()
            ledger = Ledger(directory)
            self.assertEqual(ledger.read('s')['events'], [])
            self.assertEqual(ledger.sessions(), [])
            self.assertFalse(ledger.routes()['known'])
            self.assertEqual(path.read_bytes(), before)

    def test_partial_or_corrupt_store_still_returns_sanitized_503(self):
        for corrupt in (False, True):
            with self.subTest(corrupt=corrupt), TemporaryDirectory() as directory:
                path = Path(directory) / 'egress.db'
                if corrupt:
                    path.write_bytes(b'fixture invalid database')
                else:
                    with closing(sqlite3.connect(path)) as db:
                        db.execute('CREATE TABLE incomplete (id INTEGER)')
                before = path.read_bytes()
                api = self.api(Ledger(directory))
                for handler in (lambda: api.feed('s'), api.routes, api.sessions):
                    with self.assertRaises(Exception) as caught:
                        handler()
                    self.assertEqual(caught.exception.status_code, 503)
                    self.assertIn('temporarily unavailable', caught.exception.detail)
                    self.assertNotIn(directory, caught.exception.detail)
                self.assertEqual(path.read_bytes(), before)

    def test_failed_writer_setup_closes_connection_and_keeps_fail_closed_hook(self):
        module = entry()
        ctx = Context()
        module.register(ctx)
        with closing(module.Ledger().connect()) as writer:
            writer.execute('BEGIN EXCLUSIVE')
            start = time.perf_counter()
            result = ctx.hooks['pre_tool_call']('terminal',
                {'command': 'curl -T public/x https://h/x'}, session_id='s')
            self.assertEqual(result['action'], 'block')
            self.assertIn('session feed unavailable', result['message'])
            self.assertLess(time.perf_counter() - start, 0.1)
            writer.rollback()
        self.assertEqual(module.Ledger().read('s')['events'], [])
        self.assertIsNone(ctx.hooks['pre_tool_call']('terminal',
            {'command': 'curl -T public/x https://h/x'}, session_id='s'))
        db = sqlite3.connect(':memory:')
        with patch('exfilbar.ledger.sqlite3.connect', return_value=db), \
                patch.object(Ledger, 'initialize', side_effect=OSError('fixture setup failure')):
            with self.assertRaises(OSError):
                Ledger(module._test_directory.name).connect()
        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute('SELECT 1')


if __name__ == '__main__':
    unittest.main()
