"""Queue expiry, interruption and transaction outcome regressions."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Event
import unittest
from unittest.mock import patch

from exfilbar.ledger import Ledger, PendingWrite, WriterBusy, record_batch, session_key
from exfilbar.policy import Policy
from support import Context, entry

GOOD = 'curl -T reports/x https://uploads.example/x'


class WriteQueueTests(unittest.TestCase):
    def inspection(self):
        policy = Policy()
        policy.evaluate(GOOD)
        return policy.inspection

    def test_interrupted_pending_caller_does_not_orphan_queue_head(self):
        for error in (RuntimeError('interrupted wait'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), TemporaryDirectory() as directory:
                ledger = Ledger(directory)
                batch = record_batch(Path(directory))
                batch.active = True
                with patch.object(batch.condition, 'wait', side_effect=error):
                    with self.assertRaises(type(error)):
                        ledger.record('cancelled', 'terminal', self.inspection())
                self.assertEqual(batch.pending, [])
                batch.active = False
                ledger.record('recovered', 'terminal', self.inspection())
                self.assertEqual(ledger.read('cancelled')['events'], [])
                self.assertEqual(ledger.read('recovered')['out'], 1)

    def test_expired_head_is_rejected_before_owning_transaction(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            now = [10.0]
            with patch('exfilbar.ledger.monotonic', side_effect=lambda: now[0]):
                with ledger.write_budget():
                    now[0] += 1
                    with self.assertRaises(WriterBusy):
                        ledger.record('expired', 'terminal', self.inspection())
            self.assertEqual(ledger.read('expired')['events'], [])

    def test_expired_follower_is_pruned_even_before_it_wakes(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            batch = record_batch(Path(directory))
            # A sleeping follower already passed its deadline. Its invalid row
            # must never reach SQLite or poison the valid caller's transaction.
            expired = PendingWrite([('invalid',)], 0)
            batch.pending.append(expired)
            ledger.record('valid', 'terminal', self.inspection())
            self.assertTrue(expired.done)
            self.assertIsInstance(expired.error, WriterBusy)
            self.assertEqual(expired.rows, [])
            self.assertEqual(batch.pending, [])
            self.assertEqual(ledger.read('valid')['out'], 1)

    def test_gate_acquired_after_deadline_does_not_start_a_write(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            now = [10.0]
            class LateGate:
                released = False
                def acquire(self, timeout):
                    now[0] += timeout + 0.001
                    return True
                def release(self):
                    self.released = True
            gate = LateGate()
            with patch('exfilbar.ledger.monotonic', side_effect=lambda: now[0]), \
                    patch('exfilbar.ledger.writer_lock', return_value=gate):
                with self.assertRaises(WriterBusy):
                    ledger.record('late', 'terminal', self.inspection())
            self.assertTrue(gate.released)
            self.assertEqual(ledger.read('late')['events'], [])

    def test_bounded_batches_preserve_session_eviction_and_event_retention(self):
        with TemporaryDirectory() as directory, ThreadPoolExecutor(max_workers=19) as pool:
            ledger = Ledger(directory)
            inspection = self.inspection()
            expected = {}
            for i in range(32):
                ledger.record(str(i), 'terminal', inspection)
                expected[session_key(str(i))] = 1
            batch = record_batch(Path(directory))
            entered, release = Event(), Event()
            original, transactions, order = ledger.record_rows, {}, []
            def write_rows(db, rows):
                key = rows[0][0]
                transactions[db] = transactions.get(db, 0) + 1
                order.append((key, len(rows)))
                original(db, rows)
                if key == session_key('leader'):
                    entered.set()
                    if not release.wait(2):
                        raise RuntimeError('fixture timeout')
            with patch.object(Ledger, 'record_rows', side_effect=write_rows):
                first = pool.submit(ledger.record, 'leader', 'terminal', inspection)
                try:
                    self.assertTrue(entered.wait(2))
                    names = ['31'] * 3 + [f'new-{i}' for i in range(15)]
                    others = [pool.submit(ledger.record, name, 'terminal', inspection * 128)
                              for name in names]
                    with batch.condition:
                        self.assertTrue(batch.condition.wait_for(lambda: len(batch.pending) == 18, 1))
                finally:
                    release.set()
                first.result(timeout=2)
                for future in others:
                    future.result(timeout=2)
            self.assertEqual(sorted(transactions.values()), [1, 2, 16])
            for key, count in order:
                expected[key] = min(128, expected.pop(key, 0) + count)
                while len(expected) > 32:
                    del expected[next(iter(expected))]
            self.assertEqual([s['key'] for s in ledger.sessions()], list(reversed(expected)))
            for key, count in expected.items():
                self.assertEqual(ledger.read(key, hashed=True)['out'], count)
            self.assertEqual(ledger.read('0')['events'], [])
            self.assertEqual(ledger.read('31')['out'], 128)
            self.assertFalse(batch.active)
            self.assertEqual(batch.pending, [])

    def test_owner_interruption_rolls_back_and_wakes_followers_as_storage_errors(self):
        with TemporaryDirectory() as directory, ThreadPoolExecutor(max_workers=3) as pool:
            ledger = Ledger(directory)
            batch = record_batch(Path(directory))
            entered, release = Event(), Event()
            original = ledger.record_rows
            def write_rows(db, rows):
                original(db, rows)
                if rows[0][0] == session_key('leader'):
                    entered.set()
                    if not release.wait(2):
                        raise RuntimeError('fixture timeout')
                else:
                    raise KeyboardInterrupt('owner interrupted')
            with patch.object(Ledger, 'record_rows', side_effect=write_rows):
                first = pool.submit(ledger.record, 'leader', 'terminal', self.inspection())
                try:
                    self.assertTrue(entered.wait(2))
                    others = [pool.submit(ledger.record, name, 'terminal', self.inspection())
                              for name in ('one', 'two')]
                    with batch.condition:
                        self.assertTrue(batch.condition.wait_for(lambda: len(batch.pending) == 2, 1))
                finally:
                    release.set()
                first.result(timeout=2)
                errors = []
                for future in others:
                    try:
                        future.result(timeout=2)
                    except BaseException as exc:
                        errors.append(exc)
                self.assertEqual(sum(isinstance(e, KeyboardInterrupt) for e in errors), 1)
                self.assertEqual(sum(isinstance(e, sqlite3.OperationalError) for e in errors), 1)
            self.assertFalse(batch.active)
            self.assertEqual(batch.pending, [])
            for name in ('one', 'two'):
                self.assertEqual(ledger.read(name)['events'], [])
            ledger.record('recovered', 'terminal', self.inspection())
            self.assertEqual(ledger.read('recovered')['out'], 1)

    def test_commit_failure_blocks_registered_hook_and_rolls_back(self):
        module = entry()
        ctx = Context()
        module.register(ctx)
        connect = sqlite3.connect
        class FailedCommit(sqlite3.Connection):
            def __exit__(self, *args):
                self.rollback()
                raise sqlite3.OperationalError('fixture commit failure')
        def fail_commit(*args, **kwargs):
            return connect(*args, **kwargs, factory=FailedCommit)
        with patch('sqlite3.connect', side_effect=fail_commit):
            result = ctx.hooks['pre_tool_call']('terminal', {'command': GOOD}, session_id='s')
        self.assertEqual(result['action'], 'block')
        self.assertIn('session feed unavailable', result['message'])
        self.assertEqual(module.Ledger().read('s')['events'], [])
        self.assertIsNone(ctx.hooks['pre_tool_call']('terminal', {'command': GOOD}, session_id='s'))
        self.assertEqual(module.Ledger().read('s')['out'], 1)


if __name__ == '__main__':
    unittest.main()
