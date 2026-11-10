"""Budget and metadata regressions for the 2026-11-09 hostile review."""
from contextlib import closing
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch
from exfilbar.code import inspect_code
from exfilbar.ledger import Ledger, MAX_EVENTS
from exfilbar.parse import Transfer, remote
from exfilbar.policy import Policy, Verdict
from support import Context, entry


class BudgetTests(unittest.TestCase):
    def test_remote_boundaries_without_backtracking(self):
        for value in ('user@host:x', '@:x', 'rsync://host/x', 'host:x'):
            self.assertTrue(remote(value))
        for value in ('@' * 12000, 'local/file', '/absolute:x', 'has space:x'):
            self.assertFalse(remote(value))

    def test_every_source_is_normalized_once(self):
        policy = Policy()
        with patch.object(policy, 'normalize', wraps=policy.normalize) as normalize:
            result = policy.decide([Transfer('curl', ('public/x', 'public/x'), 'https://a/x'),
                                    Transfer('curl', ('public/x',), 'https://b/x')])
        self.assertFalse(result.blocked)
        self.assertEqual(normalize.call_count, 1)

    def test_submitted_python_reuses_normalized_sources(self):
        policy = Policy(routes=[dict(paths=['reports/**'], to=['https://h/*'])])
        code = 'import requests; ' + ';'.join(['requests.post("https://h/x", data=open("reports/x"))'] * 10)
        with patch.object(policy, 'normalize', wraps=policy.normalize) as normalize:
            self.assertFalse(inspect_code(policy, code).blocked)
        self.assertEqual([call.args[0] for call in normalize.call_args_list].count('reports/x'), 1)

    def test_multiplication_and_compound_budget_fail_closed_even_with_pass_setting(self):
        commands = [
            'curl ' + '-T public/x ' * 500 + ' '.join(['https://h/x'] * 500),
            'wget --post-file=x ' + ' '.join(['https://h/x'] * 1100),
            'cat ' + ' '.join(['public/x'] * 500) + ' | mail ' + ' '.join(['h'] * 500),
            ';'.join(['curl -Tx -Ty https://h/x'] * 600),
        ]
        for command in commands:
            with self.subTest(size=len(command)):
                policy = Policy(block_unresolved=False)
                self.assertTrue(policy.evaluate(command).blocked)
                self.assertIn('too many transfer pairs', policy.inspection[-1][2].reason)
                self.assertEqual(len(policy.inspection), 1)

    def test_only_retained_tail_is_constructed(self):
        class MustNotInspect:
            def __iter__(self):
                raise AssertionError('evicted metadata was inspected')
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            keep = (Transfer('curl', ('x',), 'https://h/x'), ('x',), Verdict())
            ledger.record('s', 'terminal', [(None, MustNotInspect(), None)] * 500 + [keep] * MAX_EVENTS)
            self.assertEqual(ledger.read('s')['out'], MAX_EVENTS)

    def test_lock_waits_are_bounded_and_feed_failure_blocks(self):
        module = entry()
        ctx = Context(routes=[dict(paths=['reports/**'], to=['https://h/*'])])
        module.register(ctx)
        with closing(module.Ledger().connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            ctx.settings['routes'] = [dict(paths=['reports/**'], to=['https://other/*'])]
            start = time.perf_counter()
            result = ctx.hooks['pre_tool_call']('terminal', {'command': 'curl -T reports/x https://other/x'}, session_id='s')
            elapsed = time.perf_counter() - start
            self.assertEqual(result['action'], 'block')
            self.assertIn('session feed unavailable', result['message'])
            self.assertLess(elapsed, 0.1)
            db.rollback()

    def test_initialized_read_does_not_run_schema_ddl(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            ledger.publish_routes([])
            with patch.object(Ledger, 'initialize', side_effect=AssertionError('read ran DDL')):
                ledger.routes()
                ledger.sessions()
                ledger.read('s')
