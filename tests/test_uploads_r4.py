"""Round-four user paths, inspected as text without executing clients."""
import unittest
from exfilbar.parse import parse
from exfilbar.policy import Policy
from support import Context, admission_clock, entry


class UploadReviewTests(unittest.TestCase):
    def test_nonupload_clients_with_output_redirects(self):
        for command in ('gh pr view 12', 'gh release list', 'aws s3 ls',
                        'aws sts get-caller-identity'):
            for form in (command, command + ' >output.txt', '>output.txt ' + command,
                         command + ' 2>&1', command + ' >/dev/null'):
                with self.subTest(command=form):
                    self.assertEqual(parse(form), [])
                    self.assertFalse(Policy().evaluate(form).blocked)

    def test_common_aws_download_options(self):
        for command in (
            'aws s3 cp s3://good/up reports/x --no-cli-pager',
            'aws --no-sign-request s3 cp s3://good/up reports/x',
            'aws s3 cp s3://good/ reports/ --recursive --exclude "*" --include "*.csv"',
            'aws s3 cp s3://good/up s3://other/up --no-cli-pager',
            'aws s3 cp s3://good/up reports/x --endpoint-url https://custom.example',
        ):
            with self.subTest(command=command):
                self.assertEqual(parse(command), [])

    def test_aws_options_preserve_upload_routes_and_protection(self):
        options = ('--no-cli-pager', '--no-sign-request',
                   '--exclude "*.tmp" --include "*.csv"',
                   '--cli-connect-timeout 30 --cli-read-timeout=60')
        for option in options:
            for source in ('reports/x', 'private/x'):
                for host in ('good', 'bad'):
                    command = f'aws s3 cp {source} s3://{host}/up {option}'
                    for form in (command, command + ' 2>&1', '>/dev/null ' + command):
                        for unresolved in (True, False):
                            with self.subTest(command=form, unresolved=unresolved):
                                transfers = parse(form)
                                self.assertEqual(transfers[0].sources, (source,))
                                self.assertFalse(transfers[0].unresolved)
                                policy = Policy(routes=[dict(paths=['reports/**'], to=['s3://good/*'])],
                                                block_unresolved=unresolved)
                                self.assertEqual(policy.evaluate(form).blocked,
                                                 source.startswith('private/') or host == 'bad')
        for command in ('aws s3 cp reports/ s3://good/ --recursive --exclude "*.tmp"',
                        'aws s3 cp reports/x s3://good/up --unknown',
                        'gh release upload v1 reports/x -R org/good >log',
                        '>log gh release upload v1 reports/x -R org/good',
                        '>log aws s3 cp reports/x s3://good/up'):
            with self.subTest(command=command):
                self.assertTrue(Policy().evaluate(command).blocked)

    def test_controls_through_registered_hook_do_not_record_uploads(self):
        plugin = entry()
        ctx = Context()
        plugin.register(ctx)
        with admission_clock(type(plugin.Ledger())):
            for command in ('gh pr view 12 >pr.txt', '>list.txt aws s3 ls',
                            'aws s3 cp s3://good/up reports/x --no-cli-pager'):
                self.assertIsNone(ctx.hooks['pre_tool_call']('terminal', {'command': command},
                                                           session_id='r4'))
        self.assertEqual(plugin.Ledger().read('r4')['events'], [])
