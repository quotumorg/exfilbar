"""Round-five regressions inspect inert strings without executing clients."""
import unittest
from exfilbar.parse import parse
from exfilbar.policy import Policy
from support import Context, admission_clock, entry


class UploadReviewTests(unittest.TestCase):
    forms = (
        'aws s3 sync {source} s3://good/up --exclude "*.tmp"',
        'aws --no-cli-pager s3api put-object --bucket good --key up --body {source}',
        'aws s3api put-object --body={source} --bucket good --key up --content-type text/plain',
        'gh gist create {source} --public --desc example',
        'gh api repos/org/good/contents/up -F file=@{source}',
        'gh api -X POST repos/org/good/contents/up --field=file=@{source}',
        'gh api repos/org/good/contents/up --input={source}',
        'gh issue create --title example --body-file {source} -R org/good',
        'gh issue create --title example -F{source} -R org/good',
        'gh pr create --title example --body-file={source} -R org/good',
    )

    def test_sources_and_uncertainty(self):
        for form in self.forms:
            for source in ('private/x', 'reports/x'):
                base = form.format(source=source)
                for command in (base, base + ' 2>&1', '>/dev/null ' + base):
                    for unresolved in (True, False):
                        with self.subTest(command=command, unresolved=unresolved):
                            self.assertEqual(parse(command)[0].sources, (source,))
                            self.assertTrue(parse(command)[0].unresolved)
                            policy = Policy(block_unresolved=unresolved, routes=[
                                dict(paths=['reports/**'], to=['*'])])
                            verdict = policy.evaluate(command)
                            self.assertEqual(verdict.blocked, unresolved or source.startswith('private/'))
                            if source.startswith('private/'):
                                self.assertEqual(verdict.reason, 'protected path rule')
                            self.assertFalse(verdict.route)

    def test_mv_routes_and_controls(self):
        for source in ('private/x', 'reports/x'):
            for target in ('good', 'bad'):
                for unresolved in (True, False):
                    command = f'aws s3 mv {source} s3://{target}/up --no-sign-request --cli-read-timeout=60'
                    policy = Policy(block_unresolved=unresolved, routes=[
                        dict(paths=['reports/**'], to=['s3://good/*'])])
                    self.assertFalse(parse(command)[0].unresolved)
                    self.assertEqual(policy.evaluate(command).blocked,
                                     source.startswith('private/') or target == 'bad')
        for command in ('aws s3 mv s3://good/up reports/x',
                        'aws s3 sync s3://good/ reports/ --exclude "*.tmp"',
                        'aws s3 sync reports/ s3://good/ --dryrun',
                        'aws s3 mv s3://good/up s3://other/up',
                        'gh api repos/org/good', 'gh api endpoint -f email=user@example.org', 'gh gist list',
                        'gh issue create --title example --body hello'):
            with self.subTest(command=command):
                self.assertEqual(parse(command), [])
        for command in ('gh api repos/org/good', 'gh api endpoint -f email=user@example.org', 'gh gist list', 'gh issue list'):
            for form in (command + ' >log', '>log ' + command):
                self.assertEqual(parse(form), [])

    def test_redirects_and_multiple_sources(self):
        for form in self.forms + ('aws s3 mv {source} s3://good/up',):
            command = form.format(source='reports/x')
            for redirected in ('>log ' + command, command + ' >log'):
                self.assertTrue(Policy().evaluate(redirected).blocked, redirected)
        for command in ('gh gist create reports/x private/y',
                        'gh api endpoint -F a=@reports/x -F b=@private/y'):
            self.assertEqual(parse(command)[0].sources, ('reports/x', 'private/y'))
            self.assertTrue(Policy(block_unresolved=False).evaluate(command).blocked)

    def test_registered_hook_and_feed(self):
        plugin = entry()
        ctx = Context(block_unresolved=False)
        plugin.register(ctx)
        commands = [form.format(source='private/x') for form in self.forms]
        commands.append('aws s3 mv private/x s3://good/up')
        with admission_clock(type(plugin.Ledger())):
            for command in commands:
                result = ctx.hooks['pre_tool_call']('terminal', {'command': command}, session_id='r5')
                self.assertEqual(result['action'], 'block', command)
                self.assertIn('protected path', result['message'])
        feed = plugin.Ledger().read('r5')
        self.assertEqual(feed['blocked'], len(commands))
        self.assertTrue(all(row['paths'] == ['private/x'] for row in feed['events']))
