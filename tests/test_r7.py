"""Desktop display regressions; enforcement and stored metadata stay intact."""
from contextlib import closing
from dataclasses import replace
from tempfile import TemporaryDirectory
import unittest

from exfilbar.ledger import Ledger, format_feed, session_key
from exfilbar.policy import Policy
from exfilbar.report import format_verdict
from support import Context, entry
from test_integration import source_root
from test_r5 import ROUTES, GOOD, BAD


class DisplayTests(unittest.TestCase):
    def test_route_block_and_check_are_markdown_plain(self):
        # markdown-text.tsx preprocesses prose with markdown-preprocess.ts.
        # Its CITATION_MARKER_RE strips orphan numeric brackets after a letter.
        # Streamdown also interprets brackets, HTML, emphasis and code spans.
        # Exact regression rule for the reported block: no square/angle bracket,
        # asterisk, paired underscore span, or backtick anywhere in the message.
        ctx = Context(routes=ROUTES)
        entry().register(ctx)
        result = ctx.hooks['pre_tool_call']('terminal', {'command': BAD})
        self.assertEqual(result['action'], 'block')
        expected = ('Exfilbar | BLOCK | curl | off route; allowed hosts: uploads.example'
                    ' | path=reports/weekly.csv | route=route 1 | destination=https://elsewhere.example')
        self.assertEqual(result['message'], expected)
        checked = ctx.commands['exfil']('check ' + BAD)
        self.assertEqual(checked, expected.replace('Exfilbar', 'dry run', 1))
        for message in (result['message'], checked):
            self.assertNotRegex(message, r'[\[\]<>*`]|_[^_\n]+_')

    def test_renderer_source_explains_the_lost_number(self):
        desktop = source_root() / 'apps/desktop/src'
        renderer = (desktop / 'components/assistant-ui/markdown-text.tsx').read_text()
        preprocess = (desktop / 'lib/markdown-preprocess.ts').read_text()
        compact = (desktop / 'components/chat/compact-markdown.tsx').read_text()
        self.assertIn('preprocessMarkdown(text)', renderer)
        self.assertIn('StreamdownTextPrimitive', renderer)
        self.assertIn('<Streamdown', compact)
        citation_rule = r'''/(?<=[\p{L}\p{N})\].,!?:;"'”’])\[(?:\d+(?:\s*,\s*\d+)*)\](?!\()/gu'''
        self.assertIn('const CITATION_MARKER_RE = ' + citation_rule, preprocess)
        self.assertIn('.replace(CITATION_MARKER_RE, marker => {', preprocess)
        self.assertIn("return ids.every(id => sourceListIds.has(id)) ? marker : ''", preprocess)

    def test_same_numbering_for_multiple_and_high_routes(self):
        policy = Policy(routes=ROUTES * 128)
        verdict = policy.evaluate(GOOD)
        self.assertFalse(verdict.blocked)
        # Internal identifiers remain compatible with stored rule metadata.
        self.assertEqual(verdict.route.split(',')[0], 'routes[1]')
        self.assertEqual(verdict.route.split(',')[-1], 'routes[128]')
        self.assertIn('route=route 1, route 2', format_verdict(verdict))
        self.assertIn('route=route 128', format_verdict(replace(verdict, route='routes[128]')))
        description = policy.describe_routes()
        self.assertTrue(description.startswith('route 1 |'))
        self.assertIn('\nroute 128 |', description)
        self.assertNotIn('routes[', description)

    def test_legacy_ledger_display_without_rewriting_rows(self):
        with TemporaryDirectory(prefix='exfilbar-r7-') as directory:
            ledger = Ledger(directory, clock=lambda: '2000-01-01T00:00:00+00:00')
            policy = Policy(routes=ROUTES)
            for command in (GOOD, BAD):
                policy.evaluate(command)
                ledger.record('legacy', 'terminal', policy.inspection)
            def stored():
                with closing(ledger.connect()) as db:
                    return [tuple(row) for row in db.execute(
                        'SELECT decision,rule FROM events WHERE session=? ORDER BY id',
                        (session_key('legacy'),))]
            before = stored()
            self.assertEqual(before, [
                ('allowed by route', 'allowed by route; routes[1]'),
                ('blocked', 'off route; allowed hosts: uploads.example; routes[1]')])
            feed = ledger.read('legacy')
            self.assertEqual((feed['out'], feed['blocked']), (1, 1))
            self.assertEqual([(e['decision'], e['rule']) for e in feed['events']], [
                ('allowed', 'route 1'),
                ('blocked', 'off route; allowed hosts: uploads.example · route 1')])
            status = format_feed(feed)
            self.assertIn(' | allowed · route 1\n', status)
            self.assertTrue(status.endswith(' | blocked · off route; allowed hosts: uploads.example · route 1'))
            self.assertNotIn('routes[', status)
            self.assertNotIn('allowed by route', status)
            # format_feed also accepts old raw event metadata directly.
            for event, (decision, rule) in zip(feed['events'], before):
                event.update(decision=decision, rule=rule)
            self.assertEqual(format_feed(feed), status)
            self.assertEqual(stored(), before)

    def test_status_command_uses_same_feed_labels(self):
        ctx = Context(routes=ROUTES)
        entry().register(ctx)
        hook = ctx.hooks['pre_tool_call']
        self.assertIsNone(hook('terminal', {'command': GOOD}, session_id='r7'))
        self.assertEqual(hook('terminal', {'command': BAD}, session_id='r7')['action'], 'block')
        status = ctx.commands['exfil']('status', session_id='r7')
        self.assertIn(' | allowed · route 1\n', status)
        self.assertTrue(status.endswith(' | blocked · off route; allowed hosts: uploads.example · route 1'))
