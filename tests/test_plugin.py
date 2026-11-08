import unittest
from support import Context, entry

class PluginTests(unittest.TestCase):
    def setUp(self):
        self.ctx = Context()
        entry().register(self.ctx)
        self.hook = self.ctx.hooks['pre_tool_call']
    def test_registration(self):
        self.assertEqual(set(self.ctx.hooks), {'pre_tool_call'})
        self.assertEqual(set(self.ctx.commands), {'exfil'})
    def test_hook_read_only(self):
        args = {'command':'scp private/a host:inbox'}
        self.assertEqual(self.hook('terminal', args, session_id='fixture')['action'], 'block')
        self.assertEqual(args, {'command':'scp private/a host:inbox'})
        self.assertIsNone(self.hook('terminal', {'command':'cp private/a public/a'}))
        self.assertIsNone(self.hook('other', args))
        self.assertEqual(self.hook('terminal', {})['action'], 'block')
    def test_check_and_demo(self):
        self.assertTrue(self.ctx.commands['exfil']('check scp private/a host:inbox').startswith('dry run | BLOCK'))
        self.assertIn('fixture |', self.ctx.commands['exfil']('demo'))
    def test_bounded_session(self):
        for i in range(40):
            self.hook('terminal', {'command':'scp public/a host:x'}, session_id='fixture')
        self.assertIn('40 recent transfers; 40 out; 0 blocked', self.ctx.commands['exfil']('status', session_id='fixture'))
        self.assertIn('0 recent transfers', self.ctx.commands['exfil']('status', session_id='other'))
    def test_live_settings(self):
        self.ctx.settings['protected_globs'] = ['exports/**']
        self.assertIsNone(self.hook('terminal', {'command':'scp private/a host:inbox'}))
        self.assertEqual(self.hook('terminal', {'command':'scp exports/a host:inbox'})['action'], 'block')

    def test_terminal_workdir(self):
        self.ctx.settings['workspace_root'] = '/workspace'
        result = self.hook('terminal', {'command':'scp data.csv host:inbox', 'workdir':'/workspace/private'})
        self.assertEqual(result['action'], 'block')
