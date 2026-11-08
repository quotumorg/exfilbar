"""Run the host's real plugin scanner against the complete publication tree."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from support import ROOT


class InstallScanTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('HERMES_SOURCE'),
                         'HERMES_SOURCE is unset; set it to a prepared Hermes source checkout to run the real plugin scanner')
    def test_publication_tree_is_safe(self):
        source = Path(os.environ['HERMES_SOURCE']).resolve()
        scanner_path = source / 'tools/plugin_guard.py'
        self.assertTrue(scanner_path.is_file(), 'HERMES_SOURCE must contain tools/plugin_guard.py')
        with patch.object(sys, 'path', [str(source), *sys.path]):
            from tools import plugin_guard
            self.assertEqual(Path(plugin_guard.__file__).resolve(), scanner_path,
                             'The scanner must come from HERMES_SOURCE')
            result = plugin_guard.scan_plugin(ROOT)
        severe = [finding for finding in result.findings
                  if finding.severity in ('critical', 'high')]
        self.assertEqual(severe, [], f'Install-blocking findings: {severe}')
        self.assertEqual(result.verdict, 'safe', f'Unexpected scan verdict: {result}')
