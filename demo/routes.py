"""One-command registered-hook rehearsal with isolated stdlib storage."""
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]


def render():
    spec = importlib.util.spec_from_file_location('route_demo_plugin', ROOT / '__init__.py',
                                                submodule_search_locations=[str(ROOT)])
    plugin = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = plugin
    spec.loader.exec_module(plugin)
    fixture = json.loads((ROOT / 'tests/fixtures/routes.json').read_text())

    class Context:
        def get_config(self, key, default):
            return fixture['settings'].get(key, default)

        def register_hook(self, name, callback):
            self.hook = callback

        def register_command(self, *args, **kwargs):
            pass

    lines = ['exfilbar | same file, two destinations',
             'fixture text only. registered pre_tool_call hook. no execution. no network.',
             'temporary feed only. no Hermes installation or profile required.']
    with TemporaryDirectory(prefix='exfilbar-route-demo-') as directory:
        ledger = plugin.Ledger(directory, clock=lambda: '2000-01-01T00:00:00+00:00')
        plugin.Ledger = lambda: ledger
        ctx = Context()
        plugin.register(ctx)
        lines.append('route 1 | reports/** may go to uploads.example')
        for case in fixture['cases']:
            result = ctx.hook('terminal', {'command': case['command']}, session_id='route-demo')
            blocked = bool(result and result.get('action') == 'block')
            if blocked != case['blocked']:
                raise AssertionError('unexpected hook decision: ' + case['name'])
            lines.append(case['name'] + ' | ' + ('BLOCK' if blocked else 'PASS'))
            if blocked:
                lines.append(result['message'])
        lines.append(plugin.format_feed(ledger.read('route-demo')))
    lines.append('the off-route call was stopped before dispatch. delivery was not attempted.')
    lines.append('static recognized syntax only; not a sandbox.')
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    print(render(), end='')
