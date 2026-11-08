"""Deterministic attacker/defender rehearsal. Evaluates text, never runs it."""
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('attack_plugin', ROOT / '__init__.py',
                                            submodule_search_locations=[str(ROOT)])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class Context:
    def get_config(self, key, default):
        return default

    def register_hook(self, name, callback):
        self.hook = callback

    def register_command(self, *args, **kwargs):
        pass


# Readable transfer text stays in the shared test fixture corpus.
CASES = json.loads((ROOT / 'tests/fixtures/attack.json').read_text())


def render():
    ctx = Context()
    plugin.register(ctx)
    lines = ['EXFILBAR | ATTACKER VS DEFENDER',
             'Fixture text only. No execution. No network.',
             f'{"ATTEMPT":<24} | {"TOOL":<12} | {"DEFENDER":<7} | RULE',
             '-' * 85]
    for name, tool, payload, expected in CASES:
        result = ctx.hook(tool, {'code' if tool == 'execute_code' else 'command': payload})
        blocked = bool(result and result.get('action') == 'block')
        if blocked != expected:
            raise AssertionError('unexpected hook verdict: ' + name)
        fields = result['message'].split(' | ') if blocked else []
        rule = (fields[3] + '; ' + next(x for x in fields if x.startswith('rule='))) if blocked else 'no outbound file rule matched'
        lines.append(f'{name:<24} | {tool:<12} | {"BLOCKED" if blocked else "ALLOWED":<7} | {rule}')
    lines.append('7 attacks blocked. 3 legitimate controls allowed. Static policy, not a sandbox.')
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    output = render()
    Path(__file__).with_name('ATTACK-OUT.txt').write_text(output)
    print(output, end='')
