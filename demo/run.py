"""Deterministic fixture rehearsal. No subprocesses, shell, or network."""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exfilbar.policy import Policy
from exfilbar.report import format_verdict


def run():
    cases = json.loads((Path(__file__).resolve().parents[1] / 'tests/fixtures/cases.json').read_text())
    lines = ['EXFILBAR | fixture | dry run | no shell | no network', 'beat  | fixture | verdict']
    for case in cases:
        result = Policy(block_git_push=case.get('git', False)).evaluate(case['command'])
        lines.append(case['beat'] + ' | ' + case['name'] + ' | ' + format_verdict(result, True))
    lines.append('80-89 | run the offline suite separately; source integration checks 0 blocked executions / 1 local cp')
    lines.append('limits | explicit shell subset; no content scanning; scripts and sibling rewrites outside coverage')
    return '\n'.join(lines)


if __name__ == '__main__':
    print(run())
