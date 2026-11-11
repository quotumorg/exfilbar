"""Explicit-directory offline verification; never opens a Hermes profile."""
import argparse
from .integrity import format_verification
from .ledger import Ledger


def main():
    parser = argparse.ArgumentParser(prog='exfilbar')
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('verify', help='verify the local decision history offline')
    check.add_argument('--data-dir', required=True, help='directory containing egress.db and optional integrity.key')
    check.add_argument('--require-hmac', action='store_true', help='reject a nonempty history with no authenticated records')
    args = parser.parse_args()
    try:
        result = Ledger(args.data_dir).verify(require_hmac=args.require_hmac)
    except Exception:
        print('Verification unavailable. Check the plugin data directory; no integrity claim can be made.')
        return 2
    print(format_verification(result))
    return 0 if result['intact'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
