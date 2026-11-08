"""Hermes entry point; public registration and storage surfaces only."""
from .exfilbar.policy import Policy, Verdict
from .exfilbar.code import inspect_code
from .exfilbar.ledger import Ledger, format_feed
from .exfilbar.report import format_verdict

DEFAULTS = dict(protected_globs=['private/**', '*.env'], destination_globs=[], routes=[],
                block_git_push=False, block_unresolved=True, workspace_root='.')


def register(ctx):
    ledger = Ledger()

    def policy():
        return Policy(**{k: ctx.get_config(k, v) for k, v in DEFAULTS.items()})

    def hook(tool_name, args, **ids):
        if tool_name not in ('terminal', 'execute_code'):
            return None
        inspection = ()
        try:
            key = 'command' if tool_name == 'terminal' else 'code'
            if not isinstance(args, dict) or not isinstance(args.get(key), str):
                raise ValueError('invalid tool arguments')
            cwd = args.get('workdir')
            if cwd is None:
                cwd = '.'
            if not isinstance(cwd, str) or len(cwd) > 4096:
                raise ValueError('invalid working directory')
            current = policy()
            verdict = current.evaluate(args[key], cwd) if tool_name == 'terminal' else inspect_code(current, args[key], cwd)
            inspection = current.inspection
        except Exception:
            # The host adapter may fail open on exceptions. Return a directive
            # ourselves, without echoing exception text or invalid settings.
            verdict = Verdict(True, tool_name, 'policy error or invalid arguments; execution blocked')
        try:
            ledger.record(ids.get('session_id'), tool_name, inspection)
        except Exception:
            verdict = Verdict(True, tool_name, 'session feed unavailable; execution blocked')
        if verdict.blocked:
            return {'action': 'block', 'message': format_verdict(verdict)}
        return None

    def command(raw_args, **ids):
        if raw_args.startswith('check '):
            try:
                verdict = policy().evaluate(raw_args[6:])
            except Exception:
                verdict = Verdict(True, 'policy', 'invalid settings; execution blocked')
            return format_verdict(verdict, dry_run=True)
        if raw_args.strip() == 'routes':
            try:
                return policy().describe_routes()
            except Exception:
                return 'Invalid settings; execution blocked.'
        if raw_args.strip() == 'demo':
            from .exfilbar.demo import replay
            return replay()
        if raw_args.strip() == 'status':
            try:
                return format_feed(ledger.read(ids.get('session_id')))
            except Exception:
                return 'Session feed unavailable. Check plugin data directory permissions and retry.'
        return '/exfil check <command> (dry run), /exfil routes, /exfil demo (fixtures), /exfil status'

    ctx.register_hook('pre_tool_call', hook)
    ctx.register_command('exfil', command, description='Explain per-file routes and show inspected transfers',
                         args_hint='check <command> | routes | demo | status')
