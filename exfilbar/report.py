"""Bounded output; never include a full command or file contents."""
import re
from urllib.parse import urlsplit


def clean(value, limit=96):
    value = str(value)[:limit]
    value = ''.join(c if c.isprintable() else '?' for c in value)
    return value[:limit]


def destination(value):
    # Omit URL credentials, query, fragment, and remote path.
    if '://' in value:
        try:
            parsed = urlsplit(value)
            return clean(parsed.scheme + '://' + (parsed.hostname or 'unknown'))
        except ValueError:
            return 'unknown'
    return clean(re.sub(r'^.*@', '', value.split('?', 1)[0].split('#', 1)[0].split(':', 1)[0]))


def route_label(value):
    """Display legacy route metadata without markdown citation syntax."""
    value = re.sub(r'routes\[(\d+)\]', r'route \1', value)
    return re.sub(r',(?=route \d+)', ', ', value)


def feed_labels(decision, rule):
    """Normalize presentation only; stored decisions and rules stay intact."""
    rule = route_label(rule)
    if decision == 'allowed by route':
        decision = 'allowed'
        if rule.startswith('allowed by route; '):
            rule = rule[len('allowed by route; '):]
    if rule == decision or (rule == 'allowed by route' and decision == 'allowed'):
        rule = ''
    return decision, rule.replace('; route ', ' · route ')


def format_verdict(verdict, dry_run=False):
    fields = ['dry run' if dry_run else 'Exfilbar', 'BLOCK' if verdict.blocked else 'PASS', clean(verdict.family), clean(verdict.reason, 320)]
    if verdict.path:
        fields.append('path=' + clean(verdict.path))
    if verdict.pattern:
        fields.append('rule=' + (destination(verdict.pattern) if '://' in verdict.pattern else clean(verdict.pattern)))
    if verdict.route:
        fields.append('route=' + clean(route_label(verdict.route)))
    if verdict.destination:
        fields.append('destination=' + destination(verdict.destination))
    return ' | '.join(fields)[:640]


def allowed_hosts(targets):
    return ', '.join(dict.fromkeys(destination(t).split('://', 1)[-1] for t in targets))[:256]


def egress_destination(value, family):
    if '://' in value:
        return destination(value)
    if value in ('unknown', 'listener', 'configured remote'):
        return 'unknown'
    if family == 'socat':
        parts = value.split(':')
        return 'tcp://' + clean(parts[1]) if len(parts) > 1 else 'unknown'
    scheme = {'scp': 'ssh', 'ssh': 'ssh', 'sftp': 'ssh', 'rsync': 'rsync',
              'nc': 'tcp', 'ncat': 'tcp', 'netcat': 'tcp', 'mail': 'mailto', 'mailx': 'mailto'}.get(family)
    return scheme + '://' + destination(value) if scheme else 'unknown'
