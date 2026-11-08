"""Route destination globs with authority boundaries; legacy denies stay raw."""
from fnmatch import fnmatchcase
from urllib.parse import urlsplit


def route_matches(value, pattern):
    if pattern == '*':
        return True
    if '://' in value or '://' in pattern:
        if '://' not in value or '://' not in pattern:
            return False
        scheme, _, rest = pattern.partition('://')
        authority, slash, path = rest.partition('/')
        # Credentials and queries cannot enlarge a host permission. They are
        # ignored for routes and never displayed. Ports remain significant.
        authority = authority.rsplit('@', 1)[-1].split('?', 1)[0].split('#', 1)[0]
        path = ('/' + path if slash else '').split('?', 1)[0].split('#', 1)[0]
        try:
            actual = urlsplit(value)
            if not actual.hostname:
                return False
            actual.port  # validate malformed port syntax without guessing
        except ValueError:
            return False
        host = actual.netloc.rsplit('@', 1)[-1]
        return (fnmatchcase(value.partition('://')[0], scheme) and
                fnmatchcase(host, authority) and fnmatchcase(actual.path, path))
    # Raw SSH/SCP/rsync operands: don't let a wildcard eat the host separator.
    host, colon, path = value.partition(':')
    allowed, separator, glob = pattern.partition(':')
    if colon != separator:
        return False
    return fnmatchcase(host, allowed) and fnmatchcase(path, glob)
