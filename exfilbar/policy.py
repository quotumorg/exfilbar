"""Lexical user-owned policy; no file reads or shell calls."""
from dataclasses import dataclass
from fnmatch import fnmatchcase
import posixpath
from .parse import parse, dynamic, Transfer, MAX_PAIRS
from .report import allowed_hosts
from .destinations import route_matches


@dataclass(frozen=True)
class Verdict:
    blocked: bool = False
    family: str = 'local/unsupported'
    reason: str = 'no configured outbound rule matched'
    path: str = ''
    pattern: str = ''
    destination: str = ''
    route: str = ''


def patterns(value):
    # Reject oversized containers before traversing them.
    if not isinstance(value, (list, tuple)) or len(value) > 128:
        raise ValueError('at most 128 patterns per list')
    if any(not isinstance(x, str) or not x or len(x) > 512 for x in value):
        raise ValueError('nonempty string patterns of at most 512 characters')
    return tuple(value)


class Policy:
    def __init__(self, protected_globs=('private/**', '*.env'), destination_globs=(), block_git_push=False, block_unresolved=True, workspace_root='.', routes=()):
        self.globs = patterns(protected_globs)
        self.destinations = patterns(destination_globs)
        if not isinstance(routes, (list, tuple)) or len(routes) > 128:
            raise ValueError('at most 128 routes')
        self.routes = []
        for route in routes:
            if not isinstance(route, dict) or set(route) != {'paths', 'to'}:
                raise ValueError('each route needs paths and to lists')
            paths, targets = patterns(route['paths']), patterns(route['to'])
            if not paths or not targets:
                raise ValueError('route paths and to cannot be empty')
            self.routes.append((paths, targets))
        if not isinstance(workspace_root, str) or not workspace_root:
            raise ValueError('workspace_root must be a lexical path')
        if type(block_git_push) is not bool or type(block_unresolved) is not bool:
            raise ValueError('operation and unresolved settings must be booleans')
        if len(workspace_root) > 4096 or dynamic(workspace_root):
            raise ValueError('workspace_root must be static and at most 4096 characters')
        self.git = block_git_push
        self.unresolved = block_unresolved
        self.root = posixpath.normpath(workspace_root)
        self.inspection = ()

    def normalize(self, path, cwd='.'):
        if not isinstance(cwd, str) or len(cwd) > 4096 or dynamic(cwd):
            return None
        if dynamic(path) or not path or path == '-':
            return None
        base = cwd if posixpath.isabs(cwd) else posixpath.join(self.root, cwd)
        full = posixpath.normpath(posixpath.join(base, path))
        if posixpath.isabs(full) != posixpath.isabs(self.root):
            return None
        rel = posixpath.relpath(full, self.root)
        return None if rel == '..' or rel.startswith('../') else rel

    def evaluate(self, command, cwd='.'):
        return self.decide(parse(command), cwd)

    def over_budget(self, pairs):
        # Bound both pair count and worst-case glob comparisons, including cold caches.
        rules = len(self.globs) + len(self.destinations) + sum(
            len(paths) + 3 * len(targets) for paths, targets in self.routes)
        return pairs > MAX_PAIRS or pairs * max(1, rules) > 8192

    def budget_block(self):
        verdict = Verdict(True, 'inspection', 'too many transfer pairs to inspect; execution blocked')
        self.inspection = ((Transfer('inspection', overflow=True), (), verdict),)
        return verdict

    def decide(self, transfers, cwd='.', static=False, normalized=None):
        """One verdict for dispatch, plus one observation per recognized record.

        A blocked compound tool call suppresses ALL its records. Protected
        evidence is considered across the whole call before route/destination
        rules. Unresolved syntax never acquires a route exemption.
        """
        transfers = tuple(transfers)
        if any(t.overflow for t in transfers) or self.over_budget(
                sum(max(1, len(t.sources)) for t in transfers)):
            return self.budget_block()
        normalized = {} if normalized is None else normalized
        for x in dict.fromkeys(x for t in transfers for x in t.sources):
            if x not in normalized:
                normalized[x] = self.normalize(x, cwd)
        paths = [tuple(normalized[x] for x in t.sources) for t in transfers]
        suffix = ' (static code text)' if static else ''
        verdict = None
        # Highest priority, even if another record matched a destination deny.
        for t, sources in zip(transfers, paths):
            for path in sources:
                if path is not None:
                    for pattern in self.globs:
                        if fnmatchcase(path, pattern):
                            verdict = Verdict(True, t.family, 'protected path rule' + suffix, path, pattern, t.destination)
                            break
                    if verdict:
                        break
            if verdict:
                break
        individual = []
        for t, sources in zip(transfers, paths):
            individual.append(self._transfer(t, sources, static))
        if verdict is None:
            blocked = [v for v in individual if v.blocked]
            verdict = min(blocked, key=lambda v: 0 if v.pattern == 'block_git_push' else 1 if v.route else 2 if v.reason.startswith('destination rule') else 3) if blocked else None
        if verdict is None:
            verdict = next((v for v in individual if v.route), None)
        if verdict is None:
            verdict = next((v for v in reversed(individual) if v.reason.startswith('unresolved')), Verdict())
        self.inspection = tuple((t, p, verdict if verdict.blocked else v)
                                for t, p, v in zip(transfers, paths, individual))
        return verdict

    def _transfer(self, t, paths, static):
        f, dest = t.family, t.destination
        suffix = ' (static code text)' if static else ''
        if t.operation and self.git:
            return Verdict(True, f, 'operation rule: git push; payload unknown', pattern='block_git_push', destination=dest)
        matched = []
        uncovered = False
        for path in paths:
            applicable = [(i, targets) for i, (globs, targets) in enumerate(self.routes, 1)
                          if path is not None and any(fnmatchcase(path, g) for g in globs)]
            uncovered |= not applicable
            for i, targets in applicable:
                name = f'routes[{i}]'
                if not any(route_matches(dest, target) for target in targets):
                    return Verdict(True, f, 'off route; allowed hosts: ' + allowed_hosts(targets),
                                   path=path, destination=dest, route=name)
                matched.append(name)
        unresolved = t.unresolved or any(p is None for p in paths)
        # A route exempts only its known sources. A mixed public/uncovered
        # payload still receives destination denies and unresolved handling.
        routed = bool(matched) and not uncovered and not unresolved
        if not routed:
            for pattern in self.destinations:
                if fnmatchcase(dest, pattern):
                    return Verdict(True, f, 'destination rule' + suffix, pattern=pattern, destination=dest)
        if unresolved or (static and not routed):
            return Verdict(self.unresolved, f, 'unresolved source' + ('' if self.unresolved else ' (explicit pass setting)'), destination=dest)
        if matched:
            return Verdict(False, f, 'allowed by route', destination=dest, route=','.join(dict.fromkeys(matched)))
        return Verdict(False, f, 'allowed', destination=dest)

    def describe_routes(self):
        if not self.routes:
            return 'No routes configured. Protected and destination denies still apply.'
        from .report import clean
        return '\n'.join(f'route {i} | paths=' + ', '.join(clean(p) for p in paths) +
                         ' | allowed hosts: ' + allowed_hosts(targets)
                         for i, (paths, targets) in enumerate(self.routes, 1))
