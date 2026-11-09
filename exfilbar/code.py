"""Bounded static submitted-text inspection, never execution or file reads."""
import ast
from fnmatch import fnmatchcase
from .policy import Verdict
from .parse import Transfer

NETWORK = {'requests', 'httpx', 'urllib', 'socket', 'ftplib', 'paramiko',
           'http', 'smtplib', 'aiohttp', 'websocket', 'websockets'}
INDIRECT = {'__import__', 'eval', 'exec', 'compile', 'getattr',
            'importlib.import_module', 'runpy.run_module', 'runpy.run_path'}
PROCESS = {'subprocess', 'os', 'pty'}


def inspect_code(policy, code, cwd='.'):
    def unknown():
        return policy.decide([Transfer('execute_code', unresolved=True)], cwd, static=True)
    if not isinstance(code, str) or len(code) > 32768:
        return unknown()
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return unknown()
    nodes = []
    for node in ast.walk(tree):
        if len(nodes) == 8192:
            return unknown()
        nodes.append(node)
    aliases = {name: name for name in NETWORK}

    def tracked(name):
        return name.split('.')[0] in NETWORK | PROCESS | {'importlib', 'runpy'} or name in INDIRECT

    for node in nodes:
        if isinstance(node, ast.Import):
            for item in node.names:
                key = item.asname or item.name.split('.')[0]
                if not tracked(aliases.get(key, '')):
                    aliases[key] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name == '*':
                    return unknown()
                key = item.asname or item.name
                if not tracked(aliases.get(key, '')):
                    aliases[key] = node.module + '.' + item.name

    def qualified(node):
        # Iterative: a legal long attribute chain must not exhaust Python stack.
        suffix = []
        while isinstance(node, (ast.Attribute, ast.Call)):
            if isinstance(node, ast.Attribute):
                suffix.append(node.attr)
                node = node.value
            else:
                node = node.func
        head = aliases.get(node.id, node.id) if isinstance(node, ast.Name) else ''
        return '.'.join([head] + list(reversed(suffix)))

    # Monotonic bounded alias propagation, including function aliases.
    assignments = [n for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign))]
    for iteration in range(16):
        changed = False
        for node in assignments:
            name = qualified(node.value)
            if not tracked(name):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and not tracked(aliases.get(target.id, '')):
                    aliases[target.id] = name
                    changed = True
        if not changed:
            break
    else:
        return unknown()
    calls = [qualified(n.func) for n in nodes if isinstance(n, ast.Call)]
    indirect = any(name in INDIRECT or name.split('.')[0] in {'subprocess', 'pty', 'importlib', 'runpy'} or
                   name in {'os.system', 'os.popen', 'os.posix_spawn', 'os.posix_spawnp', 'os.startfile'} or
                   name.startswith(('os.exec', 'os.spawn'))
                   for name in calls)
    if not indirect and not any(name.split('.')[0] in NETWORK for name in calls):
        return Verdict()
    # Keep protected/destination co-occurrence evidence from r4. Route passes
    # are narrower: direct HTTP calls with literal URL and inline file reads.
    literals = [n.value for n in nodes if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    destinations = tuple(dict.fromkeys(x for x in literals if '://' in x))
    if policy.over_budget(max(1, len(literals)) * max(1, len(destinations))):
        return policy.budget_block()
    sources = []
    normalized = {}
    for value in dict.fromkeys(literals):
        if '://' in value:
            continue
        path = normalized[value] = policy.normalize(value, cwd)
        if path is not None and any(fnmatchcase(path, g) for g in
                (*policy.globs, *(g for paths, _ in policy.routes for g in paths))):
            sources.append(value)
    reads = []
    for node in nodes:
        if isinstance(node, ast.Call) and qualified(node.func) in {'open', 'io.open', 'pathlib.Path', 'Path'}:
            value = node.args[0] if node.args else None
            reads.append(node)
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                sources.append(value.value)
            else:
                sources.append('$unknown')
    direct = {'requests', 'httpx'}
    verbs = {'post', 'put', 'patch', 'get', 'delete', 'urlopen'}
    uncertain = indirect or not reads or not destinations
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        name = qualified(node.func)
        if name.split('.')[0] not in NETWORK:
            continue
        prefix, _, verb = name.rpartition('.')
        url = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == 'url'), None)
        # This is still lexical co-occurrence, never runtime data flow.
        nested = set(ast.walk(node))
        uncertain |= (prefix not in direct or verb not in verbs or
                      not isinstance(url, ast.Constant) or not isinstance(url.value, str) or
                      '://' not in url.value or not any(r in nested for r in reads))
    transfers = [Transfer('execute_code', tuple(dict.fromkeys(sources)), target, uncertain)
                 for target in (destinations or ('unknown',))]
    return policy.decide(transfers, cwd, static=True, normalized=normalized)
