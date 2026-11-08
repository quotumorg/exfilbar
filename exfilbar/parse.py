"""Read-only recognizer for a deliberately small POSIX shell subset."""
from dataclasses import dataclass, replace
import re
import shlex

FAMILIES = {'scp', 'rsync', 'curl', 'nc', 'netcat', 'ncat', 'wget', 'http', 'https', 'sftp', 'socat', 'ssh', 'mail', 'mailx', 'git'}
WRAPPERS = {'sudo', 'env', 'command', 'exec', 'timeout', 'sh', 'bash', 'zsh',
            '!', 'time', 'nohup', 'nice', 'setsid'}


@dataclass(frozen=True)
class Transfer:
    family: str
    sources: tuple = ()
    destination: str = 'unknown'
    unresolved: bool = False
    operation: str = ''


def remote(path):
    return bool(re.match(r'(?:[^/\s:]+@)?[^/\s:]+:', path) or path.startswith('rsync://'))


def dynamic(value):
    return any(c in value for c in '$`*?[]~{}')


def options(tokens, operands, flags):
    """Return positionals, option values, uncertainty; unknown options fail closed."""
    pos, values, bad = [], [], False
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == '--':
            pos.extend(tokens[i + 1:])
            break
        if token.startswith('-') and token != '-':
            key, eq, value = token.partition('=')
            if key in operands:
                if not eq:
                    i += 1
                    value = tokens[i] if i < len(tokens) else ''
                values.append((key, value))
                bad |= not bool(value)
            elif token[:2] in operands and not token.startswith('--') and len(token) > 2:
                values.append((token[:2], token[2:]))
            elif not eq and (key in flags or (not token.startswith('--') and all('-' + c in flags for c in token[1:]))):
                values.extend((flag, None) for flag in ([key] if key in flags else ['-' + c for c in token[1:]]))
            else:
                bad = True
        else:
            pos.append(token)
        i += 1
    return pos, values, bad


def parse(command):
    """Return transfer records, never expand a token or inspect a source file."""
    if len(command) > 32768:
        return [Transfer('shell', unresolved=True)]
    # POSIX shells remove escaped newlines before recognizing command names.
    # shlex retains them. For this unsupported syntax, inspect a normalized
    # spelling conservatively (including continuations inside quoted text).
    if '\\\n' in command:
        normalized = command.replace('\\\n', '')
        found = parse(normalized)
        if found:
            return [replace(x, unresolved=True) for x in found]
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=';&|<>()\n')
        lexer.whitespace = ' \t\r'
        lexer.whitespace_split = True
        # Preserve newlines after comments; shlex's comment reader eats them.
        # Comments around recognized commands are conservative unresolved syntax.
        lexer.commenters = ''
        tokens = []
        for token in lexer:
            tokens.append(token)
            if len(tokens) > 4096:
                return [Transfer('shell', unresolved=True)]
    except ValueError:
        return [Transfer('shell', unresolved=True)]
    if sum(t == '|' for t in tokens) > 128:
        return [Transfer('shell', unresolved=True)]
    records = []
    segments, segment = [], []
    for token in tokens:
        if token and all(c in ';\n&' for c in token) or token == '||':
            if segment:
                segments.append(segment)
            segment = []
        else:
            segment.append(token)
    if segment:
        segments.append(segment)
    changed_directory = False
    for t in segments:
        family = t[0].rsplit('/', 1)[-1]
        if family in ('cd', 'pushd', 'popd'):
            changed_directory = True
        start = len(records)
        # Split pipelines but retain lexical read operands from upstream stages.
        stages, stage = [], []
        for token in t:
            if token == '|':
                stages.append(stage)
                stage = []
            else:
                stage.append(token)
        stages.append(stage)
        reads = []
        uncertain_read = False
        for stage in stages:
            if not stage:
                continue
            name = stage[0].rsplit('/', 1)[-1]
            if '<' in stage and (name == '<' or name.isdigit()):
                if any(x.rsplit('/', 1)[-1] in FAMILIES for x in stage):
                    records.append(Transfer('shell', unresolved=True))
            if name in FAMILIES:
                found = _one(stage, tuple(reads))
                if len(stages) > 1 and not found and name in {'nc', 'netcat', 'ncat'}:
                    found = [Transfer(name, unresolved=True)]
                if len(stages) > 1:
                    # Even an unknown producer cannot become an allowed upload.
                    found = [replace(x, sources=tuple(dict.fromkeys(x.sources + tuple(reads))),
                                     unresolved=x.unresolved or not reads or uncertain_read) for x in found]
                records.extend(found)
            elif (name in WRAPPERS or '=' in name) and any(
                    re.search(r'\b' + f + r'\b', ' '.join(stage[1:])) for f in FAMILIES):
                records.append(Transfer('wrapper', unresolved=True))
            if name in {'cat', 'base64', 'gzip', 'xxd', 'openssl', 'tar', 'zip'}:
                # Candidate operands, not filesystem reads or shell evaluation.
                reads.extend(x for x in stage[1:] if not x.startswith('-') and x != '-')
                # Archives may recurse or change operand directories (-C).
                # A lexical filename list cannot establish their full payload.
                uncertain_read |= name in {'tar', 'zip'}
            elif name not in FAMILIES:
                uncertain_read = True
            if '<' in stage:
                i = stage.index('<')
                reads.extend(stage[i + 1:i + 2])
        if changed_directory:
            records[start:] = [replace(x, unresolved=True) for x in records[start:]]
    # Unsupported topology can hide the executable at the start of a stage.
    # Fall back conservatively even if another stage was parsed successfully.
    if any(re.search(r'(?<![\w-])' + f + r'(?![\w-])', command)
                           for f in FAMILIES):
        if any(x in tokens for x in ('(', ')', '<<', '|&')) or any(x.startswith('#') for x in tokens) or any(
                x in tokens for x in ('if', 'then', 'do', 'eval')):
            records.append(Transfer('shell', unresolved=True))
    return records


def _one(t, piped=()):
    f = t[0].rsplit('/', 1)[-1]
    redirected = list(piped)
    t = list(t)
    if '<' in t:
        i = t.index('<')
        redirected.extend(t[i + 1:i + 2])
        if i + 1 >= len(t):
            return [Transfer(f, unresolved=True)]
        del t[i:i + 2]
    piped = tuple(redirected)
    controls = {'|', '||', '>', '>>', '<<', '(', ')', '<', '>&', '<&'}
    if any(x in controls - ({'<'} if f in ('nc', 'netcat') else set()) for x in t[1:]):
        return [Transfer(f, unresolved=True)]
    if f in ('scp', 'rsync'):
        operands = {'-P', '-S', '-i', '-o', '-F', '-c', '-l', '-J'} if f == 'scp' else {'-e', '--exclude', '--include', '--port', '--timeout', '--filter'}
        flags = {'-q', '-v', '-p', '-C', '-4', '-6', '-B', '-r'} if f == 'scp' else {'-a', '-v', '-z', '-r', '-q', '-n', '--dry-run', '--delete', '--progress'}
        pos, vals, bad = options(t[1:], operands, flags)
        if f == 'rsync' and not bad and any(k in ('--dry-run', '-n') and v is None for k, v in vals):
            return []
        recursive = any(x.startswith('-') and not x.startswith('--') and any(c in x[1:] for c in ('r' if f == 'scp' else 'ar')) for x in t[1:])
        if len(pos) >= 2 and remote(pos[-1]):
            local = tuple(x for x in pos[:-1] if not remote(x))
            return [Transfer(f, local, pos[-1], bad or recursive or dynamic(pos[-1]) or not local or any(dynamic(x) or x.endswith('/') for x in local))]
        if bad or len(pos) < 2 or any(dynamic(x) for x in pos):
            return [Transfer(f, unresolved=True)]
        return []
    if f == 'curl':
        pos, vals, bad = options(t[1:], {'-F', '--form', '-T', '--upload-file', '--form-string', '-o', '--output', '-D', '--dump-header', '-H', '--header', '-X', '--request', '-d', '--data', '--data-binary', '--data-urlencode', '--url', '-u', '--user'}, {'-f', '-s', '-S', '-L', '-v', '-k', '--fail', '--silent', '--show-error', '--location'})
        destinations = pos + [v for k, v in vals if k == '--url']
        sources = list(piped)
        for k, v in vals:
            if k in ('-T', '--upload-file'):
                sources.append(v)
            elif k in ('-F', '--form'):
                payload = v.partition('=')[2]
                if payload.startswith(('@', '<')):
                    # curl has its own quoted filename grammar after shell quoting.
                    # Do not mistake those quotes or escapes for pathname bytes.
                    bad |= any(c in payload[1:] for c in ('\"', "'", '\\'))
                    sources.extend(payload[1:].split(';')[0].split(','))
            elif k == '--data-urlencode' and '@' in v:
                sources.append(v.split('@', 1)[1])
            elif k in ('-d', '--data', '--data-binary', '-H', '--header') and v.startswith('@'):
                sources.append(v[1:])
        redirects = any(k in ('-L', '--location') and v is None for k, v in vals)
        dynamic_form = any(k in ('-F', '--form', '-T', '--upload-file', '-d', '--data', '--data-binary', '--data-urlencode') and dynamic(v) for k, v in vals)
        if sources or bad or dynamic_form:
            return [Transfer(f, tuple(sources), target, bad or redirects or dynamic_form or dynamic(target) or not destinations or any(dynamic(x) or x in ('', '-') or x.endswith('/') for x in sources)) for target in (destinations or ['unknown'])]
        return []
    if f in ('nc', 'netcat', 'ncat'):
        pos, vals, bad = options(t[1:], {'-p', '-s', '-w', '-q'}, {'-l', '--listen', '-k', '-n', '-v', '-u', '-4', '-6', '-z'})
        # A listener with explicit input can serve that input to a remote peer.
        listener = not bad and any(k in ('-l', '--listen') and v is None for k, v in vals)
        if listener and not piped:
            return []
        if listener:
            return [Transfer(f, piped, 'listener', any(dynamic(x) for x in piped))]
        sources = piped
        if '<' in pos:
            i = pos.index('<')
            sources = tuple(pos[i + 1:i + 2])
            pos = pos[:i] + pos[i + 2:]
        if '<' in t and not sources:
            bad = True
        return [Transfer(f, sources, ':'.join(pos[:2]) or 'unknown', bad or len(pos) != 2 or len(sources) != 1 or any(dynamic(x) for x in sources + tuple(pos)))]
    if f == 'wget':
        pos, vals, bad = options(t[1:], {'--post-file', '--body-file', '--method',
            '-O', '--output-document', '--header', '--post-data', '--body-data', '-o'},
            {'-q', '--quiet', '-c', '--continue', '-S'})
        sources = piped + tuple(v for k, v in vals if k in ('--post-file', '--body-file'))
        if sources or bad:
            return [Transfer(f, sources, target, bad or not pos or dynamic(target) or
                             any(dynamic(x) or x == '-' for x in sources)) for target in (pos or ['unknown'])]
        return []
    if f in ('http', 'https'):
        sources = list(piped)
        dest = next((x for x in t[1:] if '://' in x), 'unknown')
        for x in t[1:]:
            if x.startswith('@'):
                sources.append(x[1:])
            elif ':=@' in x or '=@' in x:
                sources.append(re.split(r':?=@', x, maxsplit=1)[1])
        bad = any(x.startswith('-') for x in t[1:]) or dest == 'unknown'
        if sources or bad:
            return [Transfer(f, tuple(sources), dest, bad or dynamic(dest) or
                             any(dynamic(x) or x in ('', '-') for x in sources))]
        return []
    if f == 'sftp':
        # A batch filename describes commands, not the transferred files.
        # Never open it; put commands/heredocs and unknown batches fail closed.
        return [Transfer(f, piped, t[-1] if len(t) > 1 else 'unknown', True)]
    if f == 'socat':
        sources = list(piped)
        for x in t[1:]:
            if x.upper().startswith(('OPEN:', 'FILE:')):
                sources.append(x.split(':', 1)[1].split(',')[0])
        dest = next((x for x in t[1:] if x.upper().startswith(('TCP:', 'TCP4:', 'TCP6:'))), 'unknown')
        return [Transfer(f, tuple(sources), dest, not sources or dest == 'unknown' or
                         any(dynamic(x) for x in sources) or dynamic(dest))]
    if f in ('ssh', 'mail', 'mailx'):
        operands = ({'-p', '-i', '-o', '-F', '-J', '-l', '-S'} if f == 'ssh'
                    else {'-s', '-a', '-r', '-c', '-b'})
        flags = {'-4', '-6', '-q', '-v', '-T', '-t', '-n'} if f == 'ssh' else {'-v', '-n'}
        pos, vals, bad = options(t[1:], operands, flags)
        destinations = pos[:1] if f == 'ssh' else pos
        if f != 'ssh':
            destinations += [v for k, v in vals if k in ('-c', '-b')]
            # mailx dialects disagree: -a can attach a file or add a header.
            # Treat the operand as a candidate file and retain uncertainty.
            attachments = tuple(v for k, v in vals if k == '-a')
            piped += attachments
            bad |= bool(attachments)
        return [Transfer(f, piped, dest, bad or not piped or
                         any(dynamic(x) for x in piped) or dynamic(dest))
                for dest in (destinations or ['unknown'])]
    if f == 'git':
        # Global git options are deliberately unresolved rather than guessed.
        if t[1:2] == ['push']:
            return [Transfer(f, destination='configured remote', operation='git push')]
        if 'push' in t[1:]:
            return [Transfer(f, unresolved=True, operation='git push')]
    return []
