"""Read-only recognizer for a deliberately small POSIX shell subset."""
from dataclasses import dataclass, replace
import re
import shlex

MAX_PAIRS = 1024

FAMILIES = {'scp', 'rsync', 'curl', 'nc', 'netcat', 'ncat', 'wget', 'http', 'https', 'sftp', 'socat', 'ssh', 'mail', 'mailx', 'git', 'gh', 'aws'}
WRAPPERS = {'sudo', 'env', 'command', 'exec', 'timeout', 'sh', 'bash', 'zsh',
            '!', 'time', 'nohup', 'nice', 'setsid'}


@dataclass(frozen=True)
class Transfer:
    family: str
    sources: tuple = ()
    destination: str = 'unknown'
    unresolved: bool = False
    operation: str = ''
    overflow: bool = False


def remote(path):
    head, colon, _ = path.partition(':')
    return bool(colon and head and not any(c == '/' or c.isspace() for c in head))


def dynamic(value):
    return any(c in value for c in '$`*?[]~{}')


def covered_command(tokens):
    """Only the upload subcommands of gh/aws belong to this recognizer."""
    family = tokens[0].rsplit('/', 1)[-1]
    pair = {'gh': ['release', 'upload'], 'aws': ['s3', 'cp']}.get(family)
    return family in FAMILIES and (pair is None or any(
        tokens[i:i + 2] == pair for i in range(1, len(tokens) - 1)))


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


def ignore_output_redirects(command):
    """Erase only literal fd duplication/closure and output to /dev/null.

    Work on shell text before shlex loses quoting and fd adjacency. In
    particular, a quoted "2" before >&1 is still an argument, not an fd.
    File writes and file-input redirects remain visible to the conservative parser.
    """
    pieces, start, word, quote, i = [], 0, 0, '', 0
    boundaries = ' \t\r\n;&|<>()'
    while i < len(command):
        char = command[i]
        if char == '\\' and quote != "'":
            i += 2
            continue
        if quote:
            if char == quote:
                quote = ''
            i += 1
            continue
        if char in "\"'":
            quote = char
            i += 1
            continue
        if char in '<>':
            j = i + 1
            if j < len(command) and command[j] in (char, '&'):
                j += 1
            operator = command[i:j]
            target_start = j
            while target_start < len(command) and command[target_start] in ' \t':
                target_start += 1
            end = target_start
            while end < len(command) and command[end] not in boundaries:
                end += 1
            target = command[target_start:end]
            safe = (operator in ('>&', '<&') and
                    (target.isascii() and target.isdigit() or target == '-')) or (
                    operator in ('>', '>>') and target == '/dev/null')
            # A leading & is unsupported combined redirection, not a separator
            # to erase accidentally. Leave it for conservative handling.
            if safe and (i == 0 or command[i - 1] not in '<>&'):
                prefix = command[word:i]
                begin = word if prefix.isascii() and prefix.isdigit() else i
                pieces.extend((command[start:begin], ' '))
                start, i, word = end, end, end
                continue
        if char in boundaries:
            word = i + 1
        i += 1
    pieces.append(command[start:])
    return ''.join(pieces)


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
    command = ignore_output_redirects(command)
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
    pairs = 0
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
            if (name in {'<', '>', '>>', '>&', '<&', '&>', '&>>', '>|'} or
                    name.isdigit() and any(x in stage for x in ('<', '>', '>>', '>&', '<&', '>|'))):
                if any(covered_command(stage[i:]) for i, x in enumerate(stage)
                       if x.rsplit('/', 1)[-1] in FAMILIES):
                    records.append(Transfer('shell', unresolved=True))
            if name in FAMILIES:
                found = _one(stage, tuple(reads))
                if len(stages) > 1 and not found and name in {'nc', 'netcat', 'ncat'}:
                    found = [Transfer(name, unresolved=True)]
                pairs += sum(max(1, len(x.sources) + (len(reads) if len(stages) > 1 else 0)) for x in found)
                if pairs > MAX_PAIRS or any(x.overflow for x in found):
                    return [Transfer('shell', overflow=True)]
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
    if not covered_command(t):
        return []
    redirected = list(piped)
    t = list(t)
    if '<' in t:
        i = t.index('<')
        redirected.extend(t[i + 1:i + 2])
        if i + 1 >= len(t):
            return [Transfer(f, unresolved=True)]
        del t[i:i + 2]
    piped = tuple(redirected)
    controls = {'|', '||', '>', '>>', '<<', '(', ')', '<', '>&', '<&', '&>', '&>>', '>|'}
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
            if len(sources) * max(1, len(destinations)) > MAX_PAIRS:
                return [Transfer(f, overflow=True)]
            sources = tuple(sources)
            return [Transfer(f, sources, target, bad or redirects or dynamic_form or dynamic(target) or not destinations or any(dynamic(x) or x in ('', '-') or x.endswith('/') for x in sources)) for target in (destinations or ['unknown'])]
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
            if len(sources) * max(1, len(pos)) > MAX_PAIRS:
                return [Transfer(f, overflow=True)]
            return [Transfer(f, sources, target, bad or not pos or dynamic(target) or
                             any(dynamic(x) or x == '-' for x in sources)) for target in (pos or ['unknown'])]
        return []
    if f in ('http', 'https'):
        sources = list(piped)
        urls = [x for x in t[1:] if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', x)]
        dest = urls[0] if len(urls) == 1 else 'unknown'
        url_set = set(urls)
        ambiguous = False
        for x in t[1:]:
            if x in url_set:
                continue
            if x.startswith('@'):
                sources.append(x[1:])
            elif ':=@' in x or '=@' in x:
                sources.append(re.split(r':?=@', x, maxsplit=1)[1])
            elif '@' in x and not x.startswith('-'):
                # HTTPie multipart field@file, optionally with ;type= or
                # ;filename= metadata. Literal data/header items can contain @.
                field, _, filename = x.partition('@')
                if not any(c in field for c in '=:\\'):
                    sources.append(filename.split(';', 1)[0])
                    ambiguous |= not bool(field) or '\\' in filename
        bad = ambiguous or any(x.startswith('-') and x not in {
            '--form', '-f', '--multipart', '--check-status', '--ignore-stdin',
            '--print=Hh', '--quiet', '-q'} for x in t[1:]) or len(urls) != 1
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
        if len(piped) * max(1, len(destinations)) > MAX_PAIRS:
            return [Transfer(f, overflow=True)]
        return [Transfer(f, piped, dest, bad or not piped or
                         any(dynamic(x) for x in piped) or dynamic(dest))
                for dest in (destinations or ['unknown'])]
    if f == 'gh' and any(t[i:i + 2] == ['release', 'upload'] for i in range(1, len(t) - 1)):
        i = next(i for i in range(1, len(t) - 1) if t[i:i + 2] == ['release', 'upload'])
        pos, vals, bad = options(t[1:i] + t[i + 2:], {'-R', '--repo'}, {'--clobber'})
        repos = [v for k, v in vals if k in ('-R', '--repo')]
        repo = repos[0] if len(repos) == 1 else ''
        # An implicit repository needs cwd/config/network resolution. Never
        # infer it from the workspace name or inspect Git configuration.
        match = re.fullmatch(r'(?:(?:https://)?([A-Za-z0-9.-]+)/)?([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)', repo)
        dest = ('https://' + (match[1] or 'github.com') + '/' + match[2] + '/' + match[3]) if match else 'unknown'
        sources = tuple(x.split('#', 1)[0] for x in pos[1:])
        return [Transfer(f, sources, dest, bad or not match or len(pos) < 2 or
                         dynamic(pos[0]) or any(not x or dynamic(x) or x.endswith('/') for x in sources))]
    if f == 'aws' and any(t[i:i + 2] == ['s3', 'cp'] for i in range(1, len(t) - 1)):
        i = next(i for i in range(1, len(t) - 1) if t[i:i + 2] == ['s3', 'cp'])
        pos, vals, bad = options(t[1:i] + t[i + 2:],
            {'--profile', '--region', '--endpoint-url', '--content-type', '--acl', '--storage-class',
             '--exclude', '--include', '--cli-connect-timeout', '--cli-read-timeout'},
            {'--quiet', '--only-show-errors', '--no-progress', '--dryrun', '--recursive',
             '--no-cli-pager', '--no-sign-request'})
        if not bad and any(k == '--dryrun' for k, v in vals):
            return []
        if not bad and len(pos) == 2 and not any(dynamic(x) for x in pos) and pos[0].startswith('s3://'):
            return []  # download or server-side copy, no local file source
        sources = tuple(pos[:1])
        dest = pos[1] if len(pos) == 2 else 'unknown'
        endpoints = [v for k, v in vals if k == '--endpoint-url']
        if endpoints:
            dest = endpoints[-1]
        return [Transfer(f, sources, dest, bad or len(pos) != 2 or bool(endpoints) or
                         any(k == '--recursive' for k, v in vals) or not dest.startswith('s3://') or
                         dynamic(dest) or any(not x or x == '-' or dynamic(x) or x.endswith('/') for x in sources))]
    if f == 'git':
        # Global git options are deliberately unresolved rather than guessed.
        if t[1:2] == ['push']:
            return [Transfer(f, destination='configured remote', operation='git push')]
        if 'push' in t[1:]:
            return [Transfer(f, unresolved=True, operation='git push')]
    return []
