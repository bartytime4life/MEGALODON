"""Web-root watch: new or changed server-side scripts, the files web shells are.

A web shell is a script dropped where the web server runs it: a `.php` file
in an upload folder, a `.jsp` in a webapps folder, PHP code hidden in a
`.jpg` (ATT&CK T1505.003). `megalodon webroot` records the server-side
code files under the web roots and reports new and changed ones. It also
looks inside each new, changed or baselined file for well-known web-shell
shapes: a command or `eval` call fed straight from request input, or
obfuscated `eval`.

Read-only; only code files are recorded and hashed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

SCHEMA = 'megalodon-webroot-watch-v1'
REPORT_SCHEMA = 'megalodon-webroot-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/webroot.json'
DEFAULT_ROOTS = ('/var/www', '/srv/www', '/srv/http', '/usr/share/nginx/html', '/var/lib/tomcat*/webapps',
                 '/opt/tomcat*/webapps')
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_FILES = 200_000
MAX_WALK = 1_000_000
MAX_DEPTH = 32
SNIFF_BYTES = 4096
MAX_HASH = 16 * 1024 * 1024
MAX_PATTERN_READ = 2 * 1024 * 1024
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

SCRIPT_SUFFIXES = {'.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.php8', '.phps', '.pht', '.phar', '.inc',
                   '.jsp', '.jspx', '.jsf', '.asp', '.aspx', '.ashx', '.asmx', '.ascx', '.cshtml', '.cfm', '.cgi',
                   '.pl', '.py', '.rb', '.sh', '.shtml', '.war'}
# Files a web server only serves, never runs. Code inside one is hidden code.
INERT_SUFFIXES = {'.jpg', '.jpeg', '.png', '.gif', '.ico', '.bmp', '.webp', '.svg', '.txt', '.css', '.pdf', '.zip',
                  '.woff', '.woff2', '.ttf', '.mp4', '.mp3', '.json', '.xml', '.csv', '.log'}
UPLOAD_FOLDERS = {'upload', 'uploads', 'images', 'image', 'img', 'media', 'files', 'tmp', 'temp', 'cache',
                  'attachments', 'avatars', 'static', 'assets'}
_CODE_OPENERS = re.compile(rb'<\?php|<\?=|<%@|<%=|<%\s|<script[^>]+runat\s*=\s*["\']?server', re.I)
SKIP_FOLDERS = {'.git', 'node_modules', '.svn', '.hg'}

_REQUEST = r'\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b'
_DECODE = r'(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)'
INDICATORS = (
    ('a command or eval call fed straight from request input', re.compile(
        r'\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:@?\s*'
        + _REQUEST + r'|' + _DECODE + r'\s*\(\s*' + _REQUEST + r')', re.I)),
    ('eval of decoded or decompressed text', re.compile(
        r'\b(?:eval|assert)\s*\(\s*(?:' + _DECODE + r'\s*\(\s*){1,}', re.I)),
    ('a regular expression that runs code (/e)', re.compile(r'\bpreg_replace\s*\(\s*[\'"](.).{0,128}\1[a-z]*e[a-z]*[\'"]',
                                                             re.I)),
    ('a function built from request input', re.compile(r'\bcreate_function\s*\(.{0,160}' + _REQUEST, re.I | re.S)),
    ('backtick command with request input', re.compile(r'`[^`\n]{0,40}' + _REQUEST, re.I)),
    ('a Java command run from a request parameter', re.compile(
        r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*request\s*\.\s*getParameter', re.I)),
    ('an ASP eval or process start fed from the request', re.compile(
        r'\b(?:eval|execute)\s*\(\s*Request\b|Process\s*\.\s*Start\s*\([^)]{0,160}Request\b', re.I)),
)

RULES = {
    'CODE_IN_NON_SCRIPT_FILE': ('CRITICAL', 'Server-side code inside a file that should only be served, such as an '
                                            'image: a common way to hide a web shell.'),
    'SCRIPT_IN_UPLOAD_FOLDER': ('CRITICAL', 'A new server-side script in a folder meant for uploads or static files, '
                                            'where web shells are dropped.'),
    'WEB_SHELL_PATTERN': ('HIGH', 'The file contains a known web-shell shape.'),
    'WEB_SCRIPT_REPLACED_BY_LINK': ('HIGH', 'A recorded script is now a link to another file, which the web '
                                            'server serves in its place.'),
    'WEB_LINK_ADDED': ('MEDIUM', 'A new link under a web root. Deployments use links; so does an intruder pointing '
                                 'a page at a dropped script.'),
    'WEB_LINK_CHANGED': ('MEDIUM', 'A link under a web root now leads elsewhere, or its target changed.'),
    'WEB_SCRIPT_ADDED': ('HIGH', 'A new server-side script under a web root. Deployments add these; so do intruders.'),
    'WEB_SCRIPT_CHANGED': ('MEDIUM', 'A server-side script changed. Updates do this; so does an injected backdoor.'),
}


class WebrootError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def roots(given=None):
    found = []
    for pattern in given or DEFAULT_ROOTS:
        for path in sorted(glob.glob(os.path.expanduser(pattern))) if any(c in pattern for c in '*?[') else [pattern]:
            path = os.path.realpath(os.path.expanduser(path))
            if os.path.isdir(path) and path not in found:
                found.append(path)
    return found


def _read_head(fd):
    try:
        return os.pread(fd, SNIFF_BYTES, 0)
    except OSError:
        return b''


def _classify(path, head):
    suffix = os.path.splitext(path)[1].lower()
    if suffix in SCRIPT_SUFFIXES:
        return 'script'
    if _CODE_OPENERS.search(head):
        return 'hidden' if suffix in INERT_SUFFIXES else 'script'
    return None


def _hash_and_match(fd, size):
    digest, read, tail, matches = hashlib.sha256(), 0, b'', set()
    while read < min(size, MAX_HASH):
        chunk = os.read(fd, min(1 << 20, MAX_HASH - read))
        if not chunk:
            break
        digest.update(chunk)
        if read < MAX_PATTERN_READ:
            text = (tail + chunk).decode('latin-1')
            for label, pattern in INDICATORS:
                if pattern.search(text):
                    matches.add(label)
            tail = chunk[-512:]
        read += len(chunk)
    return (digest.hexdigest() if read >= size else None), sorted(matches)


def _link(path):
    try:
        target = os.readlink(path)
    except OSError:
        target = None
    entry = dict(kind='link', target=target, target_kind='missing', sha256=None, size=None, mtime_ns=None,
                 indicators=[])
    try:
        info = os.stat(path)
    except OSError:
        return entry
    if stat.S_ISDIR(info.st_mode):
        entry['target_kind'] = 'folder'      # not followed: it may lead out of the web root or loop
        return entry
    if not stat.S_ISREG(info.st_mode):
        entry['target_kind'] = 'other'
        return entry
    entry.update(target_kind='file', size=info.st_size, mtime_ns=info.st_mtime_ns)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return entry
    try:
        entry['sha256'], entry['indicators'] = _hash_and_match(fd, info.st_size)
    finally:
        os.close(fd)
    return entry


def snapshot(web_roots=None):
    files, gaps, walked = {}, [], 0
    chosen = roots(web_roots)
    if not chosen:
        gaps.append('no web root folder exists; pass --root for this server\'s document roots')
    for root in chosen:
        stack = [(root, 0)]
        while stack:
            folder, depth = stack.pop()
            try:
                entries = os.scandir(folder)
            except OSError:
                gaps.append(f'{folder} cannot be read')
                continue
            with entries:
                for entry in entries:
                    walked += 1
                    if walked > MAX_WALK or len(files) >= MAX_FILES:
                        break
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if stat.S_ISDIR(info.st_mode):
                        if entry.name not in SKIP_FOLDERS and depth < MAX_DEPTH:
                            stack.append((entry.path, depth + 1))
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        # A web server that follows links serves whatever the link points to: record the target,
                        # and the contents when it is a file, instead of skipping it.
                        files[entry.path] = _link(entry.path)
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    try:
                        fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                    except OSError:
                        if os.path.splitext(entry.name)[1].lower() in SCRIPT_SUFFIXES:
                            files[entry.path] = dict(kind='script', size=info.st_size, sha256=None,
                                                     mtime_ns=info.st_mtime_ns,
                                                     mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid,
                                                     indicators=[], unreadable=True)
                        continue
                    try:
                        kind = _classify(entry.path, _read_head(fd))
                        if kind is None:
                            continue
                        digest, indicators = _hash_and_match(fd, info.st_size)
                    finally:
                        os.close(fd)
                    files[entry.path] = dict(kind=kind, size=info.st_size, sha256=digest, mtime_ns=info.st_mtime_ns,
                                             mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid,
                                             indicators=indicators)
            if walked > MAX_WALK or len(files) >= MAX_FILES:
                gaps.append('the scan reached its limit; later files were not recorded')
                break
    folders = sum(1 for f in files.values() if f.get('target_kind') == 'folder')
    if folders:
        gaps.append(f'{folders} links to folders were recorded but not followed; their contents are not checked')
    unreadable = sum(1 for f in files.values() if f.get('unreadable'))
    if unreadable:
        gaps.append(f'{unreadable} scripts could not be read; run as root or as the web server\'s owner')
    return dict(roots=chosen, files=files, gaps=gaps)


def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.webroot-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise WebrootError(f'no web-root baseline at {path}; run megalodon webroot baseline') from None
    except OSError as exc:
        raise WebrootError(f'web-root baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise WebrootError(f'web-root baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise WebrootError('web-root baseline is too large')
    try:
        value = json.loads(raw)
    except ValueError:
        raise WebrootError('web-root baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('files')) is not dict:
        raise WebrootError('web-root baseline has an unsupported format')
    return value


def _finding(rule, path, entry, detail):
    severity, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=['T1505.003'], path=path, detail=detail,
                summary=summary, sha256=entry.get('sha256'), size=entry.get('size'), uid=entry.get('uid'))


def _in_upload_folder(path, root_list):
    root = next((r for r in root_list if path.startswith(r.rstrip('/') + '/')), '')
    parts = path[len(root):].strip('/').split('/')[:-1]
    return any(part.lower() in UPLOAD_FOLDERS for part in parts)


def _indicator_findings(path, entry):
    return [_finding('WEB_SHELL_PATTERN', path, entry, f'{path}: {label}') for label in entry.get('indicators', [])]


def _same(before, entry):
    if (before.get('kind') == 'link') != (entry.get('kind') == 'link'):
        return False
    if entry.get('kind') == 'link' and before.get('target') != entry.get('target'):
        return False
    if before.get('sha256') and entry.get('sha256'):
        return before['sha256'] == entry['sha256']
    # Too large to hash or unreadable: fall back to size and modification time.
    return (before.get('sha256') is None and entry.get('sha256') is None and before.get('size') == entry.get('size')
            and before.get('mtime_ns') == entry.get('mtime_ns'))


def compare(old, new, root_list):
    findings, removed = [], sorted(set(old) - set(new))
    for path in sorted(new):
        entry, before = new[path], old.get(path)
        if before is not None and _same(before, entry):
            continue
        if entry['kind'] == 'link':
            shown = f"{path} -> {entry.get('target')}"
            if before is not None and before.get('kind') != 'link':
                findings.append(_finding('WEB_SCRIPT_REPLACED_BY_LINK', path, entry,
                                         f'script {path} was replaced by a link: {shown}'))
            elif before is None:
                findings.append(_finding('WEB_LINK_ADDED', path, entry, f'new link {shown}'))
            else:
                findings.append(_finding('WEB_LINK_CHANGED', path, entry, f'link {shown} now leads elsewhere or '
                                                                         'to changed contents'))
            findings += _indicator_findings(path, entry)
            continue
        if entry['kind'] == 'hidden':
            findings.append(_finding('CODE_IN_NON_SCRIPT_FILE', path, entry,
                                     f'{path} contains server-side code but is not a script'))
        elif before is None and _in_upload_folder(path, root_list):
            findings.append(_finding('SCRIPT_IN_UPLOAD_FOLDER', path, entry, f'new script {path} in an upload or '
                                                                             'static folder'))
        elif before is None:
            findings.append(_finding('WEB_SCRIPT_ADDED', path, entry, f'new script {path}'))
        else:
            findings.append(_finding('WEB_SCRIPT_CHANGED', path, entry, f'{path} changed'))
        findings += _indicator_findings(path, entry)
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['path'], f['rule_id']))
    return findings, removed


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, web_roots=None):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise WebrootError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(web_roots)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), **state))
    # A web shell already present is recorded as normal unless it is reported now.
    present = []
    for name, entry in sorted(state['files'].items()):
        if entry['kind'] == 'hidden':
            present.append(_finding('CODE_IN_NON_SCRIPT_FILE', name, entry,
                                    f'{name} contains server-side code but is not a script'))
        present += _indicator_findings(name, entry)
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), roots=state['roots'],
                files=len(state['files']), findings=present, gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, *, web_roots=None):
    old = _read(manifest)
    new = snapshot(web_roots or old.get('roots') or None)
    findings, removed = compare(old['files'], new['files'], new['roots'])
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()),
                baseline_recorded_at=old.get('recorded_at'), checked_at=_now(), roots=new['roots'],
                findings=findings, removed=removed, gaps=new['gaps'],
                note='Review each file; accept records the reviewed state. Nothing was changed.')


def accept(manifest=DEFAULT_MANIFEST, *, web_roots=None):
    old = _read(manifest)
    return dict(baseline(manifest, replace=True, web_roots=web_roots or old.get('roots') or None), action='accept')
