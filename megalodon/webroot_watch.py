"""Web-root watch: new or changed server-side scripts, the files web shells are.

A web shell is a script dropped where the web server runs it: a `.php` file
in an upload folder, a `.jsp` in a webapps folder, PHP code hidden in a
`.jpg` (ATT&CK T1505.003). `megalodon webroot` records the server-side
code files under the web roots and reports new and changed ones. It also
looks inside each new, changed or baselined file for well-known web-shell
shapes: a command or `eval` call fed straight from request input, or
obfuscated `eval`.

`megalodon webroot watch` looks at each file as it is written, through Linux
inotify, instead of every 15 minutes: a web shell dropped, used and deleted
between two checks is seen, and its deletion soon after it appeared is
reported as WEB_SCRIPT_DROPPED_AND_REMOVED.

Read-only; only code files are recorded and hashed.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time

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
# A script that appeared while watching and is deleted within this long was dropped, used and removed.
DROP_WINDOW = 3600.0
MAX_WATCHED_FOLDERS = 65536
MAX_REMEMBERED = 65536
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
    'WEB_SCRIPT_DROPPED_AND_REMOVED': ('HIGH', 'A server-side script that appeared under a web root was deleted soon '
                                               'after: a web shell dropped, used and removed, which no check finds.'),
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


def examine(path, info=None):
    """What a web root's file is, as the baseline records it: a script, code hidden in a served file, or a link
    (with its target's contents). None for anything else, or a file that is gone."""
    if info is None:
        try:
            info = os.lstat(path)
        except OSError:
            return None
    if stat.S_ISLNK(info.st_mode):
        # A web server that follows links serves whatever the link points to: record the target, and the contents
        # when it is a file, instead of skipping it.
        return _link(path)
    if not stat.S_ISREG(info.st_mode):
        return None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        if os.path.splitext(path)[1].lower() in SCRIPT_SUFFIXES:
            return dict(kind='script', size=info.st_size, sha256=None, mtime_ns=info.st_mtime_ns,
                        mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid, indicators=[], unreadable=True)
        return None
    try:
        kind = _classify(path, _read_head(fd))
        if kind is None:
            return None
        digest, indicators = _hash_and_match(fd, info.st_size)
    finally:
        os.close(fd)
    return dict(kind=kind, size=info.st_size, sha256=digest, mtime_ns=info.st_mtime_ns,
                mode=oct(stat.S_IMODE(info.st_mode)), uid=info.st_uid, indicators=indicators)


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
                    found = examine(entry.path, info)
                    if found is not None:
                        files[entry.path] = found
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


def _skipped(path, root_list):
    """Whether `path` is in a folder the snapshot does not walk (.git, node_modules...), or too deep."""
    root = next((r for r in root_list if path.startswith(r.rstrip('/') + '/')), None)
    if root is None:
        return True
    parts = path[len(root):].strip('/').split('/')[:-1]
    return len(parts) > MAX_DEPTH or any(part in SKIP_FOLDERS for part in parts)


class Watcher:
    """``webroot watch``: look at each file under the web roots as it is written, compared with the baseline, and
    report a script that appeared and was deleted soon after."""

    def __init__(self, manifest=DEFAULT_MANIFEST, emit=print, *, web_roots=None, clock=time.monotonic, warn=None,
                 notify=None, max_folders=MAX_WATCHED_FOLDERS):
        self.manifest, self.emit, self.clock = manifest, emit, clock
        self.warn = warn or (lambda text: print(f'megalodon: {text}', file=sys.stderr, flush=True))
        self.baseline, self.loaded = _read(manifest), self._stamp()
        self.roots = roots(web_roots or self.baseline.get('roots') or None)
        if not self.roots:
            raise WebrootError("no web root folder exists; pass --root for this server's document roots")
        if notify is None:
            from .ransomware_watch import _Inotify
            notify = _Inotify()
        self.notify, self.max_folders = notify, max_folders
        self.reported, self.appeared, self.moving, self.folders_moving = {}, OrderedDict(), {}, {}
        self.watched, self.overflows = 0, 0
        self.stats = dict(events=0, findings=0, dropped=0)
        for root in self.roots:
            self._watch_tree(root)

    def _stamp(self):
        try:
            info = os.stat(Path(self.manifest).expanduser())
            return (info.st_mtime_ns, info.st_size, info.st_ino)
        except OSError:
            return None

    def _watch_tree(self, top):
        """Watch `top` and the folders under it the snapshot walks; return the files found there."""
        found = []
        for folder, dirs, names in os.walk(top, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS and not _skipped(os.path.join(folder, d, 'x'),
                                                                                 self.roots)]
            if self.watched >= self.max_folders:
                self.warn(f'more than {self.max_folders} folders under the web roots: the rest are not watched '
                          'as files are written; the scheduled check still covers them')
                return found
            if self.notify.add(folder):
                self.watched += 1
            found += [os.path.join(folder, name) for name in names]
        return found

    def _send(self, found):
        found = dict(found, detected_at=_now(), live=True)
        self.stats['findings'] += 1
        self.emit(found)
        return found

    def look(self, path):
        """Judge one file as it is now against the baseline; report what changed, once for each content."""
        entry = examine(path)              # skipped folders are never watched, so no event comes from them
        if entry is None:
            return []
        # Its kind and link target too: a script replaced by a link to the same contents is a change.
        mark = (entry['kind'], entry.get('target'), entry.get('sha256') or (entry.get('size'), entry.get('mtime_ns')))
        if self.reported.get(path) == mark:
            return []
        self.reported[path] = mark
        if len(self.reported) > MAX_REMEMBERED:
            self.reported.clear()
        before = self.baseline['files'].get(path)
        findings, _removed = compare({path: before} if before is not None else {}, {path: entry}, self.roots)
        if findings and before is None and entry['kind'] != 'link':
            # When it first appeared, under this name or the one it was renamed from.
            when = self.appeared[path][0] if path in self.appeared else self.clock()
            self.appeared[path] = (when, entry)
            self.appeared.move_to_end(path)
            while len(self.appeared) > MAX_REMEMBERED:
                self.appeared.popitem(last=False)
        return [self._send(found) for found in findings]

    def gone(self, path):
        """A file under a web root was deleted or moved out of it."""
        self.reported.pop(path, None)
        item = self.appeared.pop(path, None)
        if item is None:
            return []
        when, entry = item
        age = self.clock() - when
        if age > DROP_WINDOW:
            return []
        self.stats['dropped'] += 1
        found = _finding('WEB_SCRIPT_DROPPED_AND_REMOVED', path, entry,
                         f'{path} appeared under a web root and was deleted {age:.0f} s later')
        found['techniques'] = ['T1505.003', 'T1070.004']
        return [self._send(found)]

    def _under(self, folder):
        prefix = folder.rstrip('/') + '/'
        return [path for path in list(self.appeared) if path.startswith(prefix)]

    def _folder_renamed(self, old, new):
        """A folder renamed within the web roots: its scripts keep when they first appeared."""
        for path in self._under(old):
            moved = new.rstrip('/') + path[len(old.rstrip('/')):]
            self.appeared[moved] = self.appeared.pop(path)
            if path in self.reported:
                self.reported[moved] = self.reported.pop(path)

    def _folder_gone(self, folder):
        """A folder moved out of the web roots: the kernel sends one event for it, none for what it holds."""
        out = []
        for path in self._under(folder):
            out += self.gone(path)
        prefix = folder.rstrip('/') + '/'
        for path in [p for p in self.reported if p.startswith(prefix)]:
            del self.reported[path]
        return out

    def rescan(self):
        """Look at every file now: at the start, and after the kernel dropped events."""
        out = []
        for path in sorted(snapshot(self.roots)['files']):
            out += self.look(path)
        return out

    def handle(self, events):
        from .ransomware_watch import (IN_CLOSE_WRITE, IN_CREATE, IN_DELETE, IN_ISDIR, IN_MOVED_FROM, IN_MOVED_TO,
                                       IN_Q_OVERFLOW)
        out, overflowed = [], False
        for mask, cookie, folder, name in events:
            self.stats['events'] += 1
            if mask & IN_Q_OVERFLOW:
                overflowed = True
                continue
            if folder is None or not name:
                continue
            path = os.path.join(folder, name)
            if mask & IN_ISDIR:
                if mask & IN_MOVED_FROM:
                    self.folders_moving[cookie] = path
                    continue
                if mask & IN_MOVED_TO:
                    old = self.folders_moving.pop(cookie, None)
                    if old is not None:
                        self._folder_renamed(old, path)
                if mask & (IN_CREATE | IN_MOVED_TO) and not _skipped(os.path.join(path, 'x'), self.roots):
                    for inside in self._watch_tree(path):  # a folder moved in may already hold a script
                        out += self.look(inside)
                continue
            if mask & IN_MOVED_FROM:
                self.moving[cookie] = path
            elif mask & IN_DELETE:
                out += self.gone(path)
            elif mask & IN_MOVED_TO:
                old = self.moving.pop(cookie, None)
                if old is not None and old in self.appeared:     # renamed within the web roots
                    self.appeared[path] = self.appeared.pop(old)
                    self.reported.pop(old, None)
                out += self.look(path)
            elif mask & IN_CLOSE_WRITE or (mask & IN_CREATE and os.path.islink(path)):
                out += self.look(path)
        # A move whose other half never came in this batch left the web roots.
        for cookie in list(self.moving):
            out += self.gone(self.moving.pop(cookie))
        for cookie in list(self.folders_moving):
            out += self._folder_gone(self.folders_moving.pop(cookie))
        if overflowed:
            self.overflows += 1
            self.warn('the kernel dropped file events under load; every folder is watched and every file looked '
                      'at again')
            for root in self.roots:                  # a folder made while events were lost has no watch yet
                self._watch_tree(root)
            out += self.rescan()
        return out

    def run(self, stop, *, poll=0.5):
        try:
            self.rescan()
            while not stop.is_set():
                stamp = self._stamp()
                if stamp != self.loaded:             # `accept` changed the baseline while watching
                    self.baseline, self.loaded, self.reported = _read(self.manifest), stamp, {}
                self.handle(self.notify.events(poll))
        finally:
            self.close()

    def close(self):
        if self.notify is not None:
            self.notify.close()
            self.notify = None
