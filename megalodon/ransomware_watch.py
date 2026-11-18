"""Live watch for ransomware-style file encryption in folders the operator chooses.

Encryption leaves a recognizable trail: files whose format signature (PDF,
Office/ZIP, JPEG, PNG, text, ...) is replaced by high-entropy bytes with no
known signature, often written next to the deletion or rename of the original,
and ransom notes dropped across folders. This module watches folders with
Linux inotify (no extra dependency), samples each written file's first 64 KiB,
and raises:

``RANSOMWARE_ENCRYPTION`` (CRITICAL, ATT&CK T1486)
    At least ``min_files`` files turned from a recognized format into
    encrypted-looking data within ``window_seconds``. A file counts when its
    earlier content was recognized, or when it replaces a file just deleted or
    renamed in the same folder.
``RANSOMWARE_MASS_WRITE`` (HIGH, T1486)
    Many new encrypted-looking files with no recognized predecessor in one
    window, as when a tool writes encrypted copies under new names.
``RANSOM_NOTE`` (HIGH, T1486)
    A file named like a ransom note (``HOW_TO_DECRYPT.txt``, ``_readme.txt``,
    ``RESTORE_FILES.html``, ...) was created.

Each finding names, best effort, the processes that hold files open under the
watched folders, read from ``/proc``. Nothing is blocked, killed or restored:
this is an alarm, so you can disconnect and stop the process while it runs.
"""
from __future__ import annotations

from collections import OrderedDict, deque
import ctypes
import ctypes.util
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import math
import os
from pathlib import Path
import re
import select
import stat
import struct
import sys
import time

SAMPLE_BYTES = 64 * 1024
MIN_BYTES = 1024
HIGH_ENTROPY = 7.5
MAX_BASELINE = 50_000
MAX_DIRS = 8192
MAX_SUSPECTS = 16
ATTACK = ('T1486',)

# Leading bytes of formats people keep, and that encryption destroys.
_MAGIC = (
    (0, b'%PDF'), (0, b'PK\x03\x04'), (0, b'PK\x05\x06'), (0, b'\x89PNG'), (0, b'\xff\xd8\xff'),
    (0, b'GIF8'), (0, b'ID3'), (0, b'\xff\xfb'), (0, b'\xff\xf3'), (0, b'RIFF'), (0, b'OggS'), (0, b'fLaC'),
    (0, b'\x1f\x8b'), (0, b'BZh'), (0, b'\xfd7zXZ'), (0, b'7z\xbc\xaf\x27\x1c'), (0, b'Rar!'),
    (0, b'\x7fELF'), (0, b'MZ'), (0, b'SQLite format 3'), (0, b'%!PS'), (0, b'{\\rtf'),
    (0, b'\xd0\xcf\x11\xe0'), (0, b'wOFF'), (0, b'\x00\x00\x01\x00'), (0, b'II*\x00'), (0, b'MM\x00*'),
    (0, b'8BPS'), (0, b'\x1aE\xdf\xa3'), (4, b'ftyp'), (0, b'BM'), (257, b'ustar'), (0, b'\x28\xb5\x2f\xfd'),
    (0, b'-----BEGIN'), (0, b'ssh-'), (0, b'\x04\x22\x4d\x18'),
)
_NOTE = re.compile(
    r'(?i)^(?:[!_#@~-]*)(?:'
    r'(?:read|how)[ _.-]?(?:me)?[ _.-]*(?:to)?[ _.-]*(?:decrypt|restore|recover|unlock)[\w .-]*'
    r'|(?:decrypt|restore|recover|unlock)[ _.-]*(?:my[ _.-]*)?(?:files?|data|instructions?|info)\w*'
    r'|_readme|ransom\w*|your[ _.-]*files[ _.-]*(?:are|were)[ _.-]*encrypted\w*'
    r')[!_#@~ -]*\.(?:txt|html?|hta|rtf|url|png|jpg|bmp)$')
# Extensions ransomware families append. A hint only: content must also look encrypted.
_RANSOM_EXT = re.compile(
    r'(?i)\.(?:locked|lock|encrypted|enc|crypt|crypted|cry|crypz|cerber\d?|locky|zepto|odin|wncry|wnry|wcry'
    r'|ryk|conti|lockbit|abcd|djvu|kraken|darkness|nochance|aes|rsa|xxx|ttt|micro|vvv|ccc|zzz|exx|ezz)$')

# inotify event bits (linux/inotify.h)
IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x2, 0x8, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR = (
    0x100, 0x200, 0x400, 0x4000, 0x8000, 0x40000000)
WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF


class WatchError(OSError):
    pass


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum(c / total * math.log2(c / total) for c in counts if c)


def _looks_text(data: bytes) -> bool:
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        # A sample can cut a multi-byte character at its end.
        try:
            text = data[:-4].decode('utf-8')
        except UnicodeDecodeError:
            return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in '\r\n\t')
    return printable >= 0.95 * max(1, len(text))


def classify_bytes(data: bytes) -> str:
    """'known' (recognized format), 'text', 'encrypted' (no signature, high entropy) or 'opaque'."""
    if len(data) < MIN_BYTES:
        return 'small'
    if any(data[offset:offset + len(magic)] == magic for offset, magic in _MAGIC):
        return 'known'
    if _looks_text(data[:8192]):
        return 'text'
    return 'encrypted' if entropy(data) >= HIGH_ENTROPY else 'opaque'


def classify(path) -> str | None:
    """Classify a regular file without following links or blocking on FIFOs; None if unreadable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return classify_bytes(os.read(fd, SAMPLE_BYTES))
    except OSError:
        return None
    finally:
        os.close(fd)


@dataclass
class Finding:
    rule_id: str
    severity: str
    detected_at: datetime
    message: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self):
        return dict(schema='megalodon-ransomware-finding-v1', rule_id=self.rule_id, severity=self.severity,
                    detected_at=self.detected_at.strftime('%Y-%m-%dT%H:%M:%SZ'), message=self.message,
                    attack=list(ATTACK), evidence=self.evidence)


class RansomwareDetector:
    """Pure decision logic over file events; the watcher feeds it, tests drive it directly."""

    def __init__(self, *, min_files=10, window_seconds=60, cooldown_seconds=300, max_baseline=MAX_BASELINE,
                 classifier=classify, clock=time.monotonic, wallclock=None):
        if not 2 <= min_files <= 10000 or not 5 <= window_seconds <= 3600:
            raise ValueError('min_files must be 2-10000 and window_seconds 5-3600')
        self.min_files, self.window = min_files, window_seconds
        self.cooldown = cooldown_seconds
        self.classifier, self.clock = classifier, clock
        self.wallclock = wallclock or (lambda: datetime.now(timezone.utc))
        self.baseline: OrderedDict[str, str] = OrderedDict()
        self.max_baseline = max_baseline
        self.gone: deque[tuple[float, str, str]] = deque()  # (time, folder, name) recently deleted or renamed away
        self.strong: deque[tuple[float, str]] = deque()
        self.weak: deque[tuple[float, str]] = deque()
        self.last: dict[str, float] = {}

    def remember(self, path, kind):
        if kind is None:
            return
        self.baseline[path] = kind
        self.baseline.move_to_end(path)
        while len(self.baseline) > self.max_baseline:
            self.baseline.popitem(last=False)

    def seed(self, roots, *, max_files=MAX_BASELINE):
        """Record what existing files look like, so a later rewrite can be compared."""
        seen = 0
        for root in roots:
            # The watcher reports resolved absolute paths; the baseline must use the same keys.
            root = os.path.realpath(root)
            for folder, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if not d.startswith('.')]
                for name in files:
                    if seen >= max_files:
                        return seen
                    path = os.path.join(folder, name)
                    self.remember(path, self.classifier(path))
                    seen += 1
        return seen

    def _prune(self, now):
        for queue in (self.gone, self.strong, self.weak):
            while queue and queue[0][0] < now - self.window:
                queue.popleft()

    def _emit(self, key, now):
        if now - self.last.get(key, -1e18) < self.cooldown:
            return False
        self.last[key] = now
        return True

    def rename_tree(self, old, new):
        """A watched folder was renamed: its files keep their recorded history."""
        prefix = old.rstrip('/') + '/'
        if not any(key.startswith(prefix) for key in self.baseline):
            return
        self.baseline = OrderedDict(
            (new.rstrip('/') + '/' + key[len(prefix):] if key.startswith(prefix) else key, kind)
            for key, kind in self.baseline.items())

    def deleted(self, path):
        now = self.clock()
        self._prune(now)
        folder, name = os.path.split(path)
        self.gone.append((now, folder, name))
        return []

    def moved_away(self, path):
        return self.deleted(path)

    def written(self, path, *, previous_path=None):
        """A file was closed after writing, or renamed into place (previous_path)."""
        now = self.clock()
        self._prune(now)
        folder, name = os.path.split(path)
        findings = []
        if _NOTE.match(name) and self._emit(('note', name.lower()), now):
            findings.append(Finding('RANSOM_NOTE', 'HIGH', self.wallclock(),
                                    f'A ransom-note-like file {name} appeared in {folder}',
                                    dict(file=name, folder=folder)))
        # A rename onto an existing file replaces that file: either history counts.
        before = self.baseline.get(path)
        source = self.baseline.get(previous_path) if previous_path else None
        recognized = before in ('known', 'text') or source in ('known', 'text')
        kind = self.classifier(path)
        self.remember(path, kind)
        if previous_path:
            self.baseline.pop(previous_path, None)
        if kind != 'encrypted':
            return findings
        stem = name.rsplit('.', 1)[0]
        # Same name, the old name plus an added extension, or the same stem with a swapped one.
        replaced = recognized or any(
            f == folder and (name == g or name.startswith(g + '.') or (stem != name and g.startswith(stem + '.')))
            for _, f, g in self.gone)
        # Encrypted data that only moved (a staged .tmp renamed to .enc) is not new encryption.
        already = 'encrypted' in (before, source)
        if replaced or (_RANSOM_EXT.search(name) and not already):
            self.strong.append((now, path))
        else:
            self.weak.append((now, path))
        strong = {p for _, p in self.strong}
        if len(strong) >= self.min_files and self._emit(('encryption',), now):
            findings.append(Finding(
                'RANSOMWARE_ENCRYPTION', 'CRITICAL', self.wallclock(),
                f'{len(strong)} files turned into encrypted-looking data within {self.window}s; '
                'this is how ransomware encrypts files',
                dict(files=len(strong), threshold=self.min_files, window_seconds=self.window,
                     examples=sorted(strong)[:5])))
        weak = {p for _, p in self.weak}
        if len(weak) >= 3 * self.min_files and self._emit(('mass',), now):
            findings.append(Finding(
                'RANSOMWARE_MASS_WRITE', 'HIGH', self.wallclock(),
                f'{len(weak)} new encrypted-looking files were written within {self.window}s',
                dict(files=len(weak), threshold=3 * self.min_files, window_seconds=self.window,
                     examples=sorted(weak)[:5])))
        return findings


def suspects(roots, *, proc='/proc', limit=MAX_SUSPECTS):
    """Processes holding files open under the watched folders: pid, name and program path."""
    prefixes = tuple(os.path.join(os.path.realpath(r), '') for r in roots)
    found, uid = [], os.geteuid()
    try:
        pids = [p for p in os.listdir(proc) if p.isdigit()]
    except OSError:
        return found
    for pid in pids:
        if len(found) >= limit:
            break
        base = os.path.join(proc, pid)
        try:
            if uid != 0 and os.stat(base).st_uid != uid:
                continue
            fds = os.listdir(os.path.join(base, 'fd'))
        except OSError:
            continue
        hits = 0
        for fd in fds[:4096]:
            try:
                target = os.readlink(os.path.join(base, 'fd', fd))
            except OSError:
                continue
            if target.startswith(prefixes):
                hits += 1
        if not hits:
            continue
        try:
            comm = Path(base, 'comm').read_text().strip()[:64]
        except OSError:
            comm = ''
        try:
            exe = os.readlink(os.path.join(base, 'exe'))[:512]
        except OSError:
            exe = ''
        found.append(dict(pid=int(pid), name=comm, program=exe, open_files=hits))
    return sorted(found, key=lambda item: -item['open_files'])


class _Inotify:
    def __init__(self):
        if not sys.platform.startswith('linux'):
            raise WatchError('the ransomware watch needs Linux inotify')
        self.libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6', use_errno=True)
        self.fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        if self.fd < 0:
            raise WatchError(ctypes.get_errno(), 'inotify is unavailable')
        self.paths: dict[int, str] = {}

    def add(self, path):
        wd = self.libc.inotify_add_watch(self.fd, os.fsencode(path), WATCH_MASK)
        if wd < 0:
            code = ctypes.get_errno()
            if code == errno.ENOSPC:
                raise WatchError(code, 'inotify watch limit reached; raise fs.inotify.max_user_watches')
            return False
        fresh = wd not in self.paths
        self.paths[wd] = path  # Re-adding a moved folder's inode updates its path.
        return fresh

    def events(self, timeout):
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return []
        try:
            data = os.read(self.fd, 256 * 1024)
        except BlockingIOError:
            return []
        out, offset = [], 0
        while offset + 16 <= len(data):
            wd, mask, cookie, length = struct.unpack_from('iIII', data, offset)
            name = data[offset + 16:offset + 16 + length].split(b'\0', 1)[0]
            offset += 16 + length
            folder = self.paths.get(wd)
            if mask & IN_IGNORED:
                self.paths.pop(wd, None)
            out.append((mask, cookie, folder, os.fsdecode(name) if name else ''))
        return out

    def close(self):
        os.close(self.fd)


class Watcher:
    """Recursive inotify watch feeding a RansomwareDetector; emit() receives each Finding."""

    def __init__(self, roots, detector, emit, *, max_dirs=MAX_DIRS, suspects_fn=suspects):
        self.roots = [os.path.realpath(r) for r in roots]
        for root in self.roots:
            if not os.path.isdir(root):
                raise WatchError(errno.ENOTDIR, f'{root} is not a folder')
        self.detector, self.emit = detector, emit
        self.max_dirs, self.suspects_fn = max_dirs, suspects_fn
        self.notify = _Inotify()
        self.overflows = 0
        self.watched = 0
        self.truncated = False
        for root in self.roots:
            self._watch_tree(root)

    def _watch_tree(self, root):
        for folder, dirs, _ in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            if self.watched >= self.max_dirs:
                self.truncated = True
                return
            if self.notify.add(folder):
                self.watched += 1

    def run(self, stop, *, poll=0.5):
        moves: dict[int, str] = {}
        folder_moves: dict[int, str] = {}
        while not stop.is_set():
            for mask, cookie, folder, name in self.notify.events(poll):
                if mask & IN_Q_OVERFLOW:
                    self.overflows += 1
                    continue
                if folder is None or not name:
                    continue
                path = os.path.join(folder, name)
                findings = []
                if mask & IN_ISDIR:
                    if mask & IN_MOVED_FROM:
                        folder_moves[cookie] = path
                    if mask & (IN_CREATE | IN_MOVED_TO) and not name.startswith('.'):
                        old = folder_moves.pop(cookie, None) if mask & IN_MOVED_TO else None
                        if old:
                            self.detector.rename_tree(old, path)
                        self._watch_tree(path)
                    if len(folder_moves) > 4096:
                        folder_moves.clear()
                    continue
                if mask & IN_DELETE:
                    findings = self.detector.deleted(path)
                elif mask & IN_MOVED_FROM:
                    moves[cookie] = path
                    findings = self.detector.moved_away(path)
                elif mask & IN_MOVED_TO:
                    findings = self.detector.written(path, previous_path=moves.pop(cookie, None))
                elif mask & IN_CLOSE_WRITE:
                    findings = self.detector.written(path)
                elif mask & IN_CREATE and _NOTE.match(name):
                    findings = self.detector.written(path)
                if len(moves) > 4096:
                    moves.clear()
                for finding in findings:
                    finding.evidence['processes'] = self.suspects_fn(self.roots)
                    self.emit(finding)

    def close(self):
        self.notify.close()


def selftest(directory, *, files=12):
    """Encrypt throwaway copies in a fresh folder and confirm the chain raises the alarm."""
    from threading import Event, Thread
    os.makedirs(directory, mode=0o700, exist_ok=False)
    for i in range(files):
        with open(os.path.join(directory, f'report-{i}.txt'), 'w', encoding='utf-8') as out:
            out.write('Quarterly report. Nothing to see here.\n' * 100)
    found = []
    detector = RansomwareDetector(min_files=max(2, files - 2), window_seconds=60)
    detector.seed([directory])
    watcher = Watcher([directory], detector, found.append, suspects_fn=lambda roots: [])
    stop = Event()
    thread = Thread(target=watcher.run, args=(stop,), kwargs=dict(poll=0.1), daemon=True)
    thread.start()
    try:
        for i in range(files):
            original = os.path.join(directory, f'report-{i}.txt')
            with open(original + '.locked', 'wb') as out:
                out.write(os.urandom(8192))
            os.unlink(original)
        with open(os.path.join(directory, 'HOW_TO_DECRYPT.txt'), 'w', encoding='utf-8') as out:
            out.write('MEGALODON self-test note. No files were harmed.\n')
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and {f.rule_id for f in found} < {'RANSOMWARE_ENCRYPTION', 'RANSOM_NOTE'}:
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(2)
        watcher.close()
    return found
