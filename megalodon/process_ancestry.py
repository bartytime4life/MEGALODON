"""Services that start shells, interpreters or attack tools: web shells and exploited daemons.

A web server, database or mail server has no reason to run `sh`, `python`, `nc`
or `id`. When one does, a web shell or an exploited service is the usual
cause (ATT&CK T1505.003, T1059). `check` reviews the processes running now;
`watch` sees each program as it starts, through the kernel's process events
(root), or by polling /proc, so short-lived commands are caught too.

Read-only: nothing is stopped or changed. Findings are JSON lines that
`megalodon respond ingest` reads.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import time

from .process_network import _program_kind

SCHEMA = 'megalodon-process-ancestry-v1'
MAX_DEPTH = 32
MAX_ARGV_BYTES = 512
MAX_PROCESSES = 65536
MAX_TRACKED = 65536
COOLDOWN_SECONDS = 300

# Services by executable file name. Each one only answers requests; none needs a shell to do so.
SERVICES = {
    'web': {'nginx', 'apache2', 'httpd', 'lighttpd', 'caddy', 'uwsgi', 'hiawatha', 'h2o', 'unitd', 'openresty',
            'tomcat', 'jetty'},
    'database': {'mysqld', 'mariadbd', 'postgres', 'postmaster', 'mongod', 'redis-server', 'memcached',
                 'clickhouse-server', 'influxd', 'valkey-server'},
    'mail': {'exim', 'exim4', 'dovecot', 'smtpd', 'opensmtpd'},
    'file sharing': {'vsftpd', 'proftpd', 'pure-ftpd', 'smbd'},
}
_PHP_FPM = re.compile(r'php-fpm[0-9.]*')
# Application servers are often an interpreter or the JVM running the application itself (gunicorn, uvicorn,
# node server.js, java -jar). Such a process counts as a service while it holds a listening TCP socket.
RUNTIMES = frozenset({'java'})
MAX_FDS = 4096
QUIET_SECONDS = 30.0              # how long "not listening" is remembered: a server opens its port after it starts
# Programs an intruder runs first: transfer and relay tools, and quick system reconnaissance.
TOOLS = {'nc', 'ncat', 'netcat', 'nc.openbsd', 'nc.traditional', 'socat', 'curl', 'wget', 'telnet', 'tftp', 'ftp',
         'nmap', 'masscan', 'ssh', 'scp', 'sftp', 'openssl', 'base64', 'xxd'}
RECON = {'id', 'whoami', 'uname', 'hostname', 'ifconfig', 'netstat', 'ss', 'getent', 'w', 'who', 'last',
         'groups', 'lsb_release', 'crontab'}
# What services legitimately run through `sh -c`: PHP's mail(), Apache's piped logs.
HELPERS = {'sendmail', 'rotatelogs', 'cronolog', 'logger', 'postdrop', 'msmtp', 'ssmtp'}
CGI_ROOTS = ('/usr/lib/cgi-bin/', '/var/www/cgi-bin/', '/srv/www/cgi-bin/', '/var/www/html/cgi-bin/')
_SHELL_SYNTAX = re.compile(r'[;&|`$()<>\n\\*?!{}\[\]#~]')

RULES = {
    'SERVICE_SPAWNED_SHELL': ('A network service started a shell or script interpreter. Web shells and exploited '
                              'services do this to run commands; CGI scripts and some maintenance hooks also do.'),
    'SERVICE_SPAWNED_TOOL': ('A network service started a transfer, relay or reconnaissance tool such as curl, nc '
                             'or id, as an intruder does after taking over a service.'),
}


class AncestryError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def service_category(path, comm):
    for name in (path.rsplit('/', 1)[-1], comm):
        if not name:
            continue
        if _PHP_FPM.fullmatch(name):
            return 'web'
        for category, names in SERVICES.items():
            if name in names:
                return category
    if path.startswith('/usr/lib/postfix/') or path.startswith('/usr/libexec/postfix/'):
        return 'mail'
    return None


def program_kind(path, comm):
    """'shell', 'interpreter', 'tool', 'recon' or None."""
    kind = _program_kind(path, comm)
    if kind:
        return kind
    for name in (path.rsplit('/', 1)[-1], comm):
        if name in TOOLS:
            return 'tool'
        if name in RECON:
            return 'recon'
    return None


@dataclass
class Proc:
    pid: int
    ppid: int | None
    path: str
    comm: str
    uid: int | None
    start: int | None
    argv: list = field(default_factory=list)
    cwd: str = ''


def read_proc(base, pid):
    """One process from /proc, or None if it is gone. Unreadable fields stay empty."""
    proc = base / str(pid)
    try:
        text = (proc / 'stat').read_text('utf-8', 'replace')
    except OSError:
        return None
    try:
        comm = text[text.index('(') + 1:text.rindex(')')]
        rest = text[text.rindex(')') + 2:].split()
        ppid = int(rest[1])
        start = int(rest[19]) if len(rest) > 19 else None
    except (ValueError, IndexError):
        return None
    try:
        path = os.readlink(proc / 'exe').removesuffix(' (deleted)')
    except OSError:
        path = ''
    try:
        uid = os.stat(proc, follow_symlinks=False).st_uid
    except OSError:
        uid = None
    try:
        with open(proc / 'cmdline', 'rb') as handle:
            raw = handle.read(MAX_ARGV_BYTES)
        argv = [part.decode('utf-8', 'replace') for part in raw.split(b'\0') if part]
    except OSError:
        argv = []
    try:
        cwd = os.readlink(proc / 'cwd')
    except OSError:
        cwd = ''
    return Proc(pid, ppid, path, comm, uid, start, argv, cwd)


def _allowed_helper(argv):
    """`sh -c "sendmail -t -i"`: one helper program, no shell syntax at all."""
    if len(argv) != 3 or argv[1] != '-c':
        return False
    command = argv[2]
    if _SHELL_SYNTAX.search(command):
        return False
    words = command.split()
    return bool(words) and words[0].rsplit('/', 1)[-1] in HELPERS


_CODE_OPTION = re.compile(r'-[A-Za-z]*[ceEr]')     # sh -c, perl/ruby -e/-E, php -r: code given as text
_PLAIN_PATH = re.compile(r'/[\w.@+-]+(?:/[\w.@+-]+)*')


def _cgi_script(argv):
    """`perl -T /usr/lib/cgi-bin/x.pl`: an interpreter given a script file, never code as a string."""
    if any(_CODE_OPTION.match(a) for a in argv[1:] if a.startswith('-') and not a.startswith('--')):
        return False
    operands = [a for a in argv[1:] if not a.startswith('-')]
    return bool(operands) and operands[0].startswith(CGI_ROOTS) and bool(_PLAIN_PATH.fullmatch(operands[0]))


def _load_allow(path):
    if path is None:
        return set()
    try:
        info = os.stat(path)
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise AncestryError(f'{path}: {exc.strerror}') from None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise AncestryError(f'{path} must be a regular file owned by you and writable only by you')
    try:
        data = json.loads(Path(path).read_text('utf-8'))
        return {(item['service'], item['program']) for item in data.get('allow', [])}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        raise AncestryError(f'{path} is not a valid allow list') from None


def allow(path, service, program):
    """Record that SERVICE may start PROGRAM (both executable paths; an application service is named as its
    finding's `allow_as` gives it, its runtime and what it runs). Owner-only."""
    for value in (service, program):
        if not value.startswith('/'):
            raise AncestryError('service and program must be absolute executable paths')
    entries = _load_allow(path)
    entries.add((service, program))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f'.{path.name}.{os.getpid()}')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(dict(schema=SCHEMA + '-allow',
                       allow=[dict(service=s, program=p) for s, p in sorted(entries)]), out, indent=2)
    os.replace(temporary, path)
    return len(entries)


def _runtime(proc):
    """Whether this process is an interpreter or the JVM, which run applications as themselves."""
    from .process_network import _program_kind
    name = proc.path.rsplit('/', 1)[-1]
    return _program_kind(proc.path, proc.comm) == 'interpreter' or name in RUNTIMES or proc.comm in RUNTIMES


def service_label(proc, category):
    """How a service is named and allowed: its program, or for an application its runtime and what it runs
    (`/usr/bin/python3 /usr/local/bin/gunicorn`, `/usr/bin/java -jar /opt/app.jar`), so allowing one Python
    application does not allow them all. A relative script or archive is resolved against the application's working
    directory, so `node server.js` in /srv/a and in /srv/b are two applications, and the directory is part of the
    name, so two gunicorn applications are too."""
    if category != 'application':
        return proc.path
    from .egress_watch import script
    found = script(dict(path=proc.path, argv=proc.argv, cwd=proc.cwd or None))
    if found is None and '-jar' in proc.argv[:-1]:
        archive = proc.argv[proc.argv.index('-jar') + 1]
        if not archive.startswith('/'):
            archive = os.path.normpath(os.path.join(proc.cwd, archive)) if proc.cwd else f'./{archive}'
        found = f"-jar {archive}"
    label = f'{proc.path} {found}' if found else proc.path
    # A launcher (gunicorn, uvicorn, `-m flask`) is the same file for every application it runs: the folder each runs
    # in tells them apart.
    return f'{label} in {proc.cwd}' if proc.cwd else label


class Listeners:
    """Whether a process holds a listening TCP socket, read from its own network namespace's tables."""

    def __init__(self, base, clock=time.monotonic):
        self.base, self.clock, self.seen = Path(base), clock, OrderedDict()

    def __call__(self, proc):
        key = (proc.pid, proc.start)
        known = self.seen.get(key)
        if known is not None and (known[0] or self.clock() - known[1] < QUIET_SECONDS):
            return known[0]
        result = self._listens(proc.pid)
        self.seen[key] = (result, self.clock())
        self.seen.move_to_end(key)
        while len(self.seen) > MAX_TRACKED:
            self.seen.popitem(last=False)
        return result

    def _listens(self, pid):
        here, listening = self.base / str(pid), set()
        for name in ('tcp', 'tcp6'):
            try:
                lines = (here / 'net' / name).read_text('ascii', 'replace').splitlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) > 9 and fields[3] == '0A':
                    listening.add(fields[9])
        if not listening:
            return False
        try:
            with os.scandir(here / 'fd') as descriptors:
                for number, fd in enumerate(descriptors):
                    if number >= MAX_FDS:
                        break
                    try:
                        target = os.readlink(fd.path)
                    except OSError:
                        continue
                    if target.startswith('socket:[') and target[8:-1] in listening:
                        return True
        except OSError:
            pass
        return False


class Judge:
    """Decides, for one started program, whether a service ancestor makes it a finding."""

    def __init__(self, allowed=frozenset(), listens=None):
        self.allowed = set(allowed)
        self.listens = listens

    def judge(self, proc, ancestors, now):
        kind = program_kind(proc.path, proc.comm)
        if kind is None:
            return None
        service = next(((a, c) for a in ancestors if (c := service_category(a.path, a.comm))), None)
        if service is None and self.listens is not None:
            service = next(((a, 'application') for a in ancestors if _runtime(a) and self.listens(a)), None)
        if service is None:
            return None
        parent, category = service
        if category == 'application' and proc.path == parent.path:
            return None              # the runtime starting itself again: Python's multiprocessing, Node's cluster
        label = service_label(parent, category)
        if (label, proc.path) in self.allowed:
            return None
        direct = ancestors[0] if ancestors else None
        if kind == 'shell' and _allowed_helper(proc.argv):
            return None
        if kind in ('shell', 'interpreter') and direct is parent and category == 'web' and _cgi_script(proc.argv):
            return None
        rule = 'SERVICE_SPAWNED_SHELL' if kind in ('shell', 'interpreter') else 'SERVICE_SPAWNED_TOOL'
        severity = 'HIGH' if category in ('web', 'database') else 'MEDIUM'      # applications: MEDIUM
        attack = ['T1505.003'] if category == 'web' else []
        attack += {'shell': ['T1059.004'], 'interpreter': ['T1059'], 'tool': ['T1105'],
                   'recon': ['T1082', 'T1033']}[kind]
        name = proc.path.rsplit('/', 1)[-1] or proc.comm
        service_name = parent.path.rsplit('/', 1)[-1] or parent.comm
        if category == 'application' and label != parent.path:
            service_name = f"{service_name} {label[len(parent.path) + 1:]}"
        return dict(
            schema=SCHEMA, rule_id=rule, severity=severity, detected_at=now, attack=attack,
            message=f'{category} service {service_name} (pid {parent.pid}) started {kind} {name} (pid {proc.pid})',
            summary=RULES[rule],
            evidence=dict(
                program=proc.path, kind=kind, pid=proc.pid, start=proc.start, uid=proc.uid,
                argv=[a[:MAX_ARGV_BYTES] for a in proc.argv][:16],
                service=dict(program=parent.path, category=category, pid=parent.pid, start=parent.start,
                             **(dict(allow_as=label) if category == 'application' else {})),
                chain=[a.path or a.comm for a in ancestors[:MAX_DEPTH]],
                # The shape `megalodon respond ingest` reads: processes with their identity.
                processes=[dict(program=proc.path, pid=proc.pid, start=proc.start)]))


def _ancestors(base, proc, cache, parent_of, forked=lambda pid: False):
    """Parents up to init. A parent that already exited comes from the cache, so `sh -c 'id &'` run by a
    service still leads back to it after the shell is gone and `id` was reparented.

    A cached parent is trusted over the live process at that PID only when a fork event tied this child to
    it (`forked`). Otherwise the PID may simply have been reused, and the live process is the parent."""
    chain, seen, child, ppid = [], {proc.pid}, proc, parent_of(proc)
    while ppid and ppid not in seen and len(chain) < MAX_DEPTH:
        seen.add(ppid)
        item = read_proc(base, ppid)
        cached = cache.get(ppid)
        if item is None:
            item = cached if forked(child.pid) else None
        elif cached is not None and cached.start is not None and item.start != cached.start and forked(child.pid):
            item = cached            # the PID now belongs to another process; the one that forked us is gone
        if item is None:
            break
        cache[ppid] = item
        chain.append(item)
        child, ppid = item, parent_of(item)
    return chain


def check(root='/', *, allow_path=None, now=None):
    """Findings for the processes running now."""
    base = Path(root, 'proc')
    judge = Judge(_load_allow(allow_path), listens=Listeners(base))
    now = now or _now()
    findings, gaps, reviewed = [], [], 0
    try:
        with os.scandir(base) as listing:
            pids = [int(e.name) for e in listing if e.name.isdigit()]
    except OSError as exc:
        raise AncestryError(f'{base} cannot be read: {exc.strerror}') from None
    if len(pids) > MAX_PROCESSES:
        gaps.append(f'only the first {MAX_PROCESSES} processes were reviewed')
        pids = sorted(pids)[:MAX_PROCESSES]
    procs = {}
    for pid in pids:
        item = read_proc(base, pid)
        if item is not None:
            procs[pid] = item
    unreadable = 0
    for item in procs.values():
        reviewed += 1
        if not item.path and item.argv:   # kernel threads have neither a program nor a command line
            unreadable += 1
        chain, ppid, seen = [], item.ppid, {item.pid}
        while ppid in procs and ppid not in seen and len(chain) < MAX_DEPTH:
            seen.add(ppid)
            chain.append(procs[ppid])
            ppid = procs[ppid].ppid
        found = judge.judge(item, chain, now)
        if found:
            findings.append(found)
    if unreadable:
        gaps.append(f'{unreadable} processes\' programs could not be read'
                    + ('; run as root to see every process' if os.geteuid() else ''))
    return dict(schema=SCHEMA, checked_at=now, processes_reviewed=reviewed, findings=findings, gaps=gaps)


# ------------------------------------------------------------------ live: kernel process events

NETLINK_CONNECTOR, CN_IDX_PROC, CN_VAL_PROC = 11, 1, 1
PROC_CN_MCAST_LISTEN, PROC_CN_MCAST_IGNORE = 1, 2
NLMSG_DONE, NLMSG_HDR, CN_HDR, EVENT_HDR = 3, 16, 20, 16
PROC_EVENT_FORK, PROC_EVENT_EXEC = 0x1, 0x2


class ProcEvents:
    """The kernel's process connector: one event per fork and exec, as they happen. Needs root."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            self.sock.bind((0, CN_IDX_PROC))
            self._control(PROC_CN_MCAST_LISTEN)
        except OSError:
            self.sock.close()
            raise

    def _control(self, op):
        payload = struct.pack('=I', op)
        message = struct.pack('=IIIIHH', CN_IDX_PROC, CN_VAL_PROC, 0, 0, len(payload), 0) + payload
        self.sock.send(struct.pack('=IHHII', NLMSG_HDR + len(message), NLMSG_DONE, 0, 0, 0) + message)

    def events(self, timeout):
        """[(kind, pid, parent)] read within timeout; 'lost' when the kernel dropped some."""
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return []
        try:
            data = self.sock.recv(65536)
        except OSError as exc:
            if exc.errno == errno.ENOBUFS:
                return [('lost', 0, 0)]
            raise
        out, offset = [], 0
        while offset + NLMSG_HDR <= len(data):
            length = struct.unpack_from('=I', data, offset)[0]
            if length < NLMSG_HDR:
                break
            body = offset + NLMSG_HDR + CN_HDR
            if body + EVENT_HDR + 16 <= len(data):
                what = struct.unpack_from('=I', data, body)[0]
                if what == PROC_EVENT_FORK:
                    _, parent_tgid, child_pid, child_tgid = struct.unpack_from('=IIII', data, body + EVENT_HDR)
                    if child_pid == child_tgid:
                        out.append(('fork', child_tgid, parent_tgid))
                elif what == PROC_EVENT_EXEC:
                    pid, tgid = struct.unpack_from('=II', data, body + EVENT_HDR)
                    if pid == tgid:
                        out.append(('exec', tgid, 0))
            offset += (length + 3) & ~3
        return out

    def close(self):
        try:
            self._control(PROC_CN_MCAST_IGNORE)
        except OSError:
            pass
        self.sock.close()


class Poller:
    """Without root: new process IDs in /proc, every interval. Programs that exit sooner are missed."""

    def __init__(self, base, interval):
        self.base, self.interval = base, interval
        self.known = self._pids()

    def _pids(self):
        try:
            with os.scandir(self.base) as listing:
                return {int(e.name) for e in listing if e.name.isdigit()}
        except OSError:
            return set()

    def events(self, timeout):
        time.sleep(min(timeout, self.interval))
        current = self._pids()
        new, self.known = current - self.known, current
        return [('exec', pid, 0) for pid in sorted(new)]

    def close(self):
        pass


class Watcher:
    def __init__(self, emit, *, root='/', allow_path=None, source=None, interval=0.25, clock=time.monotonic):
        self.base = Path(root, 'proc')
        self.judge = Judge(_load_allow(allow_path), listens=Listeners(self.base, clock))
        self.emit, self.clock = emit, clock
        self.parents: OrderedDict = OrderedDict()   # child -> parent, from fork events
        self.cache: OrderedDict = OrderedDict()     # pid -> Proc, for ancestors that exit quickly
        self.last: dict = {}
        self.stats = dict(started=0, vanished=0, lost=0, findings=0)
        if source is None:
            try:
                source, self.mode = ProcEvents(), 'process events'
            except OSError:
                source, self.mode = Poller(self.base, interval), f'polling every {interval:g} s'
        else:
            self.mode = 'given'
        self.source = source

    def _remember(self, table, key, value):
        table[key] = value
        table.move_to_end(key)
        while len(table) > MAX_TRACKED:
            table.popitem(last=False)

    def _parent_of(self, proc):
        # The process that forked it, as the kernel reported; /proc shows init once that parent exits.
        return self.parents.get(proc.pid, proc.ppid)

    def handle(self, kind, pid, parent):
        if kind == 'lost':
            self.stats['lost'] += 1
            return None
        if kind == 'fork':
            self._remember(self.parents, pid, parent)
            # Until it execs, a forked child runs its parent's program: remember it so, in case it exits
            # before anything it starts is examined (a subshell in `sh -c '(id &)'`).
            known, live = self.cache.get(parent), read_proc(self.base, parent)
            if live is not None and (known is None or known.start != live.start):
                # The parent's PID may have been reused since it was last seen: the forking process is the live one.
                known = live
                self._remember(self.cache, parent, live)
            if known is not None:
                self._remember(self.cache, pid, Proc(pid, parent, known.path, known.comm, known.uid, None,
                                                     list(known.argv), known.cwd))
            return None
        self.stats['started'] += 1
        proc = read_proc(self.base, pid)
        if proc is None:
            self.stats['vanished'] += 1
            return None
        self._remember(self.cache, pid, proc)
        chain = _ancestors(self.base, proc, _BoundedCache(self.cache, self._remember), self._parent_of,
                           forked=lambda child: child in self.parents)
        found = self.judge.judge(proc, chain, _now())
        if not found:
            return None
        service = found['evidence']['service']
        # An application is its runtime and what it runs: one Python application's routine commands do not quiet
        # the same command in another.
        key = (service.get('allow_as', service['program']), proc.path, tuple(proc.argv))
        now = self.clock()
        if now - self.last.get(key, -1e18) < COOLDOWN_SECONDS:
            return None
        self.last[key] = now
        if len(self.last) > MAX_TRACKED:
            self.last.clear()
        self.stats['findings'] += 1
        self.emit(found)
        return found

    def run(self, stop, timeout=0.5):
        while not stop.is_set():
            for kind, pid, parent in self.source.events(timeout):
                self.handle(kind, pid, parent)

    def close(self):
        self.source.close()


class _BoundedCache:
    """dict-like view used while walking ancestors, so walking also fills the bounded cache."""

    def __init__(self, table, remember):
        self.table, self.remember = table, remember

    def get(self, key):
        return self.table.get(key)

    def __setitem__(self, key, value):
        self.remember(self.table, key, value)
