"""Tamper-evident command log: every program started on the machine, in a record an intruder cannot rewrite.

Shell history is the first thing an intruder deletes, and it never covered commands run by scripts, cron,
services or a web shell anyway. `megalodon commands record` writes one line for every program the kernel
starts: when, who (the account, and the login it came from even after sudo or su), on which terminal, in which
folder, which program and its arguments.

Each line is signed with a key that changes after every line: the next key is a one-way hash of the last, and
the last is then discarded. `megalodon commands init` prints the first key once and does not keep it. Whoever
holds that key can re-create every later key and check every line; an intruder who gains root later holds only
the current key, and cannot re-create the earlier ones, so cannot change, remove or insert earlier lines
without `verify` reporting it. Every line also carries its sequence number, and the heartbeat carries the latest
sequence and signature off the machine, so a log cut short or started over is seen from outside too.

Passwords and tokens on command lines are blanked before they are written, unless asked otherwise: the log
must not become a store of secrets.
"""
from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile
import time

SCHEMA = 'megalodon-command-log-v1'
STATE_SCHEMA = 'megalodon-command-log-state-v1'
REPORT_SCHEMA = 'megalodon-command-log-report-v1'
DEFAULT_LOG = '~/.local/state/megalodon/commands.jsonl'
DEFAULT_STATE = '~/.local/state/megalodon/commands-state.json'
EVOLVE = b'megalodon-command-log-evolve-v1'
ROTATE_BYTES = 64 * 1024 * 1024
MAX_ARGV_CHARS = 4096
# Enough for MAX_ARGV_CHARS characters of UTF-8. A command line longer than this ends with [cut], even when
# blanking a secret in it makes it short enough to keep.
MAX_CMDLINE_BYTES = 4 * MAX_ARGV_CHARS
FLUSH_SECONDS = 1.0
FLUSH_LINES = 256
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

RULES = {
    'COMMAND_LOG_FORGED': ('CRITICAL', 'A line of the command log does not match its signature: it was changed, '
                                       'or inserted by someone without the key it was signed with.'),
    'COMMAND_LOG_GAP': ('HIGH', 'Lines are missing from the command log: they were removed.'),
    'COMMAND_LOG_TRUNCATED': ('HIGH', 'The command log ends before the sequence it was last seen at off the '
                                      'machine: its end was cut off.'),
    'COMMAND_LOG_STOPPED_UNCLEANLY': ('MEDIUM', 'The recorder started again without having stopped: it crashed or '
                                                'was killed, and commands in between are not recorded.'),
    'COMMAND_LOG_EVENTS_LOST': ('MEDIUM', 'The kernel dropped process events while the machine was busy: some '
                                          'programs were not recorded.'),
}


class CommandLogError(ValueError):
    pass


def _iso(moment=None):
    return (moment or datetime.now(timezone.utc)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _key_id(seed):
    return hashlib.sha256(b'megalodon-command-log-id' + seed).hexdigest()[:16]


def evolve(key):
    """The next key: a one-way hash of this one."""
    return hashlib.sha256(EVOLVE + key).digest()


def _canonical(entry):
    return json.dumps({k: v for k, v in entry.items() if k != 'mac'}, sort_keys=True, separators=(',', ':')).encode()


def sign(key, entry):
    """An entry's signature covers the whole entry, including `prev`, the signature of the line before it: lines
    cannot be reordered or spliced, and each line can still be checked alone when others were removed."""
    return hmac.new(key, _canonical(entry), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ private files

def _private_read(path, what):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise CommandLogError(f'no {what} at {path}; run megalodon commands init') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise CommandLogError(f'{what} {path} must be a mode-600 file owned by you')
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b''.join(chunks)


def _write_state(path, state):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.commands-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(state, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def read_state(path=DEFAULT_STATE):
    try:
        state = json.loads(_private_read(path, 'command log state'))
    except ValueError:
        raise CommandLogError('the command log state is not valid JSON') from None
    if type(state) is not dict or state.get('schema') != STATE_SCHEMA or type(state.get('next')) is not int:
        raise CommandLogError('the command log state has an unsupported format')
    return state


def head(path=DEFAULT_STATE):
    """The last sequence and signature written, for the heartbeat; None when there is no command log here."""
    try:
        state = read_state(path)
    except CommandLogError:
        return None
    return dict(sequence=state['next'] - 1, mac=state['last_mac'], key_id=state['key_id'])


def init(*, state=DEFAULT_STATE, log=DEFAULT_LOG, replace=False, key_file=None):
    """A new log and its first key. The key is returned once, or written to key_file, and not kept otherwise.

    The key file is created first and exclusively: a log is never set up with a key that was saved nowhere.
    """
    path = Path(state).expanduser()
    if path.exists() and not replace:
        raise CommandLogError(f'{path} exists: the command log is already set up (use --replace to start a new one)')
    seed = secrets.token_bytes(32)
    key_fd = None
    if key_file:
        try:
            key_fd = os.open(Path(key_file).expanduser(), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                             os.O_CLOEXEC, 0o600)
        except FileExistsError:
            raise CommandLogError(f'{key_file} exists; the key is never written over another file') from None
    log_path = Path(log).expanduser()
    if replace and log_path.exists():
        # The old log stays, under a name of its own; its key verifies it still.
        log_path.rename(log_path.with_name(f'{log_path.name}.before-{int(time.time())}'))
    if key_fd is not None:
        try:
            os.write(key_fd, (seed.hex() + '\n').encode())
            os.fsync(key_fd)
        finally:
            os.close(key_fd)
    _write_state(path, dict(schema=STATE_SCHEMA, key_id=_key_id(seed), next=1, key=seed.hex(), last_mac='0' * 64,
                            created_at=_iso(), log=str(log_path)))
    return dict(key=f'written to {Path(key_file).expanduser()}' if key_file else seed.hex(), key_id=_key_id(seed),
                state=str(path), log=str(log_path),
                note='Store this key off this machine and do not keep a copy here: anyone holding it can rewrite '
                     'the log. `megalodon commands verify --key-file FILE` checks the log with it.')


# ------------------------------------------------------------------ recording

class Recorder:
    """Appends signed lines. Lines are written and synced before the state that names the next key."""

    def __init__(self, *, state=DEFAULT_STATE, log=DEFAULT_LOG, clock=None):
        self.state_path, self.log_path = Path(state).expanduser(), Path(log).expanduser()
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        # One recorder at a time, from before the key is read until it stops: two would sign different lines
        # with the same key and number.
        self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = os.open(self.state_path.with_name(self.state_path.name + '.lock'),
                            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock)
            raise CommandLogError('another command recorder is running for this log') from None
        try:
            state = read_state(self.state_path)
        except BaseException:
            self.close()
            raise
        self.key_id = state['key_id']
        self.next, self.key, self.last_mac = state['next'], bytes.fromhex(state['key']), state['last_mac']
        self.pending, self.flushed_at = [], time.monotonic()
        self._catch_up()

    def close(self):
        """Release the recorder lock; the state on disk is whatever was last flushed."""
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.flush()
        self.close()

    def _catch_up(self):
        """Lines written after the state was last saved (a crash between the two) move the key forward."""
        for entry in _tail(self.log_path, self.next):
            if entry.get('seq') != self.next:
                break
            if entry.get('prev') != self.last_mac or \
                    not hmac.compare_digest(str(entry.get('mac')), sign(self.key, entry)):
                break
            self.last_mac, self.key, self.next = entry['mac'], evolve(self.key), self.next + 1

    def add(self, kind, **fields):
        entry = dict(schema=SCHEMA, seq=self.next, at=_iso(self.clock()), kind=kind, key_id=self.key_id,
                     prev=self.last_mac, **fields)
        entry['mac'] = sign(self.key, entry)
        # The key just used is replaced: once this line is written, nothing on this machine can sign it again.
        self.key, self.last_mac, self.next = evolve(self.key), entry['mac'], self.next + 1
        self.pending.append(entry)
        if len(self.pending) >= FLUSH_LINES or time.monotonic() - self.flushed_at >= FLUSH_SECONDS:
            self.flush()
        return entry

    def flush(self):
        self.flushed_at = time.monotonic()
        if not self.pending:
            return
        self.log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.log_path.exists() and self.log_path.stat().st_size > ROTATE_BYTES:
            # Each rotated file keeps its own name, after the first line it holds: none is ever written over.
            first = _first_sequence(self.log_path)
            os.replace(self.log_path, self.log_path.with_name(f'{self.log_path.name}.{first:012d}'))
        fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise CommandLogError(f'command log {self.log_path} must be a mode-600 file owned by you')
            os.write(fd, b''.join(json.dumps(e, sort_keys=True, separators=(',', ':')).encode() + b'\n'
                                  for e in self.pending))
            os.fsync(fd)
        finally:
            os.close(fd)
        self.pending = []
        _write_state(self.state_path, dict(read_state(self.state_path), next=self.next, key=self.key.hex(),
                                           last_mac=self.last_mac))


def _first_sequence(path):
    try:
        with open(path, 'rb') as stream:
            return int(json.loads(stream.readline()).get('seq', 0))
    except (OSError, ValueError, TypeError, AttributeError):
        return int(time.time())          # an unreadable first line still gets a name of its own


def _tail(path, from_sequence):
    """Entries at or after a sequence in the current log, read from its end."""
    try:
        with open(path, 'rb') as stream:
            stream.seek(0, os.SEEK_END)
            size = stream.tell()
            stream.seek(max(0, size - 4 * 1024 * 1024))
            data = stream.read()
    except OSError:
        return []
    out = []
    for line in data.splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get('seq'), int) and entry['seq'] >= from_sequence:
            out.append(entry)
    return sorted(out, key=lambda e: e['seq'])


def _redact(argv):
    """Blank the values of passwords and tokens on a command line, as the exposed secrets scan finds them."""
    from .exposed_secrets import command_line_secrets
    out = list(argv)
    hidden = 0
    for kind, _shown, _fingerprint, index in command_line_secrets(argv):
        arg = out[index]
        option, sep, value = arg.partition('=')
        if kind.startswith('value of ') and not sep and index + 1 < len(out):
            out[index + 1], hidden = f'[hidden: {len(out[index + 1])} characters]', hidden + 1
        elif sep and kind.startswith('value of '):
            out[index], hidden = f'{option}=[hidden: {len(value)} characters]', hidden + 1
        elif kind == 'password given with -p':
            out[index], hidden = f'-p[hidden: {len(arg) - 2} characters]', hidden + 1
        elif kind == 'password given with sshpass -p' and index + 1 < len(out):
            out[index + 1], hidden = f'[hidden: {len(out[index + 1])} characters]', hidden + 1
        elif kind == 'password given with --user' and index + 1 < len(out) and ':' in out[index + 1]:
            user = out[index + 1].split(':', 1)[0]
            out[index + 1], hidden = f'{user}:[hidden]', hidden + 1
        else:
            out[index], hidden = f'[hidden {kind}: {len(arg)} characters]', hidden + 1
    return out, hidden


def describe(base, pid, *, redact=True):
    """What is recorded about one started program, or None if it is already gone."""
    from .process_ancestry import read_proc
    proc = read_proc(base, pid)
    if proc is None:
        return None
    folder = base / str(pid)

    def text(name):
        try:
            return (folder / name).read_text('utf-8', 'replace').strip()
        except OSError:
            return None

    def link(name):
        try:
            return os.readlink(folder / name)
        except OSError:
            return None
    login = text('loginuid')
    session = text('sessionid')
    stat_text = text('stat') or ''
    try:
        tty = int(stat_text[stat_text.rindex(')') + 2:].split()[4])
    except (ValueError, IndexError):
        tty = 0
    # Unreadable here means unreadable to read_proc too: nothing more is known.
    full, whole = _command_line(base, pid) or (proc.argv, True)
    argv, hidden = _redact(full) if redact else (full, 0)
    kept = _kept(argv)
    if not whole and kept[-1:] != ['[cut]']:
        kept.append('[cut]')
    entry = dict(pid=pid, ppid=proc.ppid, uid=proc.uid, program=proc.path, argv=kept, cwd=link('cwd'),
                 login_uid=int(login) if login and login.lstrip('-').isdigit() and int(login) != 4294967295
                 else None,
                 session=int(session) if session and session.isdigit() and int(session) != 4294967295 else None,
                 tty=tty or None, start=proc.start)
    if hidden:
        entry['hidden'] = hidden
    return entry


def _command_line_bytes(base, pid):
    """/proc/PID/cmdline as it is, read up to MAX_CMDLINE_BYTES: further than process_ancestry.read_proc reads it,
    as far as a line keeps. None when it cannot be read."""
    try:
        with open(base / str(pid) / 'cmdline', 'rb') as handle:
            return handle.read(MAX_CMDLINE_BYTES + 1)
    except OSError:
        return None


def _arguments(raw):
    """(arguments, whether the whole command line was read) from what _command_line_bytes read."""
    return ([part.decode('utf-8', 'replace') for part in raw[:MAX_CMDLINE_BYTES].split(b'\0') if part],
            len(raw) <= MAX_CMDLINE_BYTES)


def _command_line(base, pid):
    """(arguments, whether all were read) from /proc/PID/cmdline; None when it cannot be read."""
    raw = _command_line_bytes(base, pid)
    return None if raw is None else _arguments(raw)


def _kept(argv):
    joined, kept = 0, []
    for arg in argv:
        joined += len(arg) + 1
        if joined > MAX_ARGV_CHARS:
            kept.append('[cut]')
            break
        kept.append(arg)
    return kept


def describe_traced(base, record, *, redact=True):
    """What is recorded about one program the exec trace saw start: the kernel's own record, made as the exec
    completed, so a program gone at once is recorded in full. /proc adds only what the kernel's record lacks
    (the terminal, and the rest of a command line longer than the trace reads), and only while it shows the
    same process running the same program with the same start of its command line."""
    from .process_ancestry import read_proc
    argv, cut = record['argv'], record.get('argv_cut', False)
    tty, exited = None, True
    proc = read_proc(base, record['pid'])
    if proc is not None and proc.start == record['start'] and proc.path == record['path']:
        exited = False
        read = _command_line_bytes(base, record['pid']) if cut else None
        # The same command line, read as far as a line keeps. Compared as bytes: the trace's may end inside a
        # character, which decodes differently from the whole one.
        traced = record.get('argv_bytes')
        if read is not None and traced is not None and read.startswith(traced):
            argv, whole = _arguments(read)
            cut = not whole
        try:
            text = (base / str(record['pid']) / 'stat').read_text('utf-8', 'replace')
            tty = int(text[text.rindex(')') + 2:].split()[4]) or None
        except (OSError, ValueError, IndexError):
            tty = None
    argv, hidden = _redact(argv) if redact else (argv, 0)
    kept = _kept(argv)
    if cut and kept[-1:] != ['[cut]']:
        kept.append('[cut]')
    entry = dict(pid=record['pid'], ppid=record['parent'], uid=record['uid'], program=record['path'], argv=kept,
                 cwd=record['cwd'], login_uid=record.get('login_uid'), session=record.get('session'), tty=tty,
                 start=record['start'])
    if hidden:
        entry['hidden'] = hidden
    if exited:
        entry['exited'] = True                   # Gone, or running something else, by the time it was read.
    return entry


def record(stop, *, state=DEFAULT_STATE, log=DEFAULT_LOG, root='/', source=None, redact=True, clock=None,
           trace=None):
    """Record every started program until `stop` is set. Returns how many were recorded. With ``trace`` (an
    exec_trace.ExecTrace), each program is recorded from the kernel's own record of its exec."""
    from .process_ancestry import Poller, ProcEvents
    base = Path(root, 'proc')
    recorder = Recorder(state=state, log=log, clock=clock)
    if trace is not None:
        return _record_traced(stop, recorder, trace, base, redact)
    if source is None:
        try:
            source, mode = ProcEvents(), 'process events'
        except OSError:
            source, mode = Poller(base, 0.25), 'polling every 0.25 s'
    else:
        mode = 'given'
    recorder.add('start', mode=mode, recorder_pid=os.getpid())
    recorder.flush()
    count = 0
    try:
        while not stop.is_set():
            for kind, pid, _parent in source.events(0.5):
                if kind == 'lost':
                    recorder.add('lost')
                elif kind == 'exec':
                    entry = describe(base, pid, redact=redact)
                    if entry is None:
                        recorder.add('exec', pid=pid, gone=True)
                    else:
                        recorder.add('exec', **entry)
                    count += 1
            if recorder.pending and time.monotonic() - recorder.flushed_at >= FLUSH_SECONDS:
                recorder.flush()
    finally:
        try:
            recorder.add('stop', recorded=count)
            recorder.flush()
        finally:
            recorder.close()
            source.close()
    return count


def _record_traced(stop, recorder, trace, base, redact):
    recorder.add('start', mode='exec trace', recorder_pid=os.getpid())
    recorder.flush()
    count, dropped = 0, 0
    try:
        while not stop.is_set():
            trace.wait(0.5)
            for item in trace.drain():
                if item['kind'] == 'exec':
                    recorder.add('exec', **describe_traced(base, item, redact=redact))
                    count += 1
            # Execs and forks the ring buffer had no room for: some programs were not recorded.
            now = trace.dropped()
            if now > dropped:
                recorder.add('lost', dropped=now - dropped)
                dropped = now
            if recorder.pending and time.monotonic() - recorder.flushed_at >= FLUSH_SECONDS:
                recorder.flush()
    finally:
        try:
            recorder.add('stop', recorded=count)
            recorder.flush()
        finally:
            recorder.close()
            trace.close()
    return count


# ------------------------------------------------------------------ reading and verifying

def log_files(log=DEFAULT_LOG):
    """The rotated files, oldest first, then the current one."""
    path = Path(log).expanduser()
    rotated = sorted(p for p in path.parent.glob(path.name + '.*')
                     if p.name[len(path.name) + 1:].isdigit())
    return [*rotated, path] if path.exists() else rotated


def entries(log=DEFAULT_LOG):
    """Every entry of the log and its rotated files, in file order. A line that is not a record is kept as one
    marked unreadable, with where it was, so that verify can report it."""
    out = []
    for candidate in log_files(log):
        for number, line in enumerate(_private_read(candidate, 'command log').splitlines(), 1):
            try:
                entry = json.loads(line)
            except ValueError:
                entry = None
            if not isinstance(entry, dict) or type(entry.get('seq')) is not int:
                out.append(dict(seq=None, unreadable=True, file=candidate.name, line_number=number))
                continue
            out.append(entry)
    return out


def _finding(rule, subject, detail, **extra):
    severity, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, subject=subject, detail=detail, summary=summary,
                techniques=['T1070.003', 'T1070'], **extra)


def verify(key_hex, *, log=DEFAULT_LOG, expect_sequence=None, from_sequence=1):
    """Check every line against the key from init: signatures, order, gaps, restarts and the expected end."""
    try:
        seed = bytes.fromhex(key_hex.strip())
    except ValueError:
        raise CommandLogError('the key must be the 64 hexadecimal digits that `commands init` printed') from None
    if len(seed) != 32:
        raise CommandLogError('the key must be the 64 hexadecimal digits that `commands init` printed')
    every = entries(log)
    lines = [e for e in every if isinstance(e.get('seq'), int) and e['seq'] >= from_sequence]
    broken = [e for e in every if e.get('unreadable')]
    # A line that is not a signed record is not something to skip: a log rewritten as anything else must fail.
    findings = [_finding('COMMAND_LOG_FORGED', f"file:{e['file']}:{e['line_number']}",
                         f"line {e['line_number']} of {e['file']} is not a signed record") for e in broken[:100]]
    unreadable = len(broken)
    if lines and lines[0].get('key_id') not in (None, _key_id(seed)):
        raise CommandLogError('this key is not the one this log was started with')
    # Lines before from_sequence were let go on purpose; that boundary comes from whoever verifies, off the
    # machine, never from the log itself, where an intruder could write one.
    key, position, previous, expected, running = seed, 1, '0' * 64, max(1, from_sequence), False
    if from_sequence > 1 and lines and lines[0]['seq'] == from_sequence:
        previous = lines[0].get('prev')
    verified = 0
    for entry in lines:
        sequence = entry['seq']
        if sequence < expected:
            findings.append(_finding('COMMAND_LOG_FORGED', f'line:{sequence}',
                                     f'line {sequence} appears again after line {expected - 1}'))
            continue
        if sequence > expected:
            findings.append(_finding('COMMAND_LOG_GAP', f'lines:{expected}-{sequence - 1}',
                                     f'lines {expected} to {sequence - 1} are missing',
                                     first=expected, last=sequence - 1))
        while position < sequence:
            key, position = evolve(key), position + 1
        # Each line is checked with its own key; next to the line before it, it must also name that line.
        signed = hmac.compare_digest(str(entry.get('mac')), sign(key, entry))
        linked = sequence > expected or entry.get('prev') == previous
        if not signed:
            findings.append(_finding('COMMAND_LOG_FORGED', f'line:{sequence}',
                                     f'line {sequence} ({entry.get("at")}) does not match its signature'))
        elif not linked:
            findings.append(_finding('COMMAND_LOG_FORGED', f'line:{sequence}',
                                     f'line {sequence} does not follow line {sequence - 1}: lines were spliced'))
        else:
            verified += 1
        kind = entry.get('kind')
        if kind == 'start':
            if running:
                findings.append(_finding('COMMAND_LOG_STOPPED_UNCLEANLY', f'line:{sequence}',
                                         f'the recorder started again at line {sequence} ({entry.get("at")}) '
                                         f'without stopping first'))
            running = True
        elif kind == 'stop':
            running = False
        elif kind == 'lost':
            dropped = entry.get('dropped')
            findings.append(_finding('COMMAND_LOG_EVENTS_LOST', f'line:{sequence}',
                                     f'the kernel dropped process events before {entry.get("at")}'
                                     + (f' ({dropped} execs and forks)' if isinstance(dropped, int) else '')))
        previous, expected = entry.get('mac'), sequence + 1
        key, position = evolve(key), position + 1
    last = expected - 1
    if expect_sequence is not None and last < expect_sequence:
        findings.append(_finding('COMMAND_LOG_TRUNCATED', f'lines:{last + 1}-{expect_sequence}',
                                 f'the log ends at line {last}, but line {expect_sequence} was written',
                                 first=last + 1, last=expect_sequence))
    findings.sort(key=lambda f: RANK.index(f['severity']))
    return dict(schema=REPORT_SCHEMA, action='verify', lines=len(lines), verified=verified, unreadable=unreadable,
                first=lines[0]['seq'] if lines else None, last=last if lines else None,
                first_at=lines[0].get('at') if lines else None, last_at=lines[-1].get('at') if lines else None,
                findings=findings,
                note='Lines before an intruder gained root cannot be changed without this report showing it. Lines '
                     'after that can be, so compare the end with the sequence the heartbeat last carried off the '
                     'machine (--expect-sequence).')


def show(*, log=DEFAULT_LOG, since=None, uid=None, contains=None, limit=500):
    """Recorded programs, newest last, filtered by time, account and text. Not a check: use verify for that."""
    rows = []
    for entry in entries(log):
        if entry.get('kind') != 'exec' or entry.get('gone'):
            continue
        if since and str(entry.get('at', '')) < since:
            continue
        if uid is not None and uid not in (entry.get('uid'), entry.get('login_uid')):
            continue
        command = ' '.join(entry.get('argv') or [entry.get('program') or ''])
        if contains and contains not in command and contains not in str(entry.get('program')):
            continue
        rows.append(dict(seq=entry.get('seq'), at=entry.get('at'), uid=entry.get('uid'),
                         login_uid=entry.get('login_uid'), tty=entry.get('tty'), cwd=entry.get('cwd'),
                         program=entry.get('program'), command=command, pid=entry.get('pid'), ppid=entry.get('ppid')))
    return rows[-limit:]
