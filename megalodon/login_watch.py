"""Successful logins that do not fit: the attacker who already has a valid password or key.

Failed logins are counted by the auth review. The breach is usually the login
that succeeds (ATT&CK T1078): from a network the account never used, with an
SSH key never seen before, at an hour it never logs in, as a service account
that never logs in at all, or followed by sudo from someone who never used it.
`megalodon logins learn` builds a baseline from past logs; `check` reports new
logins that do not fit it.

Input: /var/log/auth.log or /var/log/secure, journal output piped in
(`journalctl -o short-iso`), or /var/log/wtmp when there is no text log.
Read-only.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import struct
import tempfile

from .auth_review import _CLASSIC, _ISO, _Clock, _address, _clean_user, read_lines

SCHEMA = 'megalodon-login-watch-v1'
REPORT_SCHEMA = 'megalodon-login-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/logins.json'
DEFAULT_CURSOR = '~/.local/state/megalodon/logins-cursor.json'
LOGS = ('/var/log/auth.log', '/var/log/secure')
WTMP = '/var/log/wtmp'
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_USERS = 4096
MAX_PER_USER = 512
MIN_LOGINS_FOR_HOURS = 20
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
NO_LOGIN_SHELLS = ('/usr/sbin/nologin', '/sbin/nologin', '/bin/false', '/usr/bin/false')

_ACCEPTED = re.compile(
    r'Accepted (?P<method>[\w/-]+) for (?P<user>\S+) from (?P<ip>[0-9A-Fa-f:.]+) port \d+'
    r'(?: ssh2)?(?:: (?P<keytype>[\w-]+) (?P<fingerprint>SHA256:[A-Za-z0-9+/=]+))?')
_SUDO = re.compile(r'^\s*(?P<user>[^\s:]+) : (?P<rest>.*\bUSER=(?P<target>[^\s;]+) ; .*\bCOMMAND=(?P<command>.*))$')
_SU = re.compile(r'pam_unix\(su(?:-l)?:session\): session opened for user (?P<target>[^\s(]+)(?:\(uid=\d+\))? '
                 r'by (?P<user>[^\s(]*)')
_FAILED_SUDO = ('incorrect password', 'NOT in sudoers', 'command not allowed', 'authentication failure')

RULES = {
    'LOGIN_SERVICE_ACCOUNT': ('CRITICAL', ['T1078.003'],
                              'An account that should never log in (a system account, or one with no login '
                              'shell) logged in.'),
    'LOGIN_NEW_KEY': ('HIGH', ['T1098.004', 'T1078'],
                      'An account logged in with an SSH key it has never used: a key someone added, or a stolen '
                      'one.'),
    'LOGIN_NEW_SOURCE': ('HIGH', ['T1078'], 'An account logged in from a network it has never logged in from.'),
    'LOGIN_ROOT_REMOTE': ('HIGH', ['T1078.003'], 'root logged in over the network, which it never did before.'),
    'LOGIN_NEW_ACCOUNT': ('HIGH', ['T1078'], 'An account that has never logged in did.'),
    'SUDO_FIRST_USE': ('HIGH', ['T1548.003'], 'An account that never used sudo ran a command as another user.'),
    'LOGIN_NEW_METHOD': ('MEDIUM', ['T1078'], 'An account logged in a way it never has, such as by password '
                                              'when it always used a key.'),
    'LOGIN_UNUSUAL_HOUR': ('MEDIUM', ['T1078'], 'An account logged in at an hour it never logs in.'),
    'SUDO_NEW_TARGET': ('MEDIUM', ['T1548.003'], 'An account used sudo to act as a user it never did before.'),
    'SU_NEW': ('MEDIUM', ['T1548'], 'An account switched to another user with su for the first time.'),
}


class LoginError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _cursor_text(moment):
    """The cursor keeps microseconds: a whole-second cursor would leave a later fraction looking new forever."""
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


def _cursor_time(text):
    """Read a cursor, with or without fractional seconds (older cursors have none)."""
    for layout in ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
        try:
            return datetime.strptime(text, layout).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise LoginError(f'login cursor has an unreadable time: {text!r}')


def _network(address):
    parsed = ipaddress.ip_address(address)
    return str(ipaddress.ip_network(f'{parsed}/{24 if parsed.version == 4 else 48}', strict=False))


def _scope(address):
    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback:
        return 'local'
    return 'public' if parsed.is_global else 'private'


# ------------------------------------------------------------------ reading events

def events_from_lines(lines, *, reference=None):
    """Successful logins, sudo and su from syslog or journal text."""
    # Classic syslog stamps carry no zone: they are local time, as in the auth reviewer.
    reference = (reference or _now()).astimezone()
    clock = _Clock(reference, reference.tzinfo)
    out = []
    for raw in lines:
        text = raw.decode('utf-8', 'replace').rstrip('\r\n') if isinstance(raw, bytes) else raw.rstrip('\r\n')
        match = _ISO.match(text)
        if match:
            when = clock.iso(match['stamp'])
        else:
            match = _CLASSIC.match(text)
            when = clock.classic(match['mon'], match['day'], match['time']) if match else None
            if when is not None and when.tzinfo is None:
                when = when.astimezone()
        if match is None or when is None:
            continue
        program, message = match['prog'].rsplit('/', 1)[-1], match['msg']
        if program.startswith('sshd'):
            found = _ACCEPTED.search(message)
            if found and _address(found['ip']):
                out.append(dict(kind='login', when=when, user=_clean_user(found['user']),
                                source=_address(found['ip']), method=found['method'],
                                key=found['fingerprint'], via='ssh'))
        elif program == 'sudo':
            found = _SUDO.match(message)
            if found and not any(word in found['rest'] for word in _FAILED_SUDO):
                out.append(dict(kind='sudo', when=when, user=_clean_user(found['user']),
                                target=_clean_user(found['target']), command=found['command'][:256]))
        elif program in ('su', 'su-l'):
            found = _SU.search(message)
            if found and found['user']:
                out.append(dict(kind='su', when=when, user=_clean_user(found['user']),
                                target=_clean_user(found['target'])))
    return out


UTMP_FORMAT = '<h2xi32s4s32s256shhiii16s20x'


def events_from_wtmp(path=WTMP):
    """Logins recorded in wtmp (any login, without method or key)."""
    size = struct.calcsize(UTMP_FORMAT)
    try:
        data = Path(path).read_bytes()[-size * 200000:]
    except OSError as exc:
        raise LoginError(f'{path} cannot be read: {exc.strerror}') from None
    out = []
    for offset in range(len(data) % size, len(data) - size + 1, size):
        kind, _pid, line, _, user, host, _, _, _, seconds, _, address = struct.unpack_from(UTMP_FORMAT, data, offset)
        if kind != 7 or not seconds:
            continue
        name = user.rstrip(b'\0').decode('utf-8', 'replace')
        host_text = host.rstrip(b'\0').decode('utf-8', 'replace')
        source = _address(host_text)
        if source is None and any(address):
            raw = address[:4] if not any(address[4:]) else address
            try:
                source = str(ipaddress.ip_address(raw))
            except ValueError:
                source = None
        out.append(dict(kind='login', when=datetime.fromtimestamp(seconds, timezone.utc).astimezone(),
                        user=_clean_user(name), source=source, method=None, key=None,
                        via='ssh' if source else line.rstrip(b'\0').decode('utf-8', 'replace')))
    return out


def read_events(logs=None):
    """Events from the given logs ('-' is standard input), else the system auth log, else wtmp."""
    if logs:
        out = []
        for log in logs:
            if os.path.basename(str(log)).startswith(('wtmp', 'btmp')):
                out += events_from_wtmp(log)
            else:
                out += events_from_lines(read_lines(str(log)))
        return sorted(out, key=lambda e: e['when'])
    for log in LOGS:
        if os.path.exists(log):
            return sorted(events_from_lines(read_lines(log)), key=lambda e: e['when'])
    if os.path.exists(WTMP):
        return sorted(events_from_wtmp(WTMP), key=lambda e: e['when'])
    raise LoginError('no auth log or wtmp found; pass --log, or pipe `journalctl -o short-iso` with --log -')


# ------------------------------------------------------------------ the baseline

def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.logins-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path, schema, what):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise LoginError(f'no {what} at {path}') from None
    except OSError as exc:
        raise LoginError(f'{what} {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise LoginError(f'{what} {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise LoginError(f'{what} {path} is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != schema:
        raise LoginError(f'{what} {path} has an unsupported format')
    return value


def _empty():
    return dict(schema=SCHEMA, users={}, sudo={}, su={})


def _add(items, value):
    if value is not None and value not in items and len(items) < MAX_PER_USER:
        items.append(value)
        items.sort()


def record(baseline, event):
    if event['kind'] == 'login':
        users = baseline['users']
        if event['user'] not in users and len(users) >= MAX_USERS:
            return
        entry = users.setdefault(event['user'], dict(networks=[], methods=[], keys=[], hours=[0] * 24, logins=0,
                                                     remote=False))
        if event.get('source') and _scope(event['source']) != 'local':
            _add(entry['networks'], _network(event['source']))
            entry['remote'] = True
        _add(entry['methods'], event.get('method'))
        _add(entry['keys'], event.get('key'))
        entry['hours'][event['when'].hour] += 1
        entry['logins'] += 1
    elif event['kind'] in ('sudo', 'su'):
        _add(baseline[event['kind']].setdefault(event['user'], []), event['target'])


def learn(manifest=DEFAULT_MANIFEST, *, logs=None, cursor=DEFAULT_CURSOR):
    path = Path(manifest).expanduser()
    baseline = _read(path, SCHEMA, 'login baseline') if path.exists() else _empty()
    events = read_events(logs)
    for event in events:
        record(baseline, event)
    baseline['recorded_at'] = _iso(_now())
    _write(path, baseline)
    if events and cursor:
        _write(cursor, dict(schema=SCHEMA + '-cursor', last=_cursor_text(events[-1]['when'])))
    return dict(schema=REPORT_SCHEMA, action='learn', manifest=str(path), events=len(events),
                accounts=len(baseline['users']), sudo_users=len(baseline['sudo']))


def _uid_min(path='/etc/login.defs'):
    """The first UID of ordinary accounts, as the system sets it (1000 when it does not say)."""
    try:
        for line in Path(path).read_text('utf-8', 'replace').splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'UID_MIN' and parts[1].isdigit():
                return int(parts[1])
    except OSError:
        pass
    return 1000


def _account(user):
    try:
        entry = pwd.getpwnam(user)
    except KeyError:
        return None
    return entry


def _finding(rule, event, detail):
    severity, techniques, summary = RULES[rule]
    source = event.get('source')
    if rule == 'LOGIN_NEW_SOURCE' and source and _scope(source) == 'private':
        severity = 'MEDIUM'
    return dict(rule_id=rule, severity=severity, techniques=techniques, user=event['user'],
                src_ip=source, when=_iso(event['when']), detail=detail, summary=summary,
                evidence={k: v for k, v in dict(method=event.get('method'), key=event.get('key'), via=event.get('via'),
                                                target=event.get('target'), command=event.get('command')).items()
                          if v is not None})


def judge(baseline, event):
    """Findings for one event against the baseline (the event is then learned, so it is reported once)."""
    found, user = [], event['user']
    if event['kind'] == 'login':
        source = event.get('source')
        account = _account(user)
        if account is not None and user != 'root' and (account.pw_uid < _uid_min()
                                                      or account.pw_shell in NO_LOGIN_SHELLS):
            found.append(_finding('LOGIN_SERVICE_ACCOUNT', event,
                                  f'{user} (UID {account.pw_uid}, shell {account.pw_shell}) logged in'
                                  + (f' from {source}' if source else '')))
        entry = baseline['users'].get(user)
        remote = bool(source) and _scope(source) != 'local'
        if entry is None:
            if user == 'root' and remote:
                found.append(_finding('LOGIN_ROOT_REMOTE', event, f'root logged in from {source}'))
            elif not found:
                found.append(_finding('LOGIN_NEW_ACCOUNT', event, f'{user} logged in for the first time'
                                      + (f' from {source}' if source else '')))
            return found
        if remote and user == 'root' and not entry.get('remote'):
            found.append(_finding('LOGIN_ROOT_REMOTE', event, f'root logged in from {source}'))
        elif remote and _network(source) not in entry['networks']:
            found.append(_finding('LOGIN_NEW_SOURCE', event, f'{user} logged in from {source}, a network it has '
                                                             'never used'))
        if event.get('key') and event['key'] not in entry['keys']:
            found.append(_finding('LOGIN_NEW_KEY', event, f'{user} logged in with a new SSH key {event["key"]}'))
        elif event.get('method') and entry['methods'] and event['method'] not in entry['methods']:
            found.append(_finding('LOGIN_NEW_METHOD', event, f'{user} logged in by {event["method"]}; it always used '
                                                             f'{", ".join(entry["methods"])}'))
        if entry['logins'] >= MIN_LOGINS_FOR_HOURS and entry['hours'][event['when'].hour] == 0:
            found.append(_finding('LOGIN_UNUSUAL_HOUR', event, f'{user} logged in at {event["when"]:%H}:00, an hour '
                                                               'it never logs in'))
    elif event['kind'] == 'sudo':
        targets = baseline['sudo'].get(user)
        if targets is None:
            found.append(_finding('SUDO_FIRST_USE', event, f'{user} used sudo for the first time, as '
                                                           f'{event["target"]}: {event["command"]}'))
        elif event['target'] not in targets:
            found.append(_finding('SUDO_NEW_TARGET', event, f'{user} used sudo as {event["target"]} for the first '
                                                            'time'))
    elif event['kind'] == 'su':
        if event['target'] not in baseline['su'].get(user, []):
            found.append(_finding('SU_NEW', event, f'{user} switched to {event["target"]} with su for the first time'))
    return found


def check(manifest=DEFAULT_MANIFEST, *, logs=None, cursor=DEFAULT_CURSOR, every=False):
    """Findings for events after the cursor (all with every=True); the cursor then moves to the last event."""
    baseline = _read(manifest, SCHEMA, 'login baseline')
    events = read_events(logs)
    since = None
    if cursor and not every and Path(cursor).expanduser().exists():
        since = _cursor_time(_read(cursor, SCHEMA + '-cursor', 'login cursor')['last'])
    fresh = [e for e in events if since is None or e['when'] > since]
    findings = []
    for event in fresh:
        findings += judge(baseline, event)
        # Judged once: a second login from the same new network in this run is not reported again.
        record(baseline, event)
    if events and cursor:
        _write(cursor, dict(schema=SCHEMA + '-cursor', last=_cursor_text(events[-1]['when'])))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['when']))
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_iso(_now()),
                events=len(fresh), findings=findings,
                note='Logins you recognize can be added with `megalodon logins learn` over the same log.')
