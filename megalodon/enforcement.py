"""Enforcement: carry out the response engine's decisions, only those you allowed, and keep a way back.

The response engine decides in shadow mode: it records what it would do and
does nothing. `megalodon enforce` is the separate step that acts. It carries
out a decision only when all of these hold:

* the enforcement policy (`enforce.toml`, owner-only) is enabled and lists the
  action and the playbook;
* the decision was made under the response policy whose SHA-256 the
  enforcement policy pins, so an edited response policy acts only once you
  pin it again;
* the decision is recent (10 minutes by default) and was `would_apply`;
* the response engine's guards still pass now, and the enforcement rate limit
  allows it.

Each action is carried out once, written to an owner-only journal with what
it takes to undo it, and can be undone with `megalodon enforce undo ID`:

* suspend_process: SIGSTOP to the one process named by PID and start time,
  checked through a pidfd, so a reused PID is never signalled. Undo: SIGCONT.
  With the playbook's suspend_minutes, the next run after that time resumes
  it by itself, with the same checks, even while enforcement is off.
* block_address: a time-limited element in MEGALODON's own nftables table,
  which expires by itself. Undo: the element is deleted.
* quarantine_file: the file is moved into the quarantine folder with no
  permissions, after its hash, owner and mode are recorded. Undo: restored.
* lock_account: the password is locked and the account expired, which stops
  key logins too. Undo: unlocked, with the previous expiry put back.
* disable_persistence: a service, job or startup entry the persistence
  baseline did not have is moved into the quarantine folder (a symlink, such
  as a systemd enablement link, is removed and its target recorded). A
  systemd timer, socket or path unit is also stopped. Entries that existed
  before are never moved: undoing an edit is not something one move can do.
  Undo: put back, and started again if it was running.
* collect_evidence: an evidence bundle, and the memory of the processes the
  finding names. notify: a summary to the alert destinations.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tomllib

from . import response_engine as engine

SCHEMA = 'megalodon-enforcement-v1'
DEFAULT_POLICY = '~/.config/megalodon/enforce.toml'
DEFAULT_JOURNAL = '~/.local/state/megalodon/enforced.jsonl'
DEFAULT_STATE = '~/.local/state/megalodon/enforce-state.json'
DEFAULT_QUARANTINE = '~/.local/share/megalodon/quarantine'
SUPPORTED = ('collect_evidence', 'notify', 'suspend_process', 'block_address', 'quarantine_file', 'lock_account',
             'disable_persistence')
# Units that fire something on their own: disabling them also stops them, or they fire until the next boot.
ACTIVATING_UNITS = ('.timer', '.socket', '.path')
# The system manager's unit folders. /etc/systemd/user holds units for every user's own manager.
SYSTEM_UNIT_FOLDERS = ('/etc/systemd/system/', '/usr/local/lib/systemd/system/')
MAX_COPY = 512 * 1024 * 1024
MAX_APPLIED_KEYS = 50_000

POLICY_TEXT = '''# MEGALODON enforcement. Off until you turn it on.
# Each response action listed here is carried out when the response engine decides it (`would_apply`),
# under the response policy pinned below, for the playbooks listed below. Review `megalodon respond report`
# first; every action can be undone with `megalodon enforce undo ID`.
[enforce]
enabled = false
# The SHA-256 of the response policy you reviewed. Edit that policy and decisions stop being carried out
# until you pin it again with `megalodon enforce init --replace`.
response_policy_sha256 = "{digest}"
# Any of: {supported}
actions = []
# Playbook names from the response policy, such as "dropped-tool-phoning-home".
playbooks = []
max_age_minutes = 10
max_actions_per_hour = 5
quarantine_folder = "{quarantine}"
'''


class EnforcementError(ValueError):
    pass


NOT_ADDED = ('only an entry the persistence baseline did not have is disabled: one that existed before and was '
             'changed has to be put back by hand, from a backup or configuration management')


def _now():
    return datetime.now(timezone.utc)


def _iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _parse(text):
    return datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ the enforcement policy

def init(path=DEFAULT_POLICY, *, response_policy=engine.DEFAULT_POLICY, replace=False):
    """Write an enforcement policy that is off, pinned to the current response policy."""
    target = Path(path).expanduser()
    digest = engine.load_policy(response_policy).digest
    if target.exists():
        if not replace:
            raise EnforcementError(f'{target} exists; pass --replace to pin the current response policy')
        text = engine._private_file(target, 'enforcement policy').decode('utf-8')
        text = re.sub(r'(?m)^response_policy_sha256 = "[0-9a-f]*"$', f'response_policy_sha256 = "{digest}"', text)
    else:
        text = POLICY_TEXT.format(digest=digest, supported=', '.join(SUPPORTED), quarantine=DEFAULT_QUARANTINE)
    engine._atomic_write(target, text.encode('utf-8'))
    return dict(action='init', policy=str(target), response_policy_sha256=digest,
                note='Enforcement stays off until you set enabled = true and list actions and playbooks.')


def load_policy(path=DEFAULT_POLICY):
    target = Path(path).expanduser()
    data = engine._private_file(target, 'enforcement policy')
    try:
        document = tomllib.loads(data.decode('utf-8'))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise EnforcementError(f'{target} is not valid TOML: {exc}') from None
    table = document.get('enforce')
    if set(document) - {'enforce'} or not isinstance(table, dict):
        raise EnforcementError('the enforcement policy must contain only an [enforce] table')
    known = {'enabled', 'response_policy_sha256', 'actions', 'playbooks', 'max_age_minutes', 'max_actions_per_hour',
             'quarantine_folder'}
    if set(table) - known:
        raise EnforcementError('enforce has unsupported settings: ' + ', '.join(sorted(set(table) - known)))
    actions, playbooks = table.get('actions', []), table.get('playbooks', [])
    if not isinstance(actions, list) or any(a not in SUPPORTED for a in actions):
        raise EnforcementError(f'actions may list only: {", ".join(SUPPORTED)}')
    if not isinstance(playbooks, list) or any(not isinstance(p, str) for p in playbooks):
        raise EnforcementError('playbooks must be a list of playbook names')
    digest = table.get('response_policy_sha256', '')
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise EnforcementError('response_policy_sha256 must be the SHA-256 that `megalodon enforce init` pinned')
    enabled = table.get('enabled', False)
    if not isinstance(enabled, bool):
        raise EnforcementError('enabled must be true or false')
    folder = table.get('quarantine_folder', DEFAULT_QUARANTINE)
    if not isinstance(folder, str) or not folder:
        raise EnforcementError('quarantine_folder must be a folder')
    return dict(enabled=enabled, digest=digest, actions=frozenset(actions), playbooks=frozenset(playbooks),
                max_age=timedelta(minutes=engine._integer(table, 'max_age_minutes', 10, 1, 1440)),
                max_per_hour=engine._integer(table, 'max_actions_per_hour', 5, 1, 100),
                quarantine=Path(folder).expanduser(), sha256=hashlib.sha256(data).hexdigest())


# ------------------------------------------------------------------ carrying out

def _start(pid, root='/'):
    try:
        text = Path(root, 'proc', str(pid), 'stat').read_text('utf-8', 'replace')
        return int(text[text.rindex(')') + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return None


class Executor:
    """What each action does to the machine, and how it is undone. Tests replace `run` (commands) only."""

    def __init__(self, *, root='/', run=None, quarantine=None, home=None):
        self.root, self.quarantine = root, Path(quarantine or DEFAULT_QUARANTINE).expanduser()
        # `~/` in a persistence location is the home of the account that ran the persistence check: the
        # scheduler runs that check and this step as the same account.
        self.home = str(home or Path.home())
        self.run = run or (lambda argv, data=None: subprocess.run(argv, input=data, capture_output=True, text=True,
                                                                  timeout=30, check=False))

    def _command(self, argv, data=None):
        result = self.run(argv, data)
        if result.returncode != 0:
            raise EnforcementError(f'{argv[0]} failed: {(result.stderr or result.stdout or "").strip()[:300]}')

    # --- processes
    def _signal(self, target, number):
        match = engine.PROCESS_ID.fullmatch(target or '')
        if not match:
            raise EnforcementError('only one exact process (PID and start time) is ever signalled')
        pid, start, program = int(match.group(1)), int(match.group(2)), match.group(3)
        try:
            handle = os.pidfd_open(pid)
        except ProcessLookupError:
            raise EnforcementError(f'process {pid} has exited') from None
        try:
            # The pidfd holds this process; its start time, read now, proves it is the one decided on.
            if _start(pid, self.root) != start:
                raise EnforcementError(f'process {pid} is no longer the one decided on (start time differs)')
            try:
                running = os.readlink(Path(self.root, 'proc', str(pid), 'exe')).removesuffix(' (deleted)')
            except OSError:
                running = None
            if running not in (program, None):
                raise EnforcementError(f'process {pid} runs {running}, not {program}')
            signal.pidfd_send_signal(handle, number)
        finally:
            os.close(handle)
        return dict(pid=pid, start=start, program=program)

    def suspend_process(self, target, decision):
        return self._signal(target, signal.SIGSTOP)

    def undo_suspend_process(self, record):
        self._signal(record['target'], signal.SIGCONT)

    # --- addresses
    def block_address(self, target, decision):
        from .firewall import NFTABLES_TABLE, NftablesFirewall
        minutes = next((a.get('minutes') for a in decision['actions'] if a.get('target') == target), 60) or 60
        plan = NftablesFirewall(timeout_seconds=int(minutes) * 60).plan_block(target, decision['playbook'])
        # MEGALODON's own table, created once: loading it again would add its rules again.
        if self.run(['nft', 'list', 'table', 'inet', 'megalodon']).returncode != 0:
            self._command(['nft', '-f', '-'], NFTABLES_TABLE)
        self._command(list(plan.command))
        return dict(set=plan.command[5], until=_iso(plan.expires_at))

    def undo_block_address(self, record):
        self._command(['nft', 'delete', 'element', 'inet', 'megalodon', record['undo']['set'],
                       '{', record['target'], '}'])

    # --- files
    @staticmethod
    def _folder(path):
        """The folder holding `path`, opened one name at a time from / without following a symlink, and the name.

        The guards check the path as written; a folder on the way swapped for a symlink (uploads/x -> /etc) would
        otherwise lead somewhere they never checked. Everything after this works relative to the folder opened.
        """
        if not path.startswith('/') or path.startswith('//') or os.path.normpath(path) != path or path == '/':
            raise EnforcementError(f'{path} is not a plain absolute path')
        names = path.split('/')[1:]
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for name in names[:-1]:
                inner = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = inner
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                raise EnforcementError(f'a folder on the way to {path} is a symlink or not a folder') from None
            raise
        return fd, names[-1]

    def quarantine_file(self, target, decision):
        return self._move_aside(target)

    def _move_aside(self, target, *, links=False):
        """Move a file into the quarantine folder, or with `links`, remove a symlink and record where it led."""
        parent, name = self._folder(target)
        try:
            if links:
                try:
                    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    raise EnforcementError(f'{target} is no longer there') from None
                if stat.S_ISLNK(info.st_mode):
                    pointed = os.readlink(name, dir_fd=parent)
                    os.unlink(name, dir_fd=parent)
                    return dict(kind='link', link_target=pointed, uid=info.st_uid, gid=info.st_gid)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_COPY:
                    raise EnforcementError('only a regular file up to 512 MiB is quarantined')
                folder = self.quarantine / secrets.token_hex(8)
                folder.mkdir(mode=0o700, parents=True)
                kept = folder / 'file'
                digest = hashlib.sha256()
                out = os.open(kept, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                try:
                    for chunk in iter(lambda: os.read(fd, 1 << 20), b''):
                        os.write(out, chunk)
                        digest.update(chunk)
                    os.fsync(out)
                finally:
                    os.close(out)
            finally:
                os.close(fd)
            now = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (now.st_dev, now.st_ino) != (info.st_dev, info.st_ino):
                shutil.rmtree(folder)
                raise EnforcementError(f'{target} was replaced while it was being quarantined')
            os.unlink(name, dir_fd=parent)
        finally:
            os.close(parent)
        os.chmod(kept, 0)
        return dict(kind='file', kept=str(kept), sha256=digest.hexdigest(), mode=stat.S_IMODE(info.st_mode),
                    uid=info.st_uid, gid=info.st_gid)

    def undo_quarantine_file(self, record):
        self._put_back(record['target'], record['undo'])

    @staticmethod
    def _restored(parent, name, info, undo):
        """Whether what is at the path is exactly what this undo puts there: put back by an earlier undo."""
        if undo.get('kind') == 'link':
            return stat.S_ISLNK(info.st_mode) and os.readlink(name, dir_fd=parent) == undo.get('link_target')
        if not stat.S_ISREG(info.st_mode) or not undo.get('sha256'):
            return False
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            digest = hashlib.sha256()
            for chunk in iter(lambda: os.read(fd, 1 << 20), b''):
                digest.update(chunk)
        finally:
            os.close(fd)
        return digest.hexdigest() == undo['sha256']

    def _put_back(self, target, undo, *, resume=False):
        """Put a moved entry back. With `resume`, an entry already put back by an undo that stopped before its
        last step counts as put back, so that undo can be run again to finish."""
        parent, name = self._folder(target)
        try:
            try:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if resume and self._restored(parent, name, info, undo):
                    return
                kept = f'; the quarantined copy is left at {undo["kept"]}' if undo.get('kept') else ''
                raise EnforcementError(f'{target} exists again{kept}')
            except FileNotFoundError:
                pass
            if undo.get('kind') == 'link':
                os.symlink(undo['link_target'], name, dir_fd=parent)
                if os.geteuid() == 0:
                    os.chown(name, undo['uid'], undo['gid'], dir_fd=parent, follow_symlinks=False)
                return
            os.chmod(undo['kept'], 0o600)
            with open(undo['kept'], 'rb') as source:
                data = source.read()
            if hashlib.sha256(data).hexdigest() != undo['sha256']:
                os.chmod(undo['kept'], 0)
                raise EnforcementError('the quarantined copy no longer matches its recorded SHA-256')
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=parent)
            try:
                os.write(fd, data)
                os.fchmod(fd, undo['mode'])
                if os.geteuid() == 0:
                    os.fchown(fd, undo['uid'], undo['gid'])
            finally:
                os.close(fd)
        finally:
            os.close(parent)
        shutil.rmtree(Path(undo['kept']).parent)

    # --- persistence
    def _entry(self, target):
        """(category, location, the path on this machine) for a persistence target the watch covers."""
        from . import persistence_watch
        category, _, location = (target or '').partition(':')
        if why := persistence_watch.why_not_disabled(category, location):
            raise EnforcementError(why)
        if location.startswith('~/'):
            return category, location, os.path.join(self.home, location[2:])
        return category, location, (location if self.root == '/' else os.path.join(self.root, location[1:]))

    def disable_persistence(self, target, decision):
        if (decision.get('signal') or {}).get('rule_id') != 'PERSISTENCE_ADDED':
            raise EnforcementError(NOT_ADDED)
        category, location, path = self._entry(target)
        # Only units in the system manager's folders are the system manager's: /etc/systemd/user and the
        # ~/.config ones belong to each user's manager, which `systemctl` without --user never reaches.
        system_unit = category == 'systemd' and location.startswith(SYSTEM_UNIT_FOLDERS)
        moved = self._move_aside(path, links=True)
        unit = None
        try:
            if system_unit:
                # systemd forgets the unit only when told. A timer, socket or path unit is also stopped, whether
                # its own file or the link that enabled it was the new entry: either way it would go on firing
                # until the next boot. A service is left running: pause it with suspend_process, or stop it once
                # its memory is captured.
                self._command(['systemctl', 'daemon-reload'])
                name = os.path.basename(path)
                if name.endswith(ACTIVATING_UNITS):
                    active = self.run(['systemctl', 'is-active', '--quiet', name]).returncode == 0
                    if active:
                        self._command(['systemctl', 'stop', name])
                    unit = dict(name=name, was_active=active)
        except (EnforcementError, OSError, subprocess.SubprocessError) as exc:
            # All or nothing: an entry moved aside with no record of it could never be put back by undo.
            try:
                self._put_back(path, moved)
                if system_unit:
                    self.run(['systemctl', 'daemon-reload'])
            except (EnforcementError, OSError, subprocess.SubprocessError) as again:
                kept = moved.get('kept') or f"a link to {moved.get('link_target')}"
                raise EnforcementError(f'{exc}; putting {path} back also failed ({again}): it is {kept}') from None
            raise EnforcementError(f'{exc}; {path} was put back as it was') from None
        return dict(moved, path=path, category=category, unit=unit, system_unit=system_unit)

    def undo_disable_persistence(self, record):
        undo = record['undo']
        # If systemd fails after the entry is back, the undo is not recorded; running it again finishes it.
        self._put_back(undo['path'], undo, resume=True)
        if undo.get('system_unit'):
            self._command(['systemctl', 'daemon-reload'])
            if (undo.get('unit') or {}).get('was_active'):
                self._command(['systemctl', 'start', undo['unit']['name']])

    # --- accounts
    def _shadow(self, user):
        """(whether the password is already locked, the expiry day) from the shadow file."""
        try:
            for line in Path(self.root, 'etc/shadow').read_text().splitlines():
                fields = line.split(':')
                if fields[0] == user and len(fields) > 7:
                    return fields[1].startswith('!'), fields[7]
        except OSError:
            pass
        return False, ''

    def lock_account(self, target, decision):
        try:
            if pwd.getpwnam(target).pw_uid == 0:
                raise EnforcementError('an account with UID 0 is never locked')
        except KeyError:
            raise EnforcementError(f'no account named {target}') from None
        locked, previous = self._shadow(target)
        # A locked password alone still lets SSH keys in; an expired account does not.
        self._command(['usermod', '--lock', '--expiredate', '1', target])
        return dict(previous_expiry=previous, password_was_locked=locked)

    def undo_lock_account(self, record):
        expiry = record['undo'].get('previous_expiry') or ''
        # A password that was locked before stays locked: undo puts back what was there, nothing more.
        unlock = [] if record['undo'].get('password_was_locked') else ['--unlock']
        self._command(['usermod', *unlock, '--expiredate', expiry, record['target']])

    # --- evidence and notices
    def collect_evidence(self, target, decision):
        from . import evidence, memory_capture
        saved = dict(bundle=evidence.collect(root=self.root)['bundle'], memory=[])
        for process in decision['signal'].get('entities', {}).get('process_id', [])[:4]:
            match = engine.PROCESS_ID.fullmatch(process)
            if match:
                try:
                    saved['memory'].append(memory_capture.capture(int(match.group(1)), start=int(match.group(2)),
                                                                  root=self.root)['bundle'])
                except (memory_capture.MemoryCaptureError, OSError):
                    continue
        return saved

    def notify(self, target, decision, *, settings=None):
        from .alerts import HostNotice, dispatcher_for
        from .config import load_settings
        dispatcher = dispatcher_for((settings or load_settings(
            Path.home() / '.config/megalodon/settings.toml')).alerts)
        if dispatcher is None:
            raise EnforcementError('no alert destinations are configured')
        signal_ = decision['signal']
        done = ', '.join(f"{a['action']} {a.get('target') or ''}".strip() for a in decision['actions']
                         if a['status'] == 'would_apply')
        dispatcher.submit([HostNotice(signal_['rule_id'], signal_['severity'], _now(),
                                      f"enforced by {decision['playbook']}: {done}", (), signal_['summary'])],
                          any_severity=True)
        return {}


# ------------------------------------------------------------------ the journal and the run

def _journal(path, records):
    target = Path(path).expanduser()
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise EnforcementError(f'{target} must be a mode-600 file owned by you')
        for record in records:
            os.write(fd, (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def entries(path=DEFAULT_JOURNAL):
    target = Path(path).expanduser()
    if not target.exists():
        return []
    out = []
    for line in engine._private_file(target, 'enforcement journal', 64 * 1024 * 1024).decode().splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _state(path):
    target = Path(path).expanduser()
    if not target.exists():
        return dict(offset=0, inode=None, applied=[])
    try:
        return json.loads(engine._private_file(target, 'enforcement state'))
    except ValueError:
        raise EnforcementError(f'{target} is not valid JSON') from None


def _decisions(ledger, state):
    """Decisions appended to the ledger since the last run."""
    target = Path(ledger).expanduser()
    if not target.exists():
        return []
    info = target.stat()
    offset = state.get('offset', 0) if state.get('inode') == info.st_ino and state.get('offset', 0) <= info.st_size \
        else 0
    with open(target, 'rb') as stream:
        stream.seek(offset)
        data = stream.read(16 * 1024 * 1024)
    complete = data[:data.rfind(b'\n') + 1]
    state.update(inode=info.st_ino, offset=offset + len(complete))
    out = []
    for line in complete.splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


class _Lock:
    """One run or undo at a time: held from reading the state until the journal and state are written."""

    def __init__(self, journal):
        self.path = Path(journal).expanduser().with_name(Path(journal).name + '.lock')

    def __enter__(self):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        os.close(self.fd)        # closing releases the lock


def run(*, policy_path=DEFAULT_POLICY, response_policy=engine.DEFAULT_POLICY, ledger=engine.DEFAULT_LEDGER,
        journal=DEFAULT_JOURNAL, state_path=DEFAULT_STATE, now=None, executor=None, dry_run=False, protected=None):
    """Resume pauses whose time is up, then carry out the allowed decisions recorded since the last run."""
    policy = load_policy(policy_path)
    now = now or _now()
    if not policy['enabled'] and not dry_run:
        # Turning enforcement off never leaves a process paused past its time.
        return dict(schema=SCHEMA, action='run', enabled=False, applied=[], refused=[],
                    expired=expire(journal=journal, executor=executor, now=now),
                    note='Enforcement is off: set enabled = true in the enforcement policy to carry out decisions.')
    arguments = dict(policy=policy, response_policy=response_policy, ledger=ledger, journal=journal,
                     state_path=state_path, now=now, executor=executor, dry_run=dry_run,
                     protected=protected)
    if dry_run:
        return dict(_run(**arguments), expired=[dict(r, status='would_resume') for r in due(journal, now)])
    # Refused before anything is created or waited for: a run that is off or in Stage 0 leaves no trace.
    _admit()
    with _Lock(journal):
        expired = _expire(journal, executor, now)
        return dict(_run(**arguments), expired=expired)


def due(journal=DEFAULT_JOURNAL, now=None):
    """Paused processes whose suspend_minutes are up."""
    now = now or _now()
    return [r for r in active(journal) if r['action'] == 'suspend_process' and r.get('until')
            and _parse(r['until']) <= now]


def expire(*, journal=DEFAULT_JOURNAL, executor=None, now=None):
    """Resume every pause whose time is up. Reads only, and creates nothing, when none is."""
    now = now or _now()
    if not due(journal, now):
        return []
    _admit()
    with _Lock(journal):
        return _expire(journal, executor, now)


def _expire(journal, executor, now):
    executor = executor or Executor()
    done = []
    for record in due(journal, now):
        base = dict(schema=SCHEMA, id=secrets.token_hex(6), at=_iso(now), action=record['action'],
                    target=record['target'], undo_of=record['id'], incident=record.get('incident'), reason='expired')
        try:
            executor.undo_suspend_process(record)
            entry = dict(base, status='undone')
        except EnforcementError as exc:
            # Exited, or its PID now names another process: there is nothing left to resume, and nothing is
            # signalled. The pause is over either way.
            entry = dict(base, status='undone', note=str(exc)[:300])
        except OSError as exc:
            # Still paused, and still listed: tried again on the next run.
            done.append(dict(base, status='failed', reason=f'could not resume it: {exc}'[:300]))
            continue
        _journal(journal, [entry])
        done.append(entry)
    return done


def _admit():
    from .execution_boundary import Stage0Denied, require_effects_allowed
    try:
        require_effects_allowed()
    except Stage0Denied:
        raise EnforcementError('this process is in Stage 0: no effects are allowed') from None


def _run(*, policy, response_policy, ledger, journal, state_path, now, executor, dry_run, protected):
    rules = engine.load_policy(response_policy)
    state = _state(state_path)
    decisions = _decisions(ledger, state)
    executor = executor or Executor(quarantine=policy['quarantine'])
    guards = engine.Guards(rules, {}, now, protected=protected)
    applied_keys = set(state.get('applied', []))
    hour_ago = now - timedelta(hours=1)
    recent = sum(1 for e in entries(journal) if e.get('status') == 'applied' and e.get('action') not in
                 ('collect_evidence', 'notify') and _parse(e['at']) >= hour_ago)
    applied, refused, records = [], [], []
    for decision in decisions:
        for plan in decision.get('actions', []):
            if plan.get('status') != 'would_apply' or plan['action'] not in policy['actions']:
                continue
            key = hashlib.sha256(json.dumps([decision['decided_at'], decision['signal']['key'], plan['action'],
                                             plan.get('target')]).encode()).hexdigest()
            if key in applied_keys:
                continue
            reason = None
            if decision.get('playbook') not in policy['playbooks']:
                reason = 'this playbook is not listed in the enforcement policy'
            elif decision.get('policy_sha256') != policy['digest'] or rules.digest != policy['digest']:
                reason = 'decided under a response policy other than the pinned one'
            elif now - _parse(decision['decided_at']) > policy['max_age']:
                reason = 'the decision is too old to act on'
            elif plan['action'] == 'disable_persistence' and decision['signal'].get('rule_id') != 'PERSISTENCE_ADDED':
                reason = NOT_ADDED
            elif plan.get('target') is not None and (why := guards.check(plan['action'], plan['target'])):
                reason = f'a guard refuses it now: {why}'
            elif plan['action'] not in ('collect_evidence', 'notify') and recent >= policy['max_per_hour']:
                reason = f'enforcement rate limit: {policy["max_per_hour"]} actions in the last hour'
            base = dict(schema=SCHEMA, id=key[:12], at=_iso(now), action=plan['action'], target=plan.get('target'),
                        playbook=decision.get('playbook'), rule_id=decision['signal']['rule_id'],
                        decided_at=decision['decided_at'], signal_key=decision['signal'].get('key'),
                        incident=(decision.get('incident') or {}).get('id'))
            if plan['action'] == 'suspend_process' and plan.get('minutes'):
                base['until'] = _iso(now + timedelta(minutes=int(plan['minutes'])))
            if reason:
                refused.append(dict(base, status='refused', reason=reason))
                continue
            if dry_run:
                applied.append(dict(base, status='would_enforce'))
                continue
            applied_keys.add(key)
            try:
                undo = getattr(executor, plan['action'])(plan.get('target'), decision)
                record = dict(base, status='applied', undo=undo)
                if plan['action'] not in ('collect_evidence', 'notify'):
                    recent += 1
                applied.append(record)
            except (EnforcementError, OSError, ValueError) as exc:
                record = dict(base, status='failed', reason=str(exc)[:500])
                refused.append(record)
            records.append(record)
    if records:
        _journal(journal, records)
    if not dry_run:
        state['applied'] = sorted(applied_keys)[-MAX_APPLIED_KEYS:]
        engine._atomic_write(Path(state_path).expanduser(), json.dumps(state, sort_keys=True).encode())
    return dict(schema=SCHEMA, action='dry_run' if dry_run else 'run', enabled=policy['enabled'],
                decisions=len(decisions), applied=applied, refused=refused,
                note='Undo any applied action with `megalodon enforce undo ID`.')


def active(journal=DEFAULT_JOURNAL):
    """Applied actions that have not been undone."""
    records = entries(journal)
    undone = {r['undo_of'] for r in records if r.get('status') == 'undone'}
    return [r for r in records if r.get('status') == 'applied' and r['id'] not in undone
            and r['action'] not in ('collect_evidence', 'notify')]


def undo(identifier, *, journal=DEFAULT_JOURNAL, executor=None, now=None):
    _admit()
    with _Lock(journal):
        return _undo(identifier, journal=journal, executor=executor, now=now)


def _undo(identifier, *, journal, executor, now):
    record = next((r for r in active(journal) if r['id'] == identifier), None)
    if record is None:
        raise EnforcementError(f'no applied, not yet undone action has the ID {identifier}')
    executor = executor or Executor()
    getattr(executor, 'undo_' + record['action'])(record)
    done = dict(schema=SCHEMA, id=secrets.token_hex(6), at=_iso(now or _now()), action=record['action'],
                target=record['target'], status='undone', undo_of=identifier, incident=record.get('incident'))
    _journal(journal, [done])
    return done
