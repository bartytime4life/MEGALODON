"""One command to run every host watch on a schedule, with alerts.

`megalodon schedule plan` shows the systemd timers and services it would
install: each baseline check with `--alert`, the rootkit cross-checks, the
response engine's shadow pass and, as root, the live process ancestry and
container escape watches.
`install --yes` writes those units and enables them; `remove --yes` disables
and deletes them. Nothing is written or started without `--yes`.

Units are marked as MEGALODON's, and `remove` deletes only marked units.
Without systemd, `plan` prints equivalent crontab lines to add yourself.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

MARKER = '# Managed by megalodon schedule. `megalodon schedule remove --yes` deletes it.'
PREFIX = 'megalodon-'


@dataclass(frozen=True)
class Job:
    name: str
    description: str
    command: tuple
    calendar: str | None = None           # systemd OnCalendar; None for a long-running service
    manifest: str | None = None           # the baseline the check needs
    baseline: tuple | None = None         # how to take it
    root_only: bool = False
    cron: str | None = None
    cron_command: tuple | None = None     # for a live watch: the check crontab runs instead, without systemd
    interval: int | None = None           # seconds between runs, for the tamper check's overdue test
    setup: str | None = None              # what to run when there is no baseline command
    writable: tuple = ()                  # folders the job changes, writable inside ProtectSystem=full
    ebpf: str | None = None               # 'optional': goes on without it; 'required': left out where it cannot run


JOBS = (
    Job('respond', 'MEGALODON response engine, shadow pass', ('respond', 'run'), '*:0/5',
        manifest='~/.config/megalodon/response-policy.toml', baseline=('respond', 'init'), cron='*/5 * * * *',
        interval=300),
    # New actions need an enabled policy; due suspension recovery also runs while new enforcement is off.
    Job('enforce', 'MEGALODON enforcement and suspension recovery', ('enforce', 'run'), '*:*:00',
        # usermod writes /etc/shadow through lock and temporary files beside it, so it needs /etc, not one file.
        # disable_persistence moves units out of /usr/local/lib/systemd/system too; `-` allows it to be absent.
        cron='* * * * *', interval=60, root_only=True, writable=('/etc', '-/usr/local/lib/systemd/system')),
    # A signed heartbeat off the machine: its silence is what an intruder who stops everything cannot hide.
    Job('heartbeat', 'MEGALODON heartbeat', ('heartbeat', 'send'), '*:0/5',
        manifest='~/.config/megalodon/heartbeat.json', cron='*/5 * * * *', interval=300,
        setup='megalodon heartbeat init --url https://your-monitor.example/ping'),
    # The incident timeline to the fleet collector, signed with the heartbeat key; a plain monitor answers 404.
    Job('timeline-push', 'MEGALODON timeline push to the fleet collector', ('timeline', 'push'), '*:0/5',
        manifest='~/.config/megalodon/heartbeat.json', cron='*/5 * * * *', interval=300,
        setup='megalodon heartbeat init --url https://your-collector.example/heartbeat'),
    # Command log lines and evidence bundles to the fleet collector, so deleting them on the machine loses nothing.
    Job('evidence-push', 'MEGALODON evidence push to the fleet collector', ('evidence', 'push'), '*:0/5',
        manifest='~/.config/megalodon/heartbeat.json', cron='*/5 * * * *', interval=300,
        setup='megalodon heartbeat init --url https://your-collector.example/heartbeat'),
    Job('tamper', 'MEGALODON tamper check', ('tamper', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/tamper.json', baseline=('tamper', 'baseline'), cron='*/15 * * * *',
        interval=900),
    Job('persistence', 'MEGALODON persistence check', ('persistence', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/persistence.json', baseline=('persistence', 'baseline'), cron='*/15 * * * *',
        interval=900),
    Job('logins', 'MEGALODON login check', ('logins', 'check', '--alert'), '*:0/5',
        manifest='~/.config/megalodon/logins.json', baseline=('logins', 'learn'), cron='*/5 * * * *',
        interval=300),
    # Live: every 10 seconds, each change once while it lasts, and as root the listeners that open and close in
    # between, as a bind shell that takes one connection does.
    Job('listeners', 'MEGALODON listener watch', ('listeners', 'watch', '--alert'),
        manifest='~/.config/megalodon/listeners.json', baseline=('listeners', 'baseline'),
        cron='*/10 * * * *', cron_command=('listeners', 'check', '--alert')),
    # Each run records the logs without a finding, so the next one covers what was written in between, and
    # rotated copies that logrotate later deletes are not reported.
    Job('logwatch', 'MEGALODON log integrity check', ('logwatch', 'check', '--alert', '--advance'), '*:0/15',
        manifest='~/.config/megalodon/log-integrity.json', baseline=('logwatch', 'baseline'), cron='*/15 * * * *',
        interval=900),
    # Live: a keystroke-injection device types within seconds, so each new device is decided as it is plugged in.
    # Its enforcement run is a whole run, so it can write what the enforce job writes.
    Job('devices', 'MEGALODON device watch, answered at once', ('devices', 'watch', '--alert', '--respond'),
        manifest='~/.config/megalodon/devices.json', baseline=('devices', 'baseline'),
        writable=('/etc', '-/usr/local/lib/systemd/system'),
        cron='*/5 * * * *', cron_command=('devices', 'check', '--alert')),
    # Live: a web shell dropped, used and deleted between two 15-minute checks is seen as it is written.
    Job('webroot', 'MEGALODON web-root watch', ('webroot', 'watch', '--alert'),
        manifest='~/.config/megalodon/webroot.json', baseline=('webroot', 'baseline'),
        cron='*/15 * * * *', cron_command=('webroot', 'check', '--alert')),
    Job('binaries', 'MEGALODON program integrity check', ('binaries', 'check', '--alert'), '*-*-* 03:17:00',
        manifest='~/.config/megalodon/binaries.json', baseline=('binaries', 'baseline'), cron='17 3 * * *',
        interval=86400),
    Job('ebpf', 'MEGALODON eBPF program check', ('ebpf', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/ebpf.json', baseline=('ebpf', 'baseline'), cron='*/15 * * * *', interval=900,
        root_only=True),
    Job('containers', 'MEGALODON container check', ('containers', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/containers.json', baseline=('containers', 'baseline'), cron='*/15 * * * *',
        interval=900, root_only=True),
    Job('hardening', 'MEGALODON hardening drift check', ('hardening', 'check', '--alert'), 'hourly',
        manifest='~/.config/megalodon/hardening.json', baseline=('hardening', 'baseline'), cron='47 * * * *',
        interval=3600),
    Job('packages', 'MEGALODON package sources and signing keys check', ('packages', 'check', '--alert'), 'hourly',
        manifest='~/.config/megalodon/packages.json', baseline=('packages', 'baseline'), cron='29 * * * *',
        interval=3600),
    # Reads home folders and web roots: daily, at low priority.
    Job('secrets', 'MEGALODON exposed secrets check', ('secrets', 'check', '--alert'), '*-*-* 04:23:00',
        manifest='~/.config/megalodon/secrets.json', baseline=('secrets', 'baseline'), cron='23 4 * * *',
        interval=86400),
    Job('vulns', 'MEGALODON known-vulnerable software check', ('vulns', 'check', '--alert'), '*-*-* 06:41:00',
        cron='41 6 * * *', interval=86400),
    Job('boot', 'MEGALODON boot integrity check', ('boot', 'check', '--alert'), 'hourly',
        manifest='~/.config/megalodon/boot.json', baseline=('boot', 'baseline'), cron='23 * * * *', interval=3600),
    # The port test briefly binds every free port; scheduled runs leave it out.
    Job('rootkit', 'MEGALODON rootkit cross-checks', ('rootkit', 'check', '--skip-ports', '--alert'), 'hourly',
        cron='41 * * * *', interval=3600),
    # The live watches answer each finding as it is seen; their enforcement run is a whole run, so they can
    # write what the enforce job writes. With --trace-execs, each started program is taken from the kernel's
    # record at its exec (eBPF), so one gone before the watch reads it is still seen; where eBPF cannot be
    # loaded, each watch says why and goes on as without it.
    Job('ancestry', 'MEGALODON process ancestry watch, answered at once',
        ('ancestry', 'watch', '--alert', '--respond', '--trace-execs'), ebpf='optional',
        root_only=True, writable=('/etc', '-/usr/local/lib/systemd/system'),
        cron='*/5 * * * *', cron_command=('ancestry', 'check', '--alert')),
    # Every started program, in a signed log; its first key is printed once by init and kept off the machine.
    Job('commands', 'MEGALODON command log', ('commands', 'record', '--trace-execs'), root_only=True, ebpf='optional',
        manifest='~/.local/state/megalodon/commands-state.json',
        setup='megalodon commands init --key-file /path/to/move/off/this/machine'),
    Job('credentials', 'MEGALODON credential access watch, answered at once',
        ('credentials', 'watch', '--alert', '--respond', '--trace-execs'), ebpf='optional',
        writable=('/etc', '-/usr/local/lib/systemd/system'),
        cron='*/5 * * * *', cron_command=('credentials', 'check', '--alert')),
    # Live: a program started on the host from a container, as it starts, so an escape over within a second is
    # seen. It needs eBPF and has no fallback, so it is left out where the kernel lacks what eBPF needs; the
    # 15-minute containers check covers those machines.
    Job('container-escapes', 'MEGALODON container escape watch, answered at once',
        ('containers', 'watch', '--alert', '--respond'), root_only=True, ebpf='required',
        writable=('/etc', '-/usr/local/lib/systemd/system')),
    # Encryption is decided and enforced as it is seen, not on the next timer; enforcement may disable a
    # persistence entry decided earlier in the same pass, so the same folders as the enforce job are writable.
    Job('ransomware', 'MEGALODON ransomware watch, answered at once', ('ransomware', 'watch', '--respond'),
        manifest='~/.config/megalodon/ransomware.json', setup='megalodon ransomware init --dir /home --dir /srv',
        writable=('/etc', '-/usr/local/lib/systemd/system')),
    # With --trace-connects, a connection too short for a scan is named by its program (eBPF), so a dropped tool
    # in a temporary folder is OUTBOUND_FROM_TEMPORARY, not a destination alone; without eBPF, it goes on without.
    Job('egress', 'MEGALODON outgoing-program watch, answered at once',
        ('egress', 'watch', '--alert', '--respond', '--trace-connects'), ebpf='optional',
        manifest='~/.config/megalodon/egress.json', setup='megalodon egress learn --minutes 60',
        writable=('/etc', '-/usr/local/lib/systemd/system'),
        cron='*/5 * * * *', cron_command=('egress', 'check', '--alert')),
)


class ScheduleError(ValueError):
    pass


def _launcher():
    found = shutil.which('megalodon')
    return [found] if found else [sys.executable, '-m', 'megalodon']


def _system_mode(system):
    return os.geteuid() == 0 if system is None else system


def ebpf_missing():
    """Why the exec trace cannot be loaded here, as far as can be seen without loading it; None if it can."""
    import platform
    from .connect_trace import BTF_PATH, SYSCALL_BPF
    if platform.machine() not in SYSCALL_BPF:
        return f'eBPF tracing supports x86-64 and arm64, not {platform.machine()}'
    if not os.path.exists(BTF_PATH):
        return f'the kernel has no type information ({BTF_PATH})'
    try:
        release = tuple(int(part) for part in platform.release().split('-')[0].split('.')[:2])
    except ValueError:
        return None
    if release < (5, 8):
        return f'BPF ring buffers need Linux 5.8 or later, not {platform.release()}'
    return None


def _cannot_run(job):
    return ebpf_missing() if job.ebpf == 'required' else None


def unit_dir(system):
    return Path('/etc/systemd/system') if system else Path.home() / '.config/systemd/user'


def has_systemd():
    return os.path.isdir('/run/systemd/system')


def _exec(job, launcher, command=None):
    return ' '.join(shlex.quote(part) for part in [*launcher, *(command or job.command)])


def units(job, launcher, system):
    """{file name: contents} for one job."""
    service = [MARKER, '[Unit]', f'Description={job.description}', 'After=network-online.target', '',
               '[Service]', f'ExecStart={_exec(job, launcher)}',
               # Read-only checks: no new privileges, the system tree read-only, low priority.
               'NoNewPrivileges=yes', 'ProtectSystem=full', 'Nice=10']
    service += [f'ReadWritePaths={folder}' for folder in job.writable]
    if job.ebpf and system:
        # Before Linux 5.11, BPF maps count against the locked-memory limit, 8 MiB by default: the trace's
        # ring buffer alone is that much. Only as root: eBPF needs it, and a user unit cannot raise the limit.
        service.append('LimitMEMLOCK=64M')
    if job.calendar is None:
        service += ['Restart=on-failure', 'RestartSec=10', '', '[Install]',
                    f'WantedBy={"multi-user.target" if system else "default.target"}']
        return {f'{PREFIX}{job.name}.service': '\n'.join(service) + '\n'}
    service += ['Type=oneshot', 'IOSchedulingClass=idle']
    # Read-only checks use 1 for findings. Enforcement uses it for failed actions or failed recovery,
    # which must remain unsuccessful so systemd health and failure handling do not report success.
    if job.name != 'enforce':
        service.append('SuccessExitStatus=1')
    timer = [MARKER, '[Unit]', f'Description={job.description} (schedule)', '', '[Timer]',
             f'OnCalendar={job.calendar}', 'Persistent=true', 'RandomizedDelaySec=60', '', '[Install]',
             'WantedBy=timers.target']
    return {f'{PREFIX}{job.name}.service': '\n'.join(service) + '\n',
            f'{PREFIX}{job.name}.timer': '\n'.join(timer) + '\n'}


def _selected(only, system):
    jobs = [j for j in JOBS if (not only or j.name in only) and (system or not j.root_only) and not _cannot_run(j)]
    unknown = set(only or ()) - {j.name for j in JOBS}
    if unknown:
        raise ScheduleError(f'unknown jobs: {", ".join(sorted(unknown))}; choose from '
                            f'{", ".join(j.name for j in JOBS)}')
    return jobs


def plan(*, system=None, only=None, directory=None, launcher=None):
    system = _system_mode(system)
    launcher = launcher or _launcher()
    folder = Path(directory) if directory else unit_dir(system)
    rows, skipped = [], []
    for job in JOBS:
        if only and job.name not in only:
            continue
        if job.root_only and not system:
            skipped.append(dict(job=job.name, reason='needs root: run `sudo megalodon schedule plan`'))
        elif _cannot_run(job):
            skipped.append(dict(job=job.name, reason=f'needs eBPF: {_cannot_run(job)}'))
    for job in _selected(only, system):
        ready = job.manifest is None or Path(job.manifest).expanduser().exists()
        rows.append(dict(job=job.name, description=job.description, command=_exec(job, launcher),
                         every=job.calendar or 'always running', units=sorted(units(job, launcher, system)),
                         baseline=None if ready else (' '.join([*launcher, *job.baseline]) if job.baseline
                                                      else job.setup),
                         cron=f'{job.cron} {_exec(job, launcher, job.cron_command)}' if job.cron else None))
    return dict(schema='megalodon-schedule-plan-v1', scope='system' if system else 'user', unit_dir=str(folder),
                systemd=has_systemd(), jobs=rows, skipped=skipped,
                note=('Nothing was written. Take the missing baselines on a system you trust, then run '
                      '`megalodon schedule install --yes`.' if any(r['baseline'] for r in rows) else
                      'Nothing was written. Run `megalodon schedule install --yes` to install these.'))


def _systemctl(system, *args):
    return subprocess.run(['systemctl', *([] if system else ['--user']), *args], check=False,
                          capture_output=True, text=True, timeout=60)


def install(*, system=None, only=None, directory=None, launcher=None, runner=None, take_baselines=False):
    system = _system_mode(system)
    launcher = launcher or _launcher()
    runner = runner or _systemctl
    folder = Path(directory) if directory else unit_dir(system)
    if directory is None and not has_systemd():
        raise ScheduleError('systemd is not running; add the cron lines from `megalodon schedule plan` instead')
    jobs = _selected(only, system)
    missing = [j for j in jobs if j.manifest and not Path(j.manifest).expanduser().exists()]
    taken = []
    manual = [j for j in missing if not j.baseline]
    if manual:
        raise ScheduleError('set up first: ' + '; '.join(f'{j.name}: {j.setup}' for j in manual) +
                            ' (or leave them out with --only)')
    if missing and not take_baselines:
        raise ScheduleError('missing baselines for ' + ', '.join(j.name for j in missing) +
                            '; take them first (see `megalodon schedule plan`) or pass --take-baselines')
    def take(job):
        result = subprocess.run([*launcher, *job.baseline], check=False, capture_output=True, text=True,
                                timeout=1800)
        if result.returncode not in (0, 1):     # 1: a baseline that already found something, which it reported
            raise ScheduleError(f'{job.name} baseline failed: {result.stderr.strip()[:300]}')
        taken.append(job.name)
    # The tamper baseline records the other baselines and the units, so it is taken after both exist.
    for job in missing:
        if job.name != 'tamper':
            take(job)
    folder.mkdir(parents=True, exist_ok=True, mode=0o755 if system else 0o700)
    written = []
    for job in jobs:
        for name, text in units(job, launcher, system).items():
            path = folder / name
            if path.exists() and MARKER not in path.read_text(encoding='utf-8', errors='replace'):
                raise ScheduleError(f'{path} exists and is not MEGALODON\'s; it was left alone')
            temporary = path.with_name(f'.{name}.tmp')
            temporary.write_text(text, encoding='utf-8')
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
            written.append(str(path))
    for job in missing:
        if job.name == 'tamper':
            take(job)
    # A job that now runs all the time leaves no timer of its own from an earlier install to start it again.
    retired = []
    for job in jobs:
        timer = folder / f'{PREFIX}{job.name}.timer'
        if job.calendar is None and timer.exists() and MARKER in timer.read_text(encoding='utf-8', errors='replace'):
            runner(system, 'disable', '--now', timer.name)
            timer.unlink()
            retired.append(str(timer))
    enabled = [f'{PREFIX}{j.name}.{"timer" if j.calendar else "service"}' for j in jobs]
    results = [runner(system, 'daemon-reload')]
    results.append(runner(system, 'enable', '--now', *enabled))
    failed = [r for r in results if r.returncode != 0]
    after = []
    if any(j.name == 'tamper' for j in jobs) and 'tamper' not in taken:
        after.append('run `megalodon tamper accept` so the tamper check records these units')
    return dict(schema='megalodon-schedule-v1', action='install', scope='system' if system else 'user',
                baselines_taken=taken, written=written, retired=retired, enabled=enabled, next=after,
                ok=not failed, errors=[(r.stderr or '').strip()[:300] for r in failed])


def remove(*, system=None, directory=None, runner=None):
    system = _system_mode(system)
    runner = runner or _systemctl
    folder = Path(directory) if directory else unit_dir(system)
    ours = []
    for path in sorted(folder.glob(f'{PREFIX}*')) if folder.is_dir() else []:
        try:
            if MARKER in path.read_text(encoding='utf-8', errors='replace'):
                ours.append(path)
        except OSError:
            continue
    active = [p.name for p in ours if p.suffix == '.timer' or not (folder / (p.stem + '.timer')).exists()]
    results = [runner(system, 'disable', '--now', *active)] if active else []
    for path in ours:
        path.unlink()
    results.append(runner(system, 'daemon-reload'))
    failed = [r for r in results if r.returncode != 0]
    return dict(schema='megalodon-schedule-v1', action='remove', scope='system' if system else 'user',
                removed=[str(p) for p in ours], ok=not failed,
                errors=[(r.stderr or '').strip()[:300] for r in failed])
