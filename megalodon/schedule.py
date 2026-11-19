"""One command to run every host watch on a schedule, with alerts.

`megalodon schedule plan` shows the systemd timers and services it would
install: each baseline check with `--alert`, the rootkit cross-checks, the
response engine's shadow pass and, as root, the live process ancestry watch.
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
    interval: int | None = None           # seconds between runs, for the tamper check's overdue test
    setup: str | None = None              # what to run when there is no baseline command


JOBS = (
    Job('respond', 'MEGALODON response engine, shadow pass', ('respond', 'run'), '*:0/5',
        manifest='~/.config/megalodon/response-policy.toml', baseline=('respond', 'init'), cron='*/5 * * * *',
        interval=300),
    # A signed heartbeat off the machine: its silence is what an intruder who stops everything cannot hide.
    Job('heartbeat', 'MEGALODON heartbeat', ('heartbeat', 'send'), '*:0/5',
        manifest='~/.config/megalodon/heartbeat.json', cron='*/5 * * * *', interval=300,
        setup='megalodon heartbeat init --url https://your-monitor.example/ping'),
    Job('tamper', 'MEGALODON tamper check', ('tamper', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/tamper.json', baseline=('tamper', 'baseline'), cron='*/15 * * * *',
        interval=900),
    Job('persistence', 'MEGALODON persistence check', ('persistence', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/persistence.json', baseline=('persistence', 'baseline'), cron='*/15 * * * *',
        interval=900),
    Job('logins', 'MEGALODON login check', ('logins', 'check', '--alert'), '*:0/5',
        manifest='~/.config/megalodon/logins.json', baseline=('logins', 'learn'), cron='*/5 * * * *',
        interval=300),
    Job('listeners', 'MEGALODON listener check', ('listeners', 'check', '--alert'), '*:0/10',
        manifest='~/.config/megalodon/listeners.json', baseline=('listeners', 'baseline'), cron='*/10 * * * *',
        interval=600),
    Job('logwatch', 'MEGALODON log integrity check', ('logwatch', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/log-integrity.json', baseline=('logwatch', 'baseline'), cron='*/15 * * * *',
        interval=900),
    Job('devices', 'MEGALODON device check', ('devices', 'check', '--alert'), '*:0/5',
        manifest='~/.config/megalodon/devices.json', baseline=('devices', 'baseline'), cron='*/5 * * * *',
        interval=300),
    Job('webroot', 'MEGALODON web-root check', ('webroot', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/webroot.json', baseline=('webroot', 'baseline'), cron='*/15 * * * *',
        interval=900),
    Job('binaries', 'MEGALODON program integrity check', ('binaries', 'check', '--alert'), '*-*-* 03:17:00',
        manifest='~/.config/megalodon/binaries.json', baseline=('binaries', 'baseline'), cron='17 3 * * *',
        interval=86400),
    Job('ebpf', 'MEGALODON eBPF program check', ('ebpf', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/ebpf.json', baseline=('ebpf', 'baseline'), cron='*/15 * * * *', interval=900,
        root_only=True),
    Job('containers', 'MEGALODON container check', ('containers', 'check', '--alert'), '*:0/15',
        manifest='~/.config/megalodon/containers.json', baseline=('containers', 'baseline'), cron='*/15 * * * *',
        interval=900, root_only=True),
    Job('boot', 'MEGALODON boot integrity check', ('boot', 'check', '--alert'), 'hourly',
        manifest='~/.config/megalodon/boot.json', baseline=('boot', 'baseline'), cron='23 * * * *', interval=3600),
    # The port test briefly binds every free port; scheduled runs leave it out.
    Job('rootkit', 'MEGALODON rootkit cross-checks', ('rootkit', 'check', '--skip-ports', '--alert'), 'hourly',
        cron='41 * * * *', interval=3600),
    Job('ancestry', 'MEGALODON process ancestry watch', ('ancestry', 'watch', '--alert'), root_only=True),
    Job('credentials', 'MEGALODON credential access watch', ('credentials', 'watch', '--alert')),
    Job('egress', 'MEGALODON outgoing-program watch', ('egress', 'watch', '--alert'),
        manifest='~/.config/megalodon/egress.json', setup='megalodon egress learn --minutes 60'),
)


class ScheduleError(ValueError):
    pass


def _launcher():
    found = shutil.which('megalodon')
    return [found] if found else [sys.executable, '-m', 'megalodon']


def _system_mode(system):
    return os.geteuid() == 0 if system is None else system


def unit_dir(system):
    return Path('/etc/systemd/system') if system else Path.home() / '.config/systemd/user'


def has_systemd():
    return os.path.isdir('/run/systemd/system')


def _exec(job, launcher):
    return ' '.join(shlex.quote(part) for part in [*launcher, *job.command])


def units(job, launcher, system):
    """{file name: contents} for one job."""
    service = [MARKER, '[Unit]', f'Description={job.description}', 'After=network-online.target', '',
               '[Service]', f'ExecStart={_exec(job, launcher)}',
               # Read-only checks: no new privileges, the system tree read-only, low priority.
               'NoNewPrivileges=yes', 'ProtectSystem=full', 'Nice=10']
    if job.calendar is None:
        service += ['Restart=on-failure', 'RestartSec=10', '', '[Install]',
                    f'WantedBy={"multi-user.target" if system else "default.target"}']
        return {f'{PREFIX}{job.name}.service': '\n'.join(service) + '\n'}
    service += ['Type=oneshot', 'IOSchedulingClass=idle',
                # A check exits 1 when it has findings; that is a result, not a failed unit.
                'SuccessExitStatus=1']
    timer = [MARKER, '[Unit]', f'Description={job.description} (schedule)', '', '[Timer]',
             f'OnCalendar={job.calendar}', 'Persistent=true', 'RandomizedDelaySec=60', '', '[Install]',
             'WantedBy=timers.target']
    return {f'{PREFIX}{job.name}.service': '\n'.join(service) + '\n',
            f'{PREFIX}{job.name}.timer': '\n'.join(timer) + '\n'}


def _selected(only, system):
    jobs = [j for j in JOBS if (not only or j.name in only) and (system or not j.root_only)]
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
    for job in _selected(only, system):
        ready = job.manifest is None or Path(job.manifest).expanduser().exists()
        rows.append(dict(job=job.name, description=job.description, command=_exec(job, launcher),
                         every=job.calendar or 'always running', units=sorted(units(job, launcher, system)),
                         baseline=None if ready else (' '.join([*launcher, *job.baseline]) if job.baseline
                                                      else job.setup),
                         cron=f'{job.cron} {_exec(job, launcher)}' if job.cron else None))
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
    enabled = [f'{PREFIX}{j.name}.{"timer" if j.calendar else "service"}' for j in jobs]
    results = [runner(system, 'daemon-reload')]
    results.append(runner(system, 'enable', '--now', *enabled))
    failed = [r for r in results if r.returncode != 0]
    after = []
    if any(j.name == 'tamper' for j in jobs) and 'tamper' not in taken:
        after.append('run `megalodon tamper accept` so the tamper check records these units')
    return dict(schema='megalodon-schedule-v1', action='install', scope='system' if system else 'user',
                baselines_taken=taken, written=written, enabled=enabled, next=after,
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
