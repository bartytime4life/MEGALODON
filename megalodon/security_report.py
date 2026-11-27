"""One security report for this machine, in plain language, with what you can do about each finding.

`megalodon report` reads what is already recorded, and runs no check itself:

* **each check's latest result**, kept by `megalodon CHECK check` (and so by
  the scheduled jobs) in ``~/.local/state/megalodon/results``;
* **incidents** the response engine correlated, with what it decided and what
  enforcement did, from its ledger and the enforcement journal;
* **how the protection is set up**: the scheduled jobs and whether the live
  watches run, alerts, the response and enforcement policies, the heartbeat,
  and the baselines still missing.

Each finding comes with what it means, how serious it is, and the choices you
have, each as the exact command: look closer, keep evidence, say it is
expected (accept or allow), contain it, or undo what was done. Nothing is
carried out by the report.

Everything a finding names (paths, programs, addresses, log lines) can be
chosen by an attacker. It is shown with control characters replaced, every
value in a command is shell-quoted, and the HTML page escapes everything.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import html
import json
import os
from pathlib import Path
import re
import shlex

from . import results

SCHEMA = 'megalodon-security-report-v1'
DEFAULT_OUTPUT = '~/.local/state/megalodon/report.html'
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
SHOWN_PER_CHECK = 25
# Every kept finding, read only. Not the check's own command: that looks again and replaces what was kept, which
# for a watch is what it saw of things since gone.
ALL_FINDINGS = 'megalodon report --all'
CONTROL = re.compile(r'[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]')


def clean(value, limit=300):
    """Text from a finding, safe to print: control and direction characters replaced, length bounded."""
    text = CONTROL.sub('?', str(value))
    return text if len(text) <= limit else text[:limit - 1] + '…'


def command(*parts):
    """A command a person may copy: every value cleaned and shell-quoted."""
    return ' '.join(part if index < 2 and re.fullmatch(r'[a-z-]+', part) else shlex.quote(clean(part, 500))
                    for index, part in enumerate(parts))


def _choice(kind, label, *parts, note=None):
    """One choice: the command shown (shell-quoted) and the same command as arguments, which `megalodon review`
    runs without a shell when you confirm it. A choice with no arguments is yours to adapt and run."""
    item = dict(choice=kind, label=label, command=command(*parts), argv=[clean(part, 500) for part in parts])
    if note:
        item['note'] = note
    return item


# What each check is for, how it runs, and how a finding is said to be expected. `live` checks run all the time
# and act at once; their findings also reach the incidents below.
CHECKS = {
    'persistence': dict(title='Things set to start by themselves', group='Break-ins and backdoors',
                        why='Services, timers, cron jobs, startup files, SSH keys and the like: how an intruder '
                            'comes back after a reboot.', accept=('persistence', 'accept')),
    'logins': dict(title='Unusual logins', group='Break-ins and backdoors',
                   why='Logins from new networks, with new keys, at unusual hours, or by accounts that should never '
                       'log in.', accept=('logins', 'learn'), accept_label='Learn the logins seen since as normal'),
    'credentials': dict(title='Passwords and keys being read', group='Break-ins and backdoors', live=True,
                        why='Programs other than the expected ones opening SSH keys, browser passwords, cloud tokens '
                            'and similar.'),
    'ancestry': dict(title='Services starting shells and tools', group='Break-ins and backdoors', live=True,
                     why='A web server or database starting a shell or a tool such as curl is how web shells and '
                         'exploited services look.'),
    'listeners': dict(title='Open network ports', group='Break-ins and backdoors', live=True,
                      why='New programs listening for connections, which is how backdoors wait for their owner.',
                      accept=('listeners', 'accept')),
    'egress': dict(title='Programs connecting out', group='Break-ins and backdoors', live=True,
                   why='Programs connecting out that never did, or running from temporary folders, as dropped tools '
                       'phoning home do.'),
    'webroot': dict(title='Web server files', group='Break-ins and backdoors', live=True,
                    why='Scripts and code dropped into the folders a web server serves: web shells.',
                    accept=('webroot', 'accept')),
    'containers': dict(title='Containers', group='Break-ins and backdoors',
                       why='Processes that left their container, and containers given access to the host.',
                       accept=('containers', 'accept')),
    'rootkit': dict(title='Hidden processes and files', group='Break-ins and backdoors',
                    why='Processes, files and modules hidden from the normal listings, as rootkits do.'),
    'ebpf': dict(title='Programs inside the kernel (eBPF)', group='Break-ins and backdoors',
                 why='Kernel programs that can hide processes or read traffic, as some rootkits use.',
                 accept=('ebpf', 'accept')),
    'devices': dict(title='New devices', group='Break-ins and backdoors', live=True,
                    why='USB keyboards, network adapters and other devices plugged in since the baseline.',
                    accept=('devices', 'accept')),
    'binaries': dict(title='System programs changed', group='Tampering and integrity',
                     why="Installed programs that no longer match their packages: trojaned tools.",
                     accept=('binaries', 'accept')),
    'logwatch': dict(title='Logs wiped or rewritten', group='Tampering and integrity',
                     why='Logs that were deleted, truncated or rewritten, as intruders do to cover their tracks.',
                     accept=('logwatch', 'accept')),
    'boot': dict(title='How the machine starts', group='Tampering and integrity',
                 why='Kernels, boot loaders and Secure Boot: changes that survive reinstalling programs.',
                 accept=('boot', 'accept')),
    'packages': dict(title='Where software comes from', group='Tampering and integrity',
                     why='Package sources and signing keys: a changed one can install anything.',
                     accept=('packages', 'accept')),
    'tamper': dict(title='MEGALODON itself', group='Tampering and integrity',
                   why="MEGALODON's own code, schedule and settings, and whether its watches still run.",
                   accept=('tamper', 'accept')),
    'hardening': dict(title='Security settings weakened', group='Weak spots',
                      why='Protections turned off or loosened since the baseline.', accept=('hardening', 'accept')),
    'secrets': dict(title='Secrets left exposed', group='Weak spots',
                    why='Passwords, keys and tokens in files others or a web server can read.',
                    accept=('secrets', 'accept')),
    'vulns': dict(title='Updates waiting', group='Weak spots',
                  why='Security updates not installed yet, and programs still running code an update replaced.'),
}
GROUPS = ('Break-ins and backdoors', 'Tampering and integrity', 'Weak spots')
STATUS_WORDS = dict(clean='clear', findings='to review', error='broken', never_run='not run', watching='watching')
assert set(CHECKS) == set(results.NAMES)

# Plain meanings for the checks whose modules do not keep one per rule.
EXTRA_MEANINGS = {
    'PERSISTENCE_ADDED': 'Something new was set to start by itself. Intruders do this to come back after a '
                         'reboot; so do software installs.',
    'PERSISTENCE_CHANGED': 'Something already set to start by itself was changed, for example to run another '
                           'program.',
    'PERSISTENCE_REMOVED': 'Something that started by itself was removed.',
    'PERSISTENCE_SUSPICIOUS': 'Something set to start by itself, or an account, carries signs of an intruder\'s. '
                              'It was already there when the baseline was taken, so it is not a change: review it.',
    'CHECK_REPORTED_SOMETHING': 'The check reported something this report cannot list. Run the check to see it.',
    'NEW_LISTENER': 'A program started listening for network connections.',
    'LISTENER_PROGRAM_CHANGED': 'A known port is now held by another program.',
    'LISTENER_EXPOSED': 'A listener that was reachable only from this machine is now reachable from the network.',
    'LISTENER_OPENED_AND_CLOSED': 'A port was opened and closed between checks, as a backdoor that takes one '
                                  'connection does.',
    'LOG_DELETED': 'A log was deleted.', 'LOG_TRUNCATED': 'A log was cut short: lines were removed from its end.',
    'LOG_REWRITTEN': 'Lines in a log were changed or removed.', 'LOG_REPLACED': 'A log was replaced by another file.',
    'LOG_PERMISSIONS': "A log's owner or permissions changed.",
    'JOURNAL_FILE_DELETED': 'A system journal file was deleted.',
    'JOURNAL_ENTRIES_REMOVED': 'Entries were removed from the system journal.',
    'JOURNAL_ARCHIVE_CHANGED': 'An archived system journal file was changed.',
    'PACKAGE_MISMATCH': 'An installed program no longer matches its package: it may have been replaced.',
    'PACKAGE_RECORD_CHANGED': "The package manager's own record of a program changed.",
    'PROGRAM_ADDED': 'A program that no package installed appeared in a system folder.',
    'PROGRAM_CHANGED': 'A program that no package installed changed.',
    'PROGRAM_WRITABLE': 'A system program can be changed by accounts other than root.',
    'PACKAGE_FILE_MISSING': 'A file a package installed is missing.',
}


def _meaning(check, rule):
    if rule in EXTRA_MEANINGS:
        return EXTRA_MEANINGS[rule]
    module = _MODULES.get(check)
    if module is None:
        return None
    try:
        from importlib import import_module
        table = getattr(import_module(f'megalodon.{module}'), 'RULES', {})
    except ImportError:
        return None
    value = table.get(rule)
    if isinstance(value, str):
        return value
    if isinstance(value, (tuple, list)) and value and isinstance(value[-1], str):
        return value[-1]
    return None


_MODULES = dict(devices='device_watch', webroot='webroot_watch', ebpf='ebpf_watch', containers='container_watch',
                hardening='hardening_drift', packages='package_sources', secrets='exposed_secrets',
                vulns='vuln_check', boot='boot_integrity', rootkit='rootkit_check', logins='login_watch',
                egress='egress_watch', credentials='credential_watch', tamper='tamper', ancestry='process_ancestry')


def readable(value, limit=300):
    """A finding's detail or gap, as words: a mapping becomes 'key: value' pairs, a list its items."""
    def words(item, depth=0):
        if isinstance(item, dict):
            if depth == 0 and 'category' in item and 'location' in item and len(item) <= 3:
                return f'{str(item["category"]).replace("_", " ")} at {item["location"]}'
            if 'sign' in item:
                where = f' (line {item["line"]})' if item.get('line') is not None else ''
                return str(item['sign']).replace('_', ' ') + where
            return '; '.join(f'{str(k).replace("_", " ")}: {words(v, depth + 1)}' for k, v in item.items()
                             if v not in (None, '', [], {}))
        if isinstance(item, (list, tuple)):
            return ', '.join(words(v, depth + 1) for v in item[:10])
        return str(item).replace('_', ' ') if depth and isinstance(item, str) and item.isidentifier() else str(item)
    return clean(words(value), limit)


def _rule(check, finding):
    if finding.get('rule_id'):
        return str(finding['rule_id'])
    if check == 'persistence' and finding.get('change'):
        return f'PERSISTENCE_{str(finding["change"]).upper()}'
    return 'FINDING'


def _where(finding):
    for key in ('location', 'path', 'subject', 'log', 'device', 'listener', 'program', 'account', 'address'):
        value = finding.get(key)
        if isinstance(value, (str, int)) and str(value):
            return str(value)
    evidence = finding.get('evidence')
    if isinstance(evidence, dict):
        for key in ('program', 'path', 'service'):
            value = evidence.get(key)
            if isinstance(value, dict):
                value = value.get('program')
            if isinstance(value, str) and value:
                return value
    return None


def _severity(value):
    value = str(value or '').upper()
    return value if value in RANK else 'MEDIUM'


def _choices(check, finding, rule, where):
    """What you can do about one finding, most useful first, each with the exact command."""
    info = CHECKS[check]
    serious = _severity(finding.get('severity')) in ('CRITICAL', 'HIGH')
    out = [_choice('look', 'See the full details', 'megalodon', check, 'check')]
    entity = _entity(check, finding, where)
    if entity:
        out.append(_choice('look', 'See everything recorded about it, in order',
                           'megalodon', 'timeline', 'show', '--entity', entity))
    if serious and info['group'] != 'Weak spots':
        out.append(_choice('evidence', 'Keep evidence before anything changes', 'sudo', 'megalodon', 'evidence',
                           'collect'))
    evidence = finding.get('evidence') if isinstance(finding.get('evidence'), dict) else {}
    program = finding.get('program') or evidence.get('program')
    if check == 'ancestry':
        # An application service is allowed as its runtime and what it runs, as the watch matches it.
        running = evidence.get('service') if isinstance(evidence.get('service'), dict) else {}
        service = running.get('allow_as') or running.get('program')
        if service and evidence.get('program'):
            out.append(_choice('expected', 'This service may start this program: allow it',
                               'megalodon', 'ancestry', 'allow', service, evidence['program']))
    elif check == 'egress' and program:
        out.append(_choice('expected', 'This program may connect out: allow it', 'megalodon', 'egress', 'allow',
                           program))
    elif check == 'credentials' and program:
        out.append(_choice('expected', 'This program may read these: allow it', 'megalodon', 'credentials',
                           'allow', program))
    elif check == 'vulns':
        label, fix = VULN_FIXES.get(rule, VULN_FIXES['SECURITY_UPDATES_PENDING'])
        out.append(dict(choice='fix', label=label, command=fix))       # yours to adapt: never run for you
    elif info.get('accept'):
        out.append(_choice('expected', info.get('accept_label', 'It was you: record things as they are now'),
                           'megalodon', *info['accept'],
                           note='This records every current change of this check as expected, not only this one.'))
    if serious and check not in ('vulns', 'hardening', 'secrets'):
        out.append(_choice('contain', 'See what the response engine would do', 'megalodon', 'enforce', 'run',
                           '--dry-run',
                           note='Containment (pausing a process, blocking an address) is carried out only for the '
                                'actions and playbooks you list in ~/.config/megalodon/enforce.toml.'))
    return out


VULN_FIXES = {
    'VULNERABLE_EXPOSED_SERVICE': ('Install the waiting updates first: this service is reachable from the network',
                                   'sudo apt upgrade   # or: sudo dnf upgrade --security'),
    'SECURITY_UPDATES_PENDING': ('Install the waiting updates', 'sudo apt upgrade   # or: sudo dnf upgrade --security'),
    'FIX_NOT_RUNNING_EXPOSED': ('Restart the service it names, so the installed fix runs',
                                'sudo systemctl restart SERVICE   # the service the details name'),
    'FIX_NOT_RUNNING': ('Restart the program it names, so the installed fix runs',
                        'sudo systemctl restart SERVICE   # or restart the program'),
    'KERNEL_FIX_NOT_RUNNING': ('Restart the machine when you can: the fixed kernel is installed', 'sudo reboot'),
    'PACKAGE_LISTS_STALE': ('Refresh the package lists, so new fixes are known', 'sudo apt update   # or: sudo dnf makecache'),
}


def _entity(check, finding, where):
    """The entity the response engine recorded this finding under, as `timeline show --entity` takes it."""
    if check == 'persistence' and finding.get('category') and finding.get('location'):
        return f'persistence:{finding["category"]}:{finding["location"]}'
    if not where:
        return None
    if re.fullmatch(r'[0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+', where):
        return f'address:{where}'
    if where.startswith('/'):
        return f'file:{where}'
    return None


def _age(at, now):
    try:
        moment = datetime.strptime(at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return max(0.0, (now - moment).total_seconds())


def _interval(check):
    from . import schedule
    job = next((j for j in schedule.JOBS if j.name == check), None)
    if job is None:
        return None
    if job.interval:
        return job.interval
    if job.cron and job.cron.startswith('*/'):
        return int(job.cron.split()[0][2:]) * 60
    return None


def _live_states(system, runner=None):
    """{live check: 'active', another systemd state, or 'installed' where systemd cannot be asked}, for the live
    watches the scheduler installed as services."""
    from . import schedule, tamper
    folder = schedule.unit_dir(system)
    units = {check: f'{schedule.PREFIX}{check}.service' for check, info in CHECKS.items() if info.get('live')}
    installed = {check: unit for check, unit in units.items() if (folder / unit).exists()}
    if not installed:
        return {}
    if runner is None and not schedule.has_systemd():
        return {check: 'installed' for check in installed}
    states = tamper.unit_states(list(installed.values()), system, runner=runner)
    return {check: states.get(unit, {}).get('active') or 'unknown' for check, unit in installed.items()}


def _check_view(check, record, now, live_state=None, system=True, shown=SHOWN_PER_CHECK):
    info = CHECKS[check]
    view = dict(check=check, title=info['title'], group=info['group'], why=info['why'],
                live=bool(info.get('live')), findings=[], gaps=[])
    stopped = live_state is not None and live_state not in ('active', 'installed')
    if stopped:
        # Reported whatever the saved result holds: what an earlier check found still counts.
        view.update(problem=f'Its watch is installed but not running (systemd: {clean(live_state, 40)})',
                    next=command('sudo', 'systemctl', 'start', f'megalodon-{check}.service') if system
                    else command('systemctl', '--user', 'start', f'megalodon-{check}.service'))
    # What the listener or web-root watch saw since the last accept, kept beside the check's own result.
    seen = record.get('seen') if isinstance(record, dict) and isinstance(record.get('seen'), dict) else None
    if seen is not None and seen.get('error'):
        view['problem'] = f'What its watch saw cannot be read: {clean(seen["error"])}'
        seen = None
        if record.get('ran') is None and not record.get('error'):
            # Only the watch's log, and it cannot be trusted.
            view.update(status='error', status_text=view['problem'])
            return view
    if seen is not None and record.get('ran') is None:     # only the watch's log, or an untrusted result beside it
        # Only the watch's log, or a check result that cannot be trusted beside it: what the watch saw still counts.
        if record.get('error'):
            view['problem'] = f'Its last result cannot be trusted: {clean(record["error"])}'
        record = dict(check=check, at=seen.get('at'), ran=True, exit_code=0, findings=0,
                      result=dict(findings=[], gaps=[]), seen=seen, only_seen=True)
    if record is None and stopped:
        view.update(status='error', status_text=view['problem'])
        return view
    if record is None and live_state is not None:
        # The listener and web-root watches keep what they see as a result of their own (none yet, here); the others
        # pass it to the response engine, whose incidents follow.
        where = ('nothing seen since its last check or accept' if check in ('listeners', 'webroot')
                 else 'what it finds is in the incidents below')
        view.update(status='watching', status_text=f'Watching all the time; {where}'
                    if live_state == 'active' else 'Installed as a watch that runs all the time')
        return view
    if record is None:
        view.update(status='never_run', status_text='Has not run yet',
                    next=command('megalodon', check, 'check'))
        return view
    if record.get('error'):
        view.update(status='error', status_text=f'Its last result cannot be trusted: {clean(record["error"])}')
        return view
    view['last_run'] = record.get('at')
    age = _age(record.get('at'), now)
    interval = _interval(check)
    result = record.get('result') if isinstance(record.get('result'), dict) else {}
    gaps = result.get('gaps') if isinstance(result.get('gaps'), list) else []
    view['gaps'] = [readable(g) for g in gaps[:10]]
    findings = [f for f in result.get('findings', []) if isinstance(f, dict)]
    listed = len(findings)
    if check == 'persistence':
        # Entries already present at the baseline that carry an intruder's signs: the check exits 1 for them too.
        findings += [dict(f, change='suspicious') for f in result.get('suspicious', []) if isinstance(f, dict)]
    seen_extra, seen_unkept = 0, {}
    if seen is not None:
        # Each finding once: one the check also found reads the same without the watch's own stamps.
        known = {results.identity(f) for f in findings}
        kept = [f for f in seen.get('findings', []) if isinstance(f, dict)]
        findings += [f for f in kept if results.identity(f) not in known]
        seen_extra = max(0, seen.get('total', len(kept)) - len(kept))
        listed_seen = {}
        for f in kept:
            level = _severity(f.get('severity'))
            listed_seen[level] = listed_seen.get(level, 0) + 1
        for level, count in (seen.get('severities') or {}).items():
            if isinstance(count, int):
                listed_seen.setdefault(_severity(level), 0)
                seen_unkept[_severity(level)] = seen_unkept.get(_severity(level), 0) + count
        seen_unkept = {level: max(0, count - listed_seen.get(level, 0)) for level, count in seen_unkept.items()}
    if record.get('exit_code') == 1 and record.get('ran') and not findings:
        # The check said it found something (exit 1) that this report does not know how to list: never "nothing".
        findings = [dict(rule_id='CHECK_REPORTED_SOMETHING', severity='HIGH',
                         detail=f'megalodon {check} check exited 1 (findings) with nothing this report can list')]
    if not record.get('ran') or record.get('exit_code') not in (0, 1):
        reason = record.get('reason') if isinstance(record.get('reason'), str) else ''
        # A check without a baseline says which command records one; that, not running it again, is the fix.
        first = re.search(rf'; run megalodon {re.escape(check)} (baseline|learn)$', reason)
        problem = f'Could not run: {clean(reason, 300)}' if reason else 'Could not run the last time it was started'
        if findings:
            # It found something, then failed (an alert that could not be sent): the findings still count.
            problem = (f'Its last run found what follows, then failed: {clean(reason, 300)}' if reason
                       else 'Its last run found what follows, then failed')
        view.update(problem=problem if not stopped else f'{view["problem"]}; {problem[0].lower()}{problem[1:]}',
                    next=command('megalodon', check, first.group(1)) if first else command('megalodon', check, 'check'))
        if not findings:
            view.update(status='error', status_text=view['problem'])
            return view
    for finding in findings:
        rule = _rule(check, finding)
        where = _where(finding)
        detail = finding.get('detail') or finding.get('message') or finding.get('summary')
        view['findings'].append(dict(
            rule_id=clean(rule, 80), severity=_severity(finding.get('severity')),
            where=clean(where) if where else None, detail=readable(detail) if detail else None,
            meaning=_meaning(check, rule), choices=_choices(check, finding, rule, where)))
    view['findings'].sort(key=lambda f: RANK.index(f['severity']))
    # Every finding the check kept (a cut result keeps fewer than it found), and those added above.
    view['finding_count'] = max(record.get('findings', listed), listed) + len(findings) - listed + seen_extra
    # A live watch's log says when it saw something, not that a timer stopped.
    watched = seen is not None
    stale = not record.get('only_seen') and age is not None and interval and age > 3 * interval
    if view['findings']:
        worst = view['findings'][0]['severity']
        view.update(status='findings', worst=worst,
                    status_text=f'{"at least " if watched and seen.get("at_least") else ""}'
                                f'{view["finding_count"]} to review, the worst {worst.lower()}'
                    + (f' — its watch saw some, the last at {seen.get("at")}' if watched else ''))
    else:
        view.update(status='clean', status_text='Nothing found')
    if stale:
        view.update(stale=True, status_text=view['status_text'] + f' — but its last run was {_ago(age)} ago')
    if view.get('problem'):
        view['status_text'] += f' — {view["problem"][0].lower()}{view["problem"][1:]}'
    # Counted before only the first are kept for the page: the totals count every finding read, and for a result
    # too large to keep whole, every finding the check made.
    view['severities'] = {level: sum(1 for f in view['findings'] if f['severity'] == level) for level in RANK}
    for level, count in seen_unkept.items():
        view['severities'][level] += count
    saved = record.get('severities')
    if record.get('truncated') and isinstance(saved, dict):
        # The saved counts cover the check's `findings`; entries added above (suspicious ones) come on top.
        view['severities'] = dict.fromkeys(RANK, 0)
        for level, count in saved.items():
            if isinstance(count, int) and count > 0:
                view['severities'][_severity(level)] += count
        for finding in findings[listed:]:
            view['severities'][_severity(finding.get('severity'))] += 1
        for level, count in seen_unkept.items():
            view['severities'][level] += count
    kept = len(view['findings'])
    view['findings'] = view['findings'][:shown] if shown else view['findings']
    # Every finding counts; only the first are listed. Say how many more are kept (`report --all` lists them), and
    # how many were counted but not kept (a very large result keeps its first findings, a watch its latest).
    view['more'] = kept - len(view['findings'])
    view['not_kept'] = max(0, view.get('finding_count', 0) - kept)
    return view


def _ago(seconds):
    if seconds < 3600:
        return f'{int(seconds // 60)} minutes'
    if seconds < 172800:
        return f'{int(seconds // 3600)} hours'
    return f'{int(seconds // 86400)} days'


# ------------------------------------------------------------------ how the protection is set up

def _setup(system):
    from . import schedule
    rows = []
    units = schedule.unit_dir(system)
    installed = [j.name for j in schedule.JOBS
                 if any((units / name).exists() for name in schedule.units(j, ['m'], system))]
    wanted = [j.name for j in schedule.JOBS if system or not j.root_only]
    if installed:
        rows.append(dict(item='schedule', ok=True, text=f'{len(installed)} of {len(wanted)} jobs are installed',
                         fix=None))
    elif not schedule.has_systemd():
        # Without systemd the schedule is crontab lines you add yourself; whether you did cannot be seen here.
        rows.append(dict(item='schedule', ok=None,
                         text='Without systemd, the schedule is the crontab lines `megalodon schedule plan` prints; '
                              'whether they are added cannot be seen here. Each check says when it last ran.',
                         fix='megalodon schedule plan'))
    else:
        rows.append(dict(item='schedule', ok=False, text='No job is scheduled: checks run only when you start them',
                         fix='sudo megalodon schedule plan'))
    missing = []
    try:
        plan = schedule.plan(system=system, launcher=['megalodon'])
        missing = [(r['job'], r['baseline']) for r in plan['jobs'] if r['baseline']]
    except Exception as exc:        # noqa: BLE001 — the report says what it could not read
        rows.append(dict(item='baselines', ok=False, text=f'Could not read the schedule plan: {clean(exc)}'))
    else:
        rows.append(dict(item='baselines', ok=not missing,
                         text=('Every scheduled job has what it needs' if not missing else
                               f'{len(missing)} scheduled jobs need a baseline or setting up first: ' +
                               ', '.join(name for name, _ in missing[:8]) + ('…' if len(missing) > 8 else '')),
                         fix=None if not missing else _install_command()))
    rows.append(_alerts())
    response, digest = _response()
    rows.append(response)
    rows.append(_enforcement(digest))
    rows.append(_heartbeat())
    return rows


def _install_command():
    """The command that schedules the checks here: systemd installs them; without it, `plan` prints the crontab
    lines and baseline commands to run yourself (`install` refuses there)."""
    from . import schedule
    return ('sudo megalodon schedule install --yes --take-baselines' if schedule.has_systemd()
            else 'megalodon schedule plan')


# Each setting is read by the module that uses it, so the report says what that module will do with it.

def _response():
    from . import response_engine as engine
    path = Path(engine.DEFAULT_POLICY).expanduser()
    if not path.exists():
        return dict(item='response', ok=False, text='The response engine has no policy',
                    fix='megalodon respond init'), None
    try:
        policy = engine.load_policy(path)
    except (engine.ResponseError, OSError) as exc:
        return dict(item='response', ok=False, text=f'The response policy cannot be used, so nothing is decided: '
                                                     f'{clean(exc)}', fix='megalodon respond init --replace'), None
    return dict(item='response', ok=True, text='The response engine has a policy', fix=None), policy.digest


def _heartbeat():
    from . import tamper
    path = Path(tamper.DEFAULT_HEARTBEAT).expanduser()
    if not path.exists():
        return dict(item='heartbeat', ok=False, text='No heartbeat: if MEGALODON is stopped, no one is told',
                    fix='megalodon heartbeat init --url https://your-monitor.example/ping')
    try:
        tamper._read(path, tamper.HEARTBEAT_SCHEMA + '-config', 'heartbeat configuration')
    except (tamper.TamperError, OSError) as exc:
        return dict(item='heartbeat', ok=False, text=f'The heartbeat cannot be sent: {clean(exc)}',
                    fix='megalodon heartbeat init --replace --url https://your-monitor.example/ping')
    return dict(item='heartbeat', ok=True, text='A signed heartbeat goes off the machine, so silence is noticed',
                fix=None)


def _alerts():
    from .config import load_settings
    from .validation import ValidationError
    path = Path('~/.config/megalodon/settings.toml').expanduser()
    if not path.exists():
        return dict(item='alerts', ok=False, text='Alerts are off: findings stay on this machine',
                    fix='add an [alerts] section to ~/.config/megalodon/settings.toml (docs/off-machine-alerts.md)')
    try:
        alerts = load_settings(path).alerts
    except (ValidationError, OSError) as exc:
        return dict(item='alerts', ok=False, text=f'The settings file cannot be read, so no alert is sent: '
                                                   f'{clean(exc)}', fix='megalodon alerts test')
    if not getattr(alerts, 'enabled', False) or not getattr(alerts, 'destinations', ()):
        return dict(item='alerts', ok=False, text='Alerts are off: findings stay on this machine',
                    fix='turn on [alerts] in ~/.config/megalodon/settings.toml, then: megalodon alerts test')
    return dict(item='alerts', ok=True, text=f'Alerts go to {len(alerts.destinations)} destination(s)',
                fix='megalodon alerts test')


def _enforcement(response_digest=None):
    from . import enforcement
    path = Path(enforcement.DEFAULT_POLICY).expanduser()
    if not path.exists():
        return dict(item='enforcement', ok=None, text='Nothing is carried out automatically: decisions are only '
                                                      'recorded', fix='megalodon enforce init')
    try:
        policy = enforcement.load_policy(path)
    except (enforcement.EnforcementError, OSError) as exc:
        return dict(item='enforcement', ok=False, text=f'The enforcement policy cannot be used, so nothing is '
                                                        f'carried out: {clean(exc)}', fix='megalodon enforce init')
    if not policy['enabled'] or not policy['actions'] or not policy['playbooks']:
        return dict(item='enforcement', ok=None, text='Off: decisions are recorded and nothing is carried out '
                                                      'automatically. That is your choice to change.',
                    fix='edit ~/.config/megalodon/enforce.toml (docs/enforcement.md)')
    if response_digest != policy['digest']:
        # Enforcement acts only on decisions made under the response policy it pinned.
        return dict(item='enforcement', ok=False,
                    text='Enforcement is on, but the response policy is not the one it pinned, so nothing is carried '
                         'out. Review the response policy, then pin it again.',
                    fix='megalodon enforce init --replace')
    return dict(item='enforcement', ok=True,
                text=f'On for {", ".join(sorted(policy["actions"]))} in {len(policy["playbooks"])} '
                     f'playbook(s); each can be undone', fix='megalodon enforce list')


# ------------------------------------------------------------------ incidents

CAMPAIGN_MEANING = ('One address tried many different kinds of attack within minutes, faster and more widely than a '
                    'person at a keyboard does: an attack tool, or an AI agent driving one. `megalodon timeline show` '
                    'lists each attempt, in order.')
LOGIN_IN_CAMPAIGN = ' A login was part of the same incident: check whether the attacker got in.'
LURE_MEANING = ('Something read a note planted for automated agents (an agent lure) and tried the account or asked '
                'for the page it names, '
                'which no one else knows: the clearest sign MEGALODON has of an AI agent at work. '
                '`megalodon timeline show` says how soon after the note was read.')
AI_CAMPAIGN_MEANING = ('An AI-driven attack: one address tried many different kinds of attack within minutes, and it '
                       'followed a note planted for automated agents, trying the account or the page it names. '
                       '`megalodon timeline show` lists each attempt, in order.')
# What an incident is, listed before the findings it was made of, so the six shown never cut it off.
LEAD_RULES = ('AUTOMATED_CAMPAIGN', 'LURE_FOLLOWED')


def _incident_meaning(rules):
    """What an incident means in plain words, when its findings say more than their rule names do."""
    campaign, lured = 'AUTOMATED_CAMPAIGN' in rules, 'LURE_FOLLOWED' in rules
    if not (campaign or lured):
        return None
    from .login_watch import RULES as LOGIN_RULES
    meaning = AI_CAMPAIGN_MEANING if campaign and lured else CAMPAIGN_MEANING if campaign else LURE_MEANING
    return meaning + (LOGIN_IN_CAMPAIGN if any(r in LOGIN_RULES for r in rules) else '')


def _incidents(hours, now):
    from . import timeline
    try:
        found = timeline.incidents(hours=hours, now=now)['incidents']
    except Exception as exc:        # noqa: BLE001
        return [], f'Incidents could not be read: {clean(exc)}'
    rows = []
    for item in found[:15]:
        # A campaign is what the incident is: listed first, so it is never one of the rules cut off.
        rules = sorted(item.get('rules', []), key=lambda r: LEAD_RULES.index(r) if r in LEAD_RULES else len(LEAD_RULES))
        rows.append(dict(incident=clean(item['incident'], 40), severity=_severity(item['severity']),
                         first=item.get('first'), last=item.get('last'),
                         checks=[clean(s, 40) for s in item.get('sources', [])],
                         rules=[clean(r, 60) for r in rules[:6]], meaning=_incident_meaning(rules),
                         involved={clean(k, 20): [clean(v, 120) for v in values[:3]]
                                   for k, values in item.get('entities', {}).items()},
                         actions_applied=item.get('actions_applied', 0), undone=item.get('undone', 0),
                         choices=[_choice('look', 'See what happened, in order', 'megalodon', 'timeline', 'show',
                                          item['incident']),
                                  _choice('undo', 'See what was done, to undo it', 'megalodon', 'enforce', 'list',
                                          note='then: megalodon enforce undo ID')
                                  if item.get('actions_applied') else
                                  _choice('contain', 'See what the response engine would do', 'megalodon', 'enforce',
                                          'run', '--dry-run')]))
    return rows, None


# ------------------------------------------------------------------ the report

def build(*, hours=168, now=None, system=None, folder=None, runner=None, every=False):
    now = now or datetime.now(timezone.utc)
    from . import schedule
    system = schedule._system_mode(system)
    kept = results.latest(folder=folder)
    try:
        live = _live_states(system, runner)
    except (OSError, ValueError):
        live = {}
    checks = [_check_view(name, kept.get(name), now, live.get(name), system, None if every else SHOWN_PER_CHECK)
              for name in CHECKS]
    incidents, incident_gap = _incidents(hours, now)
    setup = _setup(system)
    counts = {level: sum(c.get('severities', {}).get(level, 0) for c in checks) for level in RANK}
    broken = [c for c in checks if c['status'] in ('error', 'never_run') or c.get('stale') or c.get('problem')]
    # A check that ran but could not look somewhere (an unmounted partition, processes it could not read) did not
    # see everything: that is not all clear.
    unseen = [c for c in checks if c.get('gaps') and c['status'] in ('clean', 'findings')]
    serious = counts['CRITICAL'] + counts['HIGH'] + sum(1 for i in incidents if i['severity'] in
                                                         ('CRITICAL', 'HIGH'))
    if serious:
        verdict, headline = 'act', 'Act now: there are serious findings to look at.'
    elif counts['MEDIUM'] or counts['LOW'] or counts['INFO'] or incidents:
        verdict, headline = 'review', 'Review: some findings need a look, none of them serious.'
    elif broken or incident_gap or unseen or any(r['ok'] is False for r in setup):
        verdict, headline = 'gaps', ('Nothing found, but parts of the protection are not running, or could not look '
                                     'everywhere.')
    else:
        verdict, headline = 'clear', 'All clear: every check ran and found nothing.'
    steps = []
    for check in sorted((c for c in checks if c['findings']), key=lambda c: RANK.index(c['findings'][0]['severity'])):
        first = check['findings'][0]
        steps.append(dict(text=f'{check["title"]}: {first["meaning"] or first["rule_id"]}',
                          command=first['choices'][0]['command']))
    for row in setup:
        if row['ok'] is False and row.get('fix'):
            steps.append(dict(text=row['text'], command=row['fix']))
    for check in unseen:
        shown = '; '.join(check['gaps'][:3]) + ('…' if len(check['gaps']) > 3 else '')
        steps.append(dict(text=f'{check["title"]}: could not look at everything: {shown}',
                          command=check.get('next') or command('megalodon', check['check'], 'check')))
    if incident_gap:
        # The incidents are where the live watches report: unread, they may hide what the watches found.
        steps.append(dict(text=incident_gap, command=command('megalodon', 'timeline', 'list')))
    never = [c for c in checks if c['status'] == 'never_run']
    if never:
        steps.append(dict(text=f'{len(never)} checks have not run yet ('
                               f'{", ".join(c["title"].lower() for c in never[:4])}{"…" if len(never) > 4 else ""}): '
                               'schedule them, or run one by hand',
                          command=_install_command()))
    for check in broken:
        if check['status'] == 'error' or check.get('stale') or check.get('problem'):
            steps.append(dict(text=f'{check["title"]}: {check["status_text"]}',
                              command=check.get('next') or command('megalodon', check['check'], 'check')))
    return dict(schema=SCHEMA, generated_at=now.strftime('%Y-%m-%dT%H:%M:%SZ'),
                host=clean(os.uname().nodename, 80), account='root' if system else 'user',
                verdict=verdict, headline=headline, counts=counts, next_steps=steps[:12],
                checks=checks, incidents=incidents, incident_gap=incident_gap, setup=setup,
                coverage=dict(checks=len(checks),
                              ran=sum(1 for c in checks if c['status'] in ('clean', 'findings', 'watching')),
                              never_run=sum(1 for c in checks if c['status'] == 'never_run'),
                              errors=sum(1 for c in checks if c['status'] == 'error' or c.get('problem')),
                              stale=sum(1 for c in checks if c.get('stale'))))


# ------------------------------------------------------------------ text

def text(report):
    marks = dict(clean='ok', findings='!!', error='XX', never_run='--', watching='ok')
    # Status words shown on the page.
    out = [f'MEGALODON security report for {report["host"]} — {report["generated_at"]}', '',
           report['headline'], '']
    counts = ', '.join(f'{n} {level.lower()}' for level, n in report['counts'].items() if n) or 'no findings'
    cov = report['coverage']
    out.append(f'Findings: {counts}. Checks: {cov["ran"]} of {cov["checks"]} are running or have results'
               + (f', {cov["errors"]} could not run' if cov['errors'] else '')
               + (f', {cov["stale"]} out of date' if cov['stale'] else '') + '.')
    if report['next_steps']:
        out += ['', 'What to do next:']
        for i, step in enumerate(report['next_steps'], 1):
            out += [f'  {i}. {step["text"]}', f'       {step["command"]}']
    for group in GROUPS:
        out += ['', group.upper()]
        for check in (c for c in report['checks'] if c['group'] == group):
            out.append(f'  [{marks.get(check["status"], "??")}] {check["title"]}: {check["status_text"]}')
            for finding in check['findings']:
                where = f' — {finding["where"]}' if finding['where'] else ''
                out.append(f'       {finding["severity"]:<8} {finding["rule_id"]}{where}')
                if finding['meaning']:
                    out.append(f'                {finding["meaning"]}')
                for choice in finding['choices']:
                    out.append(f'                · {choice["label"]}: {choice["command"]}')
            if check.get('more'):
                out.append(f'       …and {check["more"]} more: {ALL_FINDINGS}')
            if check.get('not_kept'):
                out.append(f'       …and {check["not_kept"]} more that were counted but not kept')
            if check.get('gaps'):
                out.append(f'       Could not see: {"; ".join(check["gaps"])}')
    if report['incidents'] or report['incident_gap']:
        out += ['', 'INCIDENTS (findings the response engine joined, last week)']
        if report['incident_gap']:
            out.append(f'  {report["incident_gap"]}')
        for item in report['incidents']:
            done = f', {item["actions_applied"]} action(s) carried out' if item['actions_applied'] else ''
            out.append(f'  {item["severity"]:<8} {item["incident"]}: {", ".join(item["rules"])} '
                       f'(seen by {", ".join(item["checks"])}){done}')
            if item.get('meaning'):
                out.append(f'           {item["meaning"]}')
            for choice in item['choices']:
                out.append(f'                · {choice["label"]}: {choice["command"]}')
    out += ['', 'HOW YOU ARE PROTECTED']
    for row in report['setup']:
        mark = 'ok' if row['ok'] else ('--' if row['ok'] is None else 'XX')
        fix = f' — {row["fix"]}' if row.get('fix') and row['ok'] is not True else ''
        out.append(f'  [{mark}] {row["text"]}{fix}')
    out += ['', 'Nothing in this report was carried out. Each command above is yours to run, or not.']
    return '\n'.join(out) + '\n'


# ------------------------------------------------------------------ HTML

PAGE_STYLE = '''
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1f;--soft:#5b5b63;--line:#e3e3e0;--crit:#b3261e;--high:#c2410c;
--med:#a16207;--low:#4b5563;--ok:#15803d;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d21;--ink:#ececf0;--soft:#a3a3ad;--line:#2e2e34;
--crit:#f2b8b5;--high:#fdba74;--med:#fcd34d;--low:#cbd5e1;--ok:#86efac;--code:#26262c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:32px 0 12px}p{margin:6px 0}.soft{color:var(--soft)}
.verdict{border-radius:12px;padding:18px 20px;margin:16px 0;background:var(--card);border:1px solid var(--line);
border-left:6px solid var(--ok)}.verdict.act{border-left-color:var(--crit)}.verdict.review{border-left-color:var(--med)}
.verdict.gaps{border-left-color:var(--high)}.verdict strong{font-size:1.15rem}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.pill{border-radius:999px;padding:2px 10px;font-size:.85rem;
border:1px solid var(--line)}.CRITICAL{color:var(--crit)}.HIGH{color:var(--high)}.MEDIUM{color:var(--med)}
.LOW,.INFO{color:var(--low)}ol{padding-left:22px}li{margin:6px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:8px 0}
details>summary{cursor:pointer;padding:12px 14px;list-style:none;display:flex;gap:10px;align-items:baseline}
details>summary::-webkit-details-marker{display:none}.status{font-size:.8rem;font-weight:600;min-width:5.5em}
.s-clean,.s-watching{color:var(--ok)}.s-findings{color:var(--high)}.s-error{color:var(--crit)}.s-never_run{color:var(--soft)}
.body{padding:0 14px 12px}.finding{border-top:1px solid var(--line);padding:10px 0}.sev{font-weight:700;font-size:.8rem}
code{background:var(--code);border-radius:5px;padding:1px 5px;font-size:.85rem;word-break:break-all}
.choice{margin:4px 0 4px 2px}.choice .label{color:var(--soft)}table{border-collapse:collapse;width:100%}
td{padding:8px 6px;border-top:1px solid var(--line);vertical-align:top}.mark{font-weight:700;width:2.5em}
footer{margin-top:40px;color:var(--soft);font-size:.9rem}
'''


def _e(value):
    return html.escape(str(value), quote=True)


def _choice_html(choice):
    note = f' <span class="soft">({_e(choice["note"])})</span>' if choice.get('note') else ''
    return (f'<div class="choice"><span class="label">{_e(choice["label"])}:</span> '
            f'<code>{_e(choice["command"])}</code>{note}</div>')


def page(report):
    counts = ''.join(f'<span class="pill {level}">{n} {level.lower()}</span>'
                     for level, n in report['counts'].items() if n) or '<span class="pill">no findings</span>'
    steps = ''.join(f'<li>{_e(step["text"])}<br><code>{_e(step["command"])}</code></li>'
                    for step in report['next_steps'])
    groups = []
    for group in GROUPS:
        cards = []
        for check in (c for c in report['checks'] if c['group'] == group):
            findings = []
            for f in check['findings']:
                where = f' — <code>{_e(f["where"])}</code>' if f['where'] else ''
                meaning = f'<p>{_e(f["meaning"])}</p>' if f['meaning'] else ''
                detail = f'<p class="soft">{_e(f["detail"])}</p>' if f['detail'] else ''
                findings.append(f'<div class="finding"><span class="sev {f["severity"]}">{f["severity"]}</span> '
                                f'{_e(f["rule_id"])}{where}{meaning}{detail}'
                                + ''.join(_choice_html(c) for c in f['choices']) + '</div>')
            if check.get('more'):
                findings.append(f'<p class="soft">…and {check["more"]} more: <code>{_e(ALL_FINDINGS)}</code></p>')
            if check.get('not_kept'):
                findings.append(f'<p class="soft">…and {check["not_kept"]} more that were counted but not kept</p>')
            extra = (f'<p class="soft">Could not see: {_e("; ".join(check["gaps"]))}</p>' if check['gaps'] else '')
            run = f'<p class="soft">Last run {_e(check["last_run"])} UTC</p>' if check.get('last_run') else ''
            nxt = f'<p>Run it: <code>{_e(check["next"])}</code></p>' if check.get('next') else ''
            open_ = ' open' if check['status'] in ('findings', 'error') else ''
            cards.append(f'<div class="card"><details{open_}><summary><span class="status s-{check["status"]}">'
                         f'{_e(STATUS_WORDS[check["status"]])}</span><span><strong>{_e(check["title"])}'
                         f'</strong> — {_e(check["status_text"])}</span></summary><div class="body">'
                         f'<p class="soft">{_e(check["why"])}</p>{run}{nxt}{extra}{"".join(findings)}</div>'
                         f'</details></div>')
        groups.append(f'<h2>{_e(group)}</h2>' + ''.join(cards))
    incidents = ''
    if report['incidents'] or report['incident_gap']:
        rows = ''.join(
            f'<div class="card"><div class="body" style="padding-top:12px"><span class="sev {i["severity"]}">'
            f'{i["severity"]}</span> <strong>{_e(", ".join(i["rules"]))}</strong> '
            f'<span class="soft">— seen by {_e(", ".join(i["checks"]))}, {_e(i["first"])} to {_e(i["last"])}'
            + (f', {i["actions_applied"]} action(s) carried out' if i['actions_applied'] else '') + '</span>'
            + (f'<p>{_e(i["meaning"])}</p>' if i.get('meaning') else '')
            + ''.join(_choice_html(c) for c in i['choices']) + '</div></div>' for i in report['incidents'])
        gap = f'<p class="soft">{_e(report["incident_gap"])}</p>' if report['incident_gap'] else ''
        incidents = '<h2>Incidents: findings joined into one story, last week</h2>' + gap + rows
    setup = ''.join(
        f'<tr><td class="mark {"s-clean" if r["ok"] else ("s-never_run" if r["ok"] is None else "s-error")}">'
        f'{"ok" if r["ok"] else ("—" if r["ok"] is None else "!")}</td><td>{_e(r["text"])}'
        + (f'<br><code>{_e(r["fix"])}</code>' if r.get('fix') and r['ok'] is not True else '') + '</td></tr>'
        for r in report['setup'])
    cov = report['coverage']
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
            f'<title>Security report — {_e(report["host"])}</title><style>{PAGE_STYLE}</style></head><body><main>'
            f'<h1>Security report</h1><p class="soft">{_e(report["host"])} · {_e(report["generated_at"])} UTC · '
            f'{cov["ran"]} of {cov["checks"]} checks running or with results</p>'
            f'<div class="verdict {report["verdict"]}"><strong>{_e(report["headline"])}</strong>'
            f'<div class="counts">{counts}</div></div>'
            + (f'<h2>What to do next</h2><ol>{steps}</ol>' if steps else '')
            + ''.join(groups) + incidents
            + f'<h2>How you are protected</h2><div class="card"><table>{setup}</table></div>'
            f'<footer>Nothing in this report was carried out. Each command is yours to run, or not. Everything a '
            f'finding names can be chosen by an attacker: read commands before running them.</footer>'
            f'</main></body></html>\n')


def write(path, content):
    """Write the report privately (mode 600): it names programs, files and addresses on this machine."""
    from .timeline import write_private
    return write_private(Path(path).expanduser(), content)
