"""End-to-end self-test of MEGALODON's detections, run in throwaway places.

``megalodon drill`` proves that each detection layer still fires on this
machine and version, instead of assuming it does. Each check reuses
MEGALODON's own built-in sample or self-test, and runs in a temporary folder:

* **network**: the built-in demo sample (``run --source sample --demo-threat``)
  runs through the real service into a temporary audit store. Its core and
  threat-signal findings must fire and be recorded.
* **canary**: a bait file is planted, then changed, and ``check`` must report it.
* **ransomware** (Linux): the ransomware self-test encrypts throwaway files
  under a real inotify watch.
* **persistence**: a throwaway folder tree is baselined, then given a new
  comment-only cron file and an extra comment line in a shell startup file.
* **listeners** (Linux): this machine's listeners are baselined into a
  temporary manifest, then the drill listens on a loopback port of its own.
* **alerts** (with ``--alerts``): one labeled test notice goes to each
  configured destination.

The real audit database, canaries, watched folders, baselines and system
files are never touched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
import sys
import tempfile
import time

SCHEMA = 'megalodon-drill-v1'
NETWORK_RULES = ['BEACONING', 'BRUTE_FORCE', 'DATA_EXFILTRATION', 'DNS_TUNNELING', 'HOST_SWEEP', 'SYN_FLOOD']


@dataclass
class Check:
    name: str
    expected: list[str]
    observed: list[str] = field(default_factory=list)
    status: str = 'failed'  # passed, failed or skipped
    detail: str = ''
    seconds: float = 0.0

    def to_dict(self):
        return dict(name=self.name, status=self.status, expected=self.expected, observed=self.observed,
                    missing=sorted(set(self.expected) - set(self.observed)), detail=self.detail,
                    seconds=round(self.seconds, 2))


def _network(work):
    from .capture import iter_sample
    from .config import Settings
    from .service import MegalodonService
    from .storage import Store
    settings = Settings(db_path=work / 'drill.db')
    found = set()
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        count = 0
        for event in iter_sample(include_demo_threat=True):
            found.update(item.rule_id for item in service.process(event))
            count += 1
    with sqlite3.connect(settings.db_path) as connection:
        stored = {row[0] for row in connection.execute('SELECT DISTINCT rule_id FROM detections')}
    missing_from_store = sorted(found - stored)
    detail = f'{count} sample events; findings recorded in a temporary store'
    if missing_from_store:
        detail += f'; not recorded: {", ".join(missing_from_store)}'
    return sorted(found & stored), detail


def _canary(work):
    from . import canary
    bait = work / 'bait'
    bait.mkdir(mode=0o700)
    manifest = work / 'canary.json'
    planted = canary.plant(str(bait), str(manifest), count=1)
    path = Path(planted['canaries'][0]['path'] if 'canaries' in planted else next(bait.iterdir()))
    with open(path, 'a', encoding='utf-8') as out:
        out.write('\n')
    result = canary.check(str(manifest))
    return sorted({item['rule_id'] for item in result['findings']}), 'one canary planted, then changed'


def _ransomware(work):
    from . import ransomware_watch
    found = ransomware_watch.selftest(str(work / 'files'))
    return sorted({item.rule_id for item in found}), 'throwaway files encrypted under a live inotify watch'


def _persistence(work):
    from . import persistence_watch
    root, home = work / 'root', work / 'home'
    for path, text in ((root / 'etc/passwd', 'root:x:0:0:root:/root:/bin/sh\n'),
                       (root / 'etc/crontab', '# crontab\n'), (home / '.profile', '# profile\n')):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
    options = dict(root=str(root), home=str(home), setuid_dirs=())
    manifest = work / 'persistence.json'
    persistence_watch.baseline(manifest, **options)
    (root / 'etc/cron.d').mkdir()
    (root / 'etc/cron.d/drill').write_text('# MEGALODON drill\n', encoding='utf-8')
    with open(home / '.profile', 'a', encoding='utf-8') as out:
        out.write('# MEGALODON drill\n')
    report = persistence_watch.check(manifest, **options)
    return sorted({item['category'] for item in report['findings']}), 'throwaway tree: new cron file, edited profile'


def _listeners(work):
    import socket

    from . import listener_watch
    manifest = work / 'listeners.json'
    listener_watch.baseline(manifest)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        probe.listen(1)
        port = probe.getsockname()[1]
        report = listener_watch.check(manifest)
    ours = sorted({f['rule_id'] for f in report['findings'] if f['port'] == port and f['protocol'] == 'tcp'})
    return ours, f'a throwaway loopback listener on port {port}'


def _alerts(settings):
    from .alerts import test_destinations
    results = test_destinations(settings)
    failed = sorted(name for name, item in results.items() if not item['ok'])
    return sorted(name for name, item in results.items() if item['ok']), (
        f'failed: {", ".join(failed)}' if failed else 'a labeled test notice reached every destination')


def run(*, alert_settings=None):
    """Run every check; returns the drill report."""
    checks = [
        ('network', NETWORK_RULES, _network),
        ('canary', ['CANARY_MODIFIED'], _canary),
        ('ransomware', ['RANSOMWARE_ENCRYPTION', 'RANSOM_NOTE'], _ransomware),
        ('persistence', ['cron', 'shell_startup'], _persistence),
        ('listeners', ['NEW_LISTENER'], _listeners),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix='megalodon-drill-') as base:
        for name, expected, function in checks:
            check = Check(name, expected)
            started = time.monotonic()
            if name in ('ransomware', 'listeners') and not sys.platform.startswith('linux'):
                check.status, check.detail = 'skipped', 'needs Linux'
            else:
                work = Path(base) / name
                work.mkdir(mode=0o700)
                try:
                    check.observed, check.detail = function(work)
                    check.status = 'passed' if set(expected) <= set(check.observed) else 'failed'
                except Exception as exc:  # A drill reports a broken layer instead of stopping.
                    check.detail = f'{type(exc).__name__}: {exc}'[:300]
            check.seconds = time.monotonic() - started
            results.append(check)
    alerts = Check('alerts', [])
    if alert_settings is None:
        alerts.status, alerts.detail = 'skipped', 'not requested (use --alerts)'
    elif not alert_settings.destinations:
        alerts.status, alerts.detail = 'skipped', 'no [[alerts.destination]] is configured'
    else:
        alerts.expected = sorted(d.name for d in alert_settings.destinations)
        started = time.monotonic()
        try:
            alerts.observed, alerts.detail = _alerts(alert_settings)
            alerts.status = 'passed' if set(alerts.expected) <= set(alerts.observed) else 'failed'
        except Exception as exc:
            alerts.detail = f'{type(exc).__name__}: {exc}'[:300]
        alerts.seconds = time.monotonic() - started
    results.append(alerts)
    counts = {status: sum(1 for c in results if c.status == status) for status in ('passed', 'failed', 'skipped')}
    return dict(schema=SCHEMA, checks=[c.to_dict() for c in results], **counts,
                note='Synthetic data in temporary folders only; nothing real was changed.')
