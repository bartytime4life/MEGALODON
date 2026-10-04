"""Prepare a read-only removal review; this module has no applying mode."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

from . import local_install, uninstall_audit

SCHEMA = 'megalodon-uninstall-plan-v1'
# Firewall removal remains a separate host-protection decision.
PACKAGE_CHOICES = tuple(name for name in uninstall_audit.APT_PACKAGES if name != 'nftables')
MAX_OUTPUT_BYTES = 64 * 1024
PREVIEW_TIMEOUT = 30
MAX_REMOVALS = 256
_PACKAGE = r'[a-z0-9][a-z0-9+.-]{0,127}(?::[a-z0-9][a-z0-9-]{0,31})?'
_REMOVAL = re.compile(rf'Remv ({_PACKAGE})(?: \[[^\r\n\x00-\x1f\x7f]{{1,256}}\])?(?: \[\])?')
_SUMMARY = re.compile(r'0 upgraded, 0 newly installed, ([0-9]{1,6}) to remove and [0-9]+ not upgraded\.')


def _selected_packages(packages: tuple[str, ...]) -> tuple[str, ...]:
    if (not isinstance(packages, (tuple, list)) or len(packages) > len(PACKAGE_CHOICES)
            or any(type(name) is not str or name not in PACKAGE_CHOICES for name in packages)
            or len(set(packages)) != len(packages)):
        raise ValueError('select each supported companion package at most once')
    return tuple(sorted(packages))


def _simulate(packages: tuple[str, ...]) -> tuple[int, str]:
    """Fixed apt simulation, bounded while reading, with no inherited overrides."""
    argv = ['/usr/bin/apt-get', '--simulate', '--no-download', '--no-install-recommends',
            '-o', 'APT::Get::AutomaticRemove=false', '-o', 'APT::Get::Purge=false',
            '-o', 'APT::Color=false', 'remove', '--', *packages]
    deadline = time.monotonic() + PREVIEW_TIMEOUT
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, cwd='/',
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}) as process:
        output = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('simulation timed out')
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), min(4096, MAX_OUTPUT_BYTES + 1 - len(output)))
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            if len(output) > MAX_OUTPUT_BYTES:
                                raise ValueError('simulation output exceeded its limit')
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            return code, output.decode('utf-8')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


def _parse_simulation(output: str) -> list[str]:
    """Require a complete removal-only transaction; never infer from a partial log."""
    if not output or len(output.encode('utf-8')) > MAX_OUTPUT_BYTES:
        raise ValueError('simulation output is empty or too large')
    if any((ord(char) < 32 and char not in '\n\t') or ord(char) == 127 for char in output):
        raise ValueError('simulation output contains unexpected controls')
    removals: list[str] = []
    summaries: list[int] = []
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith(('Inst ', 'Conf ', 'Purg ', 'E:', 'W:')):
            raise ValueError('simulation is not a clean removal-only transaction')
        if line.startswith('Remv'):
            match = _REMOVAL.fullmatch(line)
            if match is None or match[1] in removals or len(removals) >= MAX_REMOVALS:
                raise ValueError('simulation removal records are malformed or incomplete')
            removals.append(match[1])
        if match := _SUMMARY.fullmatch(line):
            summaries.append(int(match[1]))
    if summaries != [len(removals)]:
        raise ValueError('simulation totals do not match its removal records')
    return sorted(removals)


def package_preview(packages: tuple[str, ...] = ()) -> dict[str, object]:
    selected = _selected_packages(packages)
    result = {'selected': list(selected), 'state': 'not_selected', 'removals': [],
              'protected': [], 'additional': [], 'issues': []}
    if not selected:
        return result
    if sys.platform != 'linux' or os.geteuid() == 0:
        return {**result, 'state': 'unavailable', 'issues': ['requires_non_root_linux_user']}
    try:
        code, output = _simulate(selected)
        if code:
            raise ValueError('simulation returned an error')
        removed = _parse_simulation(output)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {**result, 'state': 'unavailable', 'issues': ['simulation_failed_or_incomplete']}
    # Every unselected dependency is held, including dependencies of Python/Git.
    protected = [name for name in removed if name.split(':')[0].startswith(
        ('python', 'libpython', 'pypy', 'git', 'libgit', 'nftables', 'iptables', 'ufw', 'firewalld'))]
    additional = [name for name in removed if name.split(':')[0] not in selected]
    issues = []
    if protected:
        issues.append('protected_package_removal')
    if additional:
        issues.append('unselected_dependency_removal')
    return {**result, 'state': 'blocked' if issues else 'reviewable', 'removals': removed,
            'protected': protected, 'additional': additional, 'issues': issues}


def _file_item(label: str, entry: dict[str, object], requested: bool) -> dict[str, object]:
    state = entry['state']
    disposition = 'candidate' if requested else 'preserve'
    if state == 'absent':
        disposition = 'absent'
    elif state not in {'file', 'directory'} or entry['owner_current_user'] is not True:
        disposition = 'preserve_for_review'
    if disposition == 'candidate':
        path = Path(entry['path'])
        try:
            local_install._validate_directory_chain(path if state == 'directory' else path.parent)
        except (local_install.InstallError, OSError):
            disposition = 'preserve_for_review'
    return {'name': label, **entry, 'disposition': disposition}


def plan(*, packages: tuple[str, ...] = (), include_saved_data: bool = False,
         paths: local_install.InstallPaths | None = None, home: Path | None = None) -> dict[str, object]:
    """Collect fresh observations; no saved report can authorize an operation."""
    selected_packages = _selected_packages(packages)
    if type(include_saved_data) is not bool:
        raise ValueError('include_saved_data must be a boolean')
    selected = paths or local_install.install_paths()
    inventory = uninstall_audit.audit(selected, home=home)
    files = []
    issues = ['full_removal_not_implemented', 'running_work_not_checked',
              'directory_contents_not_scanned', 'external_backups_not_scanned',
              'prior_host_settings_not_recorded']
    try:
        manifest = local_install._load_manifest(selected)
    except (local_install.InstallError, OSError):
        manifest = None
    if manifest is None:
        issues.append('managed_code_manifest_unavailable')
    else:
        for release in manifest['releases']:
            path = selected.releases / release['id']
            files.append(_file_item('managed_release', uninstall_audit._entry(path), True))
        # current is intentionally a symlink: report it separately, never follow it.
        files.append({'name': 'release_selector', **uninstall_audit._entry(selected.current),
                      'disposition': 'preserve_for_review'})
    saved_names = {'data', 'config', 'fixed_support_data', 'fixed_support_config', 'wireshark_profile'}
    for name, entry in inventory['artifacts'].items():
        # Password/settings files are covered by config; an app root is not proof
        # that every child was created by MEGALODON, so never select it recursively.
        if name in {'settings', 'hud_password'}:
            continue
        requested = include_saved_data if name in saved_names else manifest is not None and name != 'app'
        item = _file_item(name, entry, requested)
        health = inventory['installed_hud'].get('artifacts', {}).get(name)
        if health is not None:
            item['installed_artifact_status'] = health
            if health not in {'ready', 'missing'}:
                item['disposition'] = 'preserve_for_review'
        if name == 'app' and entry['state'] != 'absent':
            item['disposition'] = 'preserve_for_review'
        files.append(item)
    companions = [dict(entry, name='private_zeek', disposition='preserve_for_review')
                  for entry in inventory['private_zeek_candidates']]
    companions.extend({'name': name, 'path': path, 'disposition': 'preserve_for_review'}
                      for name, path in inventory['selected_tool_directories'].items())
    preview = package_preview(selected_packages)
    issues.extend(preview['issues'])
    if selected_packages:
        issues.append('package_ownership_not_recorded')
    if any(inventory['apt_package_presence'].get(name) not in {'installed', 'not_installed'}
           for name in selected_packages):
        issues.append('selected_package_presence_unknown')
    if inventory['private_zeek_scan_state'] != 'complete' or inventory['tool_directory_profile'] != 'readable':
        issues.append('companion_inventory_incomplete')
    return {
        'schema': SCHEMA, 'checked_at': inventory['checked_at'], 'mode': 'read_only',
        'state': 'review_required', 'execution_available': False,
        'scope': {'managed_code': True, 'include_saved_data': include_saved_data,
                  'packages': list(selected_packages), 'shared_models': 'preserve',
                  'external_backups': 'preserve', 'host_firewall': 'preserve'},
        'installed_hud': inventory['installed_hud'], 'files': files,
        'companions_for_review': companions, 'package_preview': preview,
        'private_zeek_scan_state': inventory['private_zeek_scan_state'],
        'tool_directory_profile': inventory['tool_directory_profile'],
        'apt_package_presence': inventory['apt_package_presence'],
        'other_executables_in_path': inventory['other_executables_in_path'],
        'preserve_packages': ['python3', 'git'], 'dumpcap_current': inventory['dumpcap_current'],
        'issues': issues,
        'limits': ['Candidate paths require ownership, content and live-service review before removal.',
                   'Apt simulation is unlocked and non-root; it is not a future execution guarantee.',
                   'No purge or autoremove is proposed; package settings and other leftovers may remain.',
                   'Rerun the inventory after any separately authorized removal; absence here is not a whole-PC scan.'],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Prepare a read-only MEGALODON removal review. Nothing is deleted.')
    parser.add_argument('--package', choices=PACKAGE_CHOICES, action='append', default=[],
                        help='include one companion in a combined apt removal simulation; repeat to select more')
    parser.add_argument('--include-saved-data', action='store_true',
                        help='list known saved-data/settings directories as candidates for review, without reading contents')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = plan(packages=tuple(args.package), include_saved_data=args.include_saved_data)
    except (ValueError, OSError):
        print('Removal review unavailable; check the selected packages and local installation paths.', file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print('MEGALODON removal review — read-only; execution unavailable')
        for entry in result['files'] + result['companions_for_review']:
            print(f"{entry['disposition']}: {entry['name']} — {json.dumps(entry['path'])}")
        preview = result['package_preview']
        print('Package simulation: ' + preview['state'])
        print('Selected packages: ' + (', '.join(preview['selected']) or 'none'))
        print('Would remove: ' + (', '.join(preview['removals']) or 'none reported; see simulation state'))
        for issue in result['issues']:
            print('Review: ' + issue)
        print('Python, Git, shared models, external backups and firewall settings are preservation requirements.')
        for limit in result['limits']:
            print(limit)
    # A complete report remains a review, never an authorization or apply success.
    return 0 if result['package_preview']['state'] in {'not_selected', 'reviewable'} else 2


if __name__ == '__main__':
    raise SystemExit(main())
