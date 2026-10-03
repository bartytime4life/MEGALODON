"""Read-only inventory for a future full uninstall of this user's local HUD.

Presence never proves MEGALODON installed or owns a companion package. This
module deliberately has no remove, service, privilege or network operation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
from itertools import islice
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

from .hud_autostart import unit_path
from .local_install import InstallError, InstallPaths, install_paths, status as local_status
from .tool_locations import load_directories

SCHEMA = 'megalodon-full-uninstall-audit-v1'
APT_PACKAGES = ('tshark', 'wireshark', 'wireshark-common', 'suricata', 'nftables', 'clamav', 'nmap', 'osquery')
OTHER_EXECUTABLES = {'zeek': 'zeek', 'ollama': 'ollama', 'osquery': 'osqueryi'}


def _entry(path: Path) -> dict[str, object]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'state': 'absent', 'owner_current_user': None}
    except OSError:
        return {'path': str(path), 'state': 'unavailable', 'owner_current_user': None}
    kind = ('symlink' if stat.S_ISLNK(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode)
            else 'file' if stat.S_ISREG(info.st_mode) else 'other')
    return {'path': str(path), 'state': kind, 'owner_current_user': info.st_uid == os.geteuid()}


def _package_status() -> dict[str, str]:
    """Query only fixed package names; unavailable is never interpreted as absent."""
    result = {name: 'unknown' for name in APT_PACKAGES}
    if sys.platform != 'linux':
        return result
    try:
        probe = subprocess.run(
            ['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Status}\n', *APT_PACKAGES],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if len(probe.stdout) > 8192:
            return result
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return result
    for line in probe.stdout.splitlines():
        name, separator, status = line.partition('\t')
        if separator and name in result:
            result[name] = 'installed' if status == 'install ok installed' else 'not_installed'
    return result


def _dumpcap_state(path: Path = Path('/usr/bin/dumpcap')) -> dict[str, object]:
    """Observe current metadata only; it cannot reconstruct prior settings."""
    result = _entry(path)
    result['mode'] = None
    result['capability_xattr'] = 'unknown'
    result['acl_xattr'] = 'unknown'
    if result['state'] != 'file':
        return result
    try:
        result['mode'] = oct(stat.S_IMODE(path.lstat().st_mode))
        for key, label in (('security.capability', 'capability_xattr'),
                           ('system.posix_acl_access', 'acl_xattr')):
            try:
                result[label] = 'present' if os.getxattr(path, key, follow_symlinks=False) else 'absent'
            except OSError as exc:
                result[label] = 'absent' if exc.errno == errno.ENODATA else 'unknown'
    except OSError:
        pass
    return result


def audit(paths: InstallPaths | None = None, *, home: Path | None = None) -> dict[str, object]:
    """Inventory known surfaces without reading evidence or changing the host."""
    selected = paths or install_paths()
    home = Path.home() if home is None else Path(home)
    artifacts = {name: _entry(getattr(selected, name)) for name in (
        'app', 'manifest', 'data', 'config', 'settings', 'hud_password',
        'hud_launcher', 'manager_launcher', 'desktop_entry', 'icon',
    )}
    artifacts['hud_user_service'] = _entry(unit_path(selected))
    artifacts['wireshark_profile'] = _entry(home / '.config/wireshark/profiles/MEGALODON')
    try:
        selected_tools = load_directories(home)
        profile_state = 'readable'
    except ValueError:
        selected_tools = {}
        profile_state = 'needs_review'
    private_zeek = []
    zeek_scan_state = 'complete'
    try:
        candidates = list(islice((home / '.local').iterdir(), 513))
        if len(candidates) > 512:
            zeek_scan_state = 'limited'
        for path in sorted(candidates[:512], key=lambda item: item.name):
            if path.name.startswith('zeek-'):
                private_zeek.append(_entry(path))
    except (FileNotFoundError, PermissionError, OSError):
        zeek_scan_state = 'unavailable'
    try:
        _, installed_hud = local_status(selected)
    except (InstallError, OSError):
        installed_hud = {'status': 'needs_review'}
    return {
        'schema': SCHEMA,
        'checked_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'mode': 'read_only',
        'installed_hud': installed_hud,
        'artifacts': artifacts,
        'private_zeek_candidates': private_zeek[:32],
        'private_zeek_scan_state': zeek_scan_state,
        'selected_tool_directories': selected_tools,
        'tool_directory_profile': profile_state,
        'apt_package_presence': _package_status(),
        'other_executables_in_path': {tool: shutil.which(binary) for tool, binary in OTHER_EXECUTABLES.items()},
        'dumpcap_current': _dumpcap_state(),
        'preserve_packages': ['python3', 'git'],
        'unresolved': [
            'Package presence does not prove MEGALODON installed the package.',
            'The prior dumpcap capabilities, ACL and mode were not recorded; exact reversal cannot be inferred.',
            'Saved databases and backups outside managed paths require owner-supplied locations.',
            'Selected tool directories and private Zeek prefixes are candidates, not proven MEGALODON-owned files.',
            'Running services, package dependencies and host firewall state require separate review before removal.',
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Read-only MEGALODON full-uninstall inventory; no removal is available.')
    parser.add_argument('--json', action='store_true', help='print the bounded inventory as JSON')
    args = parser.parse_args(argv)
    result = audit()
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print('MEGALODON full-uninstall audit (read-only)')
        print('Installed HUD status: ' + result['installed_hud']['status'])
        for name, entry in result['artifacts'].items():
            print(f"{name}: {entry['state']} — {entry['path']}")
        for name, state in result['apt_package_presence'].items():
            print(f'{name}: {state} (ownership unknown)')
        for name, path in result['other_executables_in_path'].items():
            print(f'{name} executable in PATH: {path or "not found"} (ownership unknown)')
        current = result['dumpcap_current']
        print('dumpcap now: ' + str(current['mode']) + ', capabilities ' + current['capability_xattr']
              + ', ACL ' + current['acl_xattr'] + ' (prior state unknown)')
        for entry in result['private_zeek_candidates']:
            print(f"Private Zeek candidate: {entry['state']} — {entry['path']} (ownership unknown)")
        if result['private_zeek_scan_state'] != 'complete':
            print('Private Zeek scan: ' + result['private_zeek_scan_state'])
        for name, path in result['selected_tool_directories'].items():
            print(f'{name} selected directory: {path} (ownership unknown)')
        print('Python and Git are preservation requirements. No removal or setting change was attempted.')
        for issue in result['unresolved']:
            print('Review: ' + issue)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
