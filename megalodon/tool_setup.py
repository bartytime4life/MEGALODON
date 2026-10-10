"""One explicit terminal entry point for companion installation and setup guidance."""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
from .tool_installer import RECIPES, install_command, uninstall_command, terminal_command, INSTALL_TIMEOUT_SECONDS
from .readiness import readiness_report
from .tool_heartbeat import heartbeat_report

# Role, scope and credentials remain operator choices; never guess or enable capture.
CONFIGURATION = {
    'core': ('Run ./scripts/install-local.sh from a reviewed checkout, then open the MEGALODON application.', 'Before startup: python -m megalodon.config_check < config/settings.toml (substitute your actual settings file). Exit 0 validates configuration only; then check your private database and availability in the HUD.'),
    'tshark': ('For offline review: tshark -r /absolute/path/to/capture.pcap -c 100', 'Live capture needs an explicitly selected interface and separately approved permissions. No permissions are granted by this script.'),
    'zeek': ('Use the pinned private-prefix build guide in README.md, "3. Build Zeek as a private, non-service producer".', 'Run zeek -r /absolute/path/to/capture.pcap inside a new private output directory; it creates logs there.'),
    'suricata': ('Review /etc/suricata/suricata.yaml: set HOME_NET to your authorized network and choose rules and output paths.', 'Validate before enabling: suricata -T -c /etc/suricata/suricata.yaml (may require read permissions).'),
    'scapy': ('Use the same Python environment as MEGALODON; select an authorized interface in the local capture workflow.', 'Check import only: python -c "import scapy; print(scapy.__version__)". No capture starts here.'),
    'nftables': ('Review /etc/nftables.conf locally and preserve an out-of-band recovery path.', 'Syntax check only: nft --check --file /etc/nftables.conf (requires platform privileges). Applying rules is a separate operator action.'),
    'clamav': ('Review /etc/clamav/freshclam.conf for signature updates and your network policy.', 'Choose an explicit scan directory; clamscan --recursive /absolute/path/to/authorized/files reports findings without deleting files.'),
    'osquery': ('Install the signed vendor package; review /etc/osquery/osquery.conf and explicitly choose query scope and schedule.', 'Validate with osqueryi --config_check. Enable osqueryd separately only after reviewing scheduled queries.'),
    'qwen': ('Install and start Ollama using the publisher guide; select the exact local model in MEGALODON AI settings.', 'ollama list shows downloaded artifacts. The install recipe downloads qwen2.5:7b; it does not select or run it.'),
    'nmap': ('Choose only systems you are authorized to assess; review scan scope and flags before executing.', 'nmap --version checks the program. This setup script never starts a scan.'),
}
ALIASES = {'core':'python-sqlite','tshark':'wireshark-tshark','qwen':'qwen-ollama'}
APT_PREVIEW_TIMEOUT_SECONDS = 30
APT_PREVIEW_MAX_CHARS = 64 * 1024


def preview_apt_removal(tool: str, command: list[str]) -> bool:
    """Show apt's current dependency plan without obtaining privileges or changing packages."""
    if RECIPES[tool].kind != 'apt':
        return True
    # uninstall_command returns [sudo, apt-get, remove, flags, fixed packages].
    preview = [command[1], '-s', 'remove', '--no-install-recommends', *RECIPES[tool].packages]
    try:
        result = subprocess.run(preview, check=False, capture_output=True, text=True,
                                timeout=APT_PREVIEW_TIMEOUT_SECONDS,
                                env={**os.environ, 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        print('Could not simulate package removal; no removal was started.', file=sys.stderr)
        return False
    output = (result.stdout or '') + (result.stderr or '')
    if result.returncode or not output.strip() or len(output) > APT_PREVIEW_MAX_CHARS:
        print('Package removal simulation failed or exceeded its display limit; no removal was started.', file=sys.stderr)
        return False
    print('Read-only apt removal plan (review every package and dependency):')
    print(output, end='' if output.endswith('\n') else '\n')
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description='Review, install, uninstall, configure or inspect a fixed MEGALODON companion. Verify prints separate executable and heartbeat observations. Default: print plan only.')
    parser.add_argument('tool', choices=tuple(RECIPES))
    parser.add_argument('action', nargs='?', default='plan', choices=('plan','install','uninstall','configure','verify'))
    parser.add_argument('--apply', action='store_true', help='Execute the fixed install or terminal-confirmed uninstall recipe')
    args = parser.parse_args(argv)
    if args.apply and args.action not in ('install', 'uninstall'):
        parser.error('--apply requires install or uninstall')
    if args.action == 'verify':
        report = readiness_report()
        item = next(t for t in report['tools'] if t['id'] == ALIASES.get(args.tool,args.tool))
        observed = heartbeat_report()
        heartbeat = next(t for t in observed['tools'] if t['id'] == args.tool)
        print(json.dumps({'tool':args.tool, 'presence':item['status'],
                          'heartbeat':heartbeat, 'observed_at':observed['checked_at'],
                          'platform':observed['platform'],
                          'boundaries':report['boundaries'] + [
                              'The separate heartbeat uses file metadata and process-name observations only; its light does not prove tool health, configuration, version or integration.']}))
        return 0
    print(f'{args.tool}: {RECIPES[args.tool].summary}')
    if args.action in ('plan','configure'):
        print('Configuration guide — review and run the applicable steps yourself; no configuration changed.')
        for index, instruction in enumerate(CONFIGURATION[args.tool], 1):
            print(f'{index}. {instruction}')
    if args.action in ('plan','install'):
        print('Install command:', terminal_command(args.tool) or 'Guided installation; use the linked publisher/setup guide in the HUD.')
    if args.action in ('plan','uninstall'):
        print('Uninstall command:', terminal_command(args.tool, 'uninstall') or 'Guided removal; select the exact installed role and follow its vendor guide.')
    if not args.apply:
        if args.action == 'install':
            print('Preview only. Add --apply to execute a supported fixed recipe. Package services may start; model downloads may be large.')
        if args.action == 'uninstall':
            print('Preview only. Add --apply in an interactive terminal to simulate apt removal and review dependencies before typing the exact tool ID. Package removal may stop services or affect dependents; no purge or autoremove is requested.')
        return 0
    if args.action == 'uninstall':
        command = uninstall_command(args.tool)
        if command is None:
            print('No automatic removal recipe. Review the installed method and follow its guide.', file=sys.stderr)
            return 2
        if not sys.stdin.isatty():
            print('Uninstall requires an interactive terminal and exact tool confirmation.', file=sys.stderr)
            return 2
        if not preview_apt_removal(args.tool, command):
            return 2
        try:
            if input(f'Type {args.tool} to run its removal command after reviewing the plan: ') != args.tool:
                print('Removal cancelled.', file=sys.stderr)
                return 2
        except EOFError:
            print('Removal cancelled.', file=sys.stderr)
            return 2
    else:
        command = install_command(args.tool)
    if command is None:
        print('No automatic recipe is available on this platform. Follow the configuration and publisher guides.',file=sys.stderr)
        return 2
    try:
        run_options = {'check': False, 'timeout': INSTALL_TIMEOUT_SECONDS}
        if args.tool == 'qwen':
            run_options['env'] = {**os.environ, 'OLLAMA_HOST': '127.0.0.1:11434'}
        return subprocess.run(command, **run_options).returncode
    except (OSError, subprocess.TimeoutExpired):
        print('Companion action did not complete. Inspect the package manager or provider locally before retrying.',file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
