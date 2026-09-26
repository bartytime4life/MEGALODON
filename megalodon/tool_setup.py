"""One explicit terminal entry point for companion installation and setup guidance."""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
from .tool_installer import RECIPES, install_command, terminal_command, INSTALL_TIMEOUT_SECONDS
from .readiness import readiness_report

# Role, scope and credentials remain operator choices; never guess or enable capture.
CONFIGURATION = {
    'core': ('Run ./scripts/install-local.sh from a reviewed checkout, then open the MEGALODON application.', 'Open HUD → Data and tools; select your private database and check availability.'),
    'tshark': ('For offline review: tshark -r /absolute/path/to/capture.pcap -c 100', 'Live capture needs an explicitly selected interface and separately approved permissions. No permissions are granted by this script.'),
    'zeek': ('Use the pinned private-prefix build guide in docs/companion-setup.md.', 'Run zeek -r /absolute/path/to/capture.pcap inside a new private output directory; it creates logs there.'),
    'suricata': ('Review /etc/suricata/suricata.yaml: set HOME_NET to your authorized network and choose rules and output paths.', 'Validate before enabling: suricata -T -c /etc/suricata/suricata.yaml (may require read permissions).'),
    'scapy': ('Use the same Python environment as MEGALODON; select an authorized interface in the local capture workflow.', 'Check import only: python -c "import scapy; print(scapy.__version__)". No capture starts here.'),
    'nftables': ('Review /etc/nftables.conf locally and preserve an out-of-band recovery path.', 'Syntax check only: nft --check --file /etc/nftables.conf (requires platform privileges). Applying rules is a separate operator action.'),
    'clamav': ('Review /etc/clamav/freshclam.conf for signature updates and your network policy.', 'Choose an explicit scan directory; clamscan --recursive /absolute/path/to/authorized/files reports findings without deleting files.'),
    'osquery': ('Install the signed vendor package; review /etc/osquery/osquery.conf and explicitly choose query scope and schedule.', 'Validate with osqueryi --config_check. Enable osqueryd separately only after reviewing scheduled queries.'),
    'qwen': ('Install and start Ollama using the publisher guide; select the exact local model in MEGALODON AI settings.', 'ollama list shows downloaded artifacts. The install recipe downloads qwen2.5:7b; it does not select or run it.'),
    'nmap': ('Choose only systems you are authorized to assess; review scan scope and flags before executing.', 'nmap --version checks the program. This setup script never starts a scan.'),
    'ossec': ('Choose agent or server role using the vendor guide before installing.', 'Review /var/ossec/etc/ossec.conf and explicitly set the manager address for an agent. Enrollment credentials stay local.'),
    'greenbone': ('Use the official container guide; choose storage, feed synchronization and a loopback console binding.', 'Set a unique administrator password and complete feed initialization before creating authorized scan targets.'),
    'zabbix': ('Review /etc/zabbix/zabbix_agentd.conf: set Server, ServerActive and Hostname for your own monitoring server.', 'Configure TLS and restrict allowed monitoring peers before separately enabling the agent service.'),
    'nagios': ('Review /etc/nagios4/nagios.cfg and host/service definitions for authorized targets.', 'Validate with nagios4 -v /etc/nagios4/nagios.cfg before separately enabling the service; restrict the web console.'),
}
ALIASES = {'core':'python-sqlite','tshark':'wireshark-tshark','qwen':'qwen-ollama','nagios':'nagios-core'}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Review, install, configure or inspect a fixed MEGALODON companion. Default: print plan only.')
    parser.add_argument('tool', choices=tuple(RECIPES))
    parser.add_argument('action', nargs='?', default='plan', choices=('plan','install','configure','verify'))
    parser.add_argument('--apply', action='store_true', help='Execute the fixed installation recipe; only valid with install')
    args = parser.parse_args(argv)
    if args.apply and args.action != 'install':
        parser.error('--apply requires install')
    if args.action == 'verify':
        report = readiness_report()
        item = next(t for t in report['tools'] if t['id'] == ALIASES.get(args.tool,args.tool))
        print(json.dumps({'tool':args.tool, 'presence':item['status'], 'boundaries':report['boundaries']}))
        return 0
    print(f'{args.tool}: {RECIPES[args.tool].summary}')
    if args.action in ('plan','configure'):
        print('Configuration guide — review and run the applicable steps yourself; no configuration changed.')
        for index, instruction in enumerate(CONFIGURATION[args.tool], 1):
            print(f'{index}. {instruction}')
    if args.action in ('plan','install'):
        print('Install command:', terminal_command(args.tool) or 'Guided installation; use the linked publisher/setup guide in the HUD.')
    if not args.apply:
        if args.action == 'install':
            print('Preview only. Add --apply to execute a supported fixed recipe. Package services may start; model downloads may be large.')
        return 0
    command = install_command(args.tool)
    if command is None:
        print('No automatic recipe is available on this platform. Follow the configuration and publisher guides.',file=sys.stderr)
        return 2
    try:
        return subprocess.run(command, check=False, timeout=INSTALL_TIMEOUT_SECONDS).returncode
    except (OSError, subprocess.TimeoutExpired):
        print('Installation did not complete. Inspect the package manager locally before retrying.',file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
