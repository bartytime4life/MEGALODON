"""Passive review of the IPv4 default gateway and the neighbor (ARP) cache. Nothing is sent or changed.

The kernel routing table and ARP cache are world-readable; this module only
reads them. It names the default gateway's link-layer (MAC) address, compares
it with an operator-recorded baseline or with the first value seen in this
HUD session, and lists MAC addresses that several IPv4 neighbors share. A
changed or shared MAC is a reason to look, never proof of ARP spoofing:
replacing a router, a failover pair, proxy ARP, virtual machines and some
mesh or repeater equipment produce the same signals. No packet is sent, no
neighbor is probed and no cache entry is changed.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys

SCHEMA = 'megalodon-gateway-review-v1'
BASELINE_SCHEMA = 'megalodon-gateway-baseline-v1'
TRUST = 'observed_not_known_clean'
ATTACK = 'T1557.002'
MAX_TABLE_READ = 1024 * 1024
MAX_TABLE_LINES = 8192
MAX_GROUPS = 8
MAX_GROUP_ADDRESSES = 8
MAX_SESSION_GATEWAYS = 16
RTF_UP, RTF_GATEWAY = 0x1, 0x2
ATF_COM, ATF_PERM = 0x2, 0x4
_INTERFACE = re.compile(r'[A-Za-z0-9_.:@-]{1,15}')
_MAC = re.compile(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}')
# Plain hex only: int(..., 16) also accepts signs and underscores, which would not round-trip.
_HEX8 = re.compile(r'[0-9A-Fa-f]{8}')
_FLAGS = re.compile(r'[0-9A-Fa-f]{1,8}')
_STAMP = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z')
_UNUSABLE_MACS = {'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'}
# /proc/net/route prints each network-order address as a host-order number.
_BYTE_ORDER = sys.byteorder
RULES = {
    'GATEWAY_MAC_CHANGED': 'review',
    'GATEWAY_MAC_SHARED': 'review',
    'GATEWAY_CHANGED': 'note',
    'SHARED_MAC': 'note',
}


def _now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _read(path):
    """Return (lines, complete) from a bounded table, without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('not a regular file')
        chunks, size = [], 0
        while size <= MAX_TABLE_READ:
            chunk = os.read(fd, MAX_TABLE_READ + 1 - size)
            if not chunk:
                break
            chunks.append(chunk); size += len(chunk)
    finally:
        os.close(fd)
    lines = b''.join(chunks)[:MAX_TABLE_READ].decode('ascii', 'replace').splitlines()
    complete = size <= MAX_TABLE_READ
    if not complete:
        lines = lines[:-1]  # the last line may be cut off
    if len(lines) > MAX_TABLE_LINES + 1:
        lines, complete = lines[:MAX_TABLE_LINES + 1], False
    return lines[1:], complete


def _ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        return None


def default_gateways(root='/'):
    """Return IPv4 default routes through a gateway, lowest metric first, and whether the table was fully read."""
    lines, complete = _read(Path(root, 'proc/net/route'))
    routes = []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[1] != '00000000' or fields[7] != '00000000':
            continue
        if not _HEX8.fullmatch(fields[2]) or not _FLAGS.fullmatch(fields[3]) or not fields[6].isdigit():
            continue
        try:
            flags, metric = int(fields[3], 16), int(fields[6])
            gateway = str(ipaddress.IPv4Address(int(fields[2], 16).to_bytes(4, _BYTE_ORDER)))
        except ValueError:
            continue
        if flags & (RTF_UP | RTF_GATEWAY) != RTF_UP | RTF_GATEWAY or not _INTERFACE.fullmatch(fields[0]):
            continue
        routes.append(dict(interface=fields[0], ip=gateway, metric=metric))
    return sorted(routes, key=lambda r: r['metric']), complete


def neighbors(root='/'):
    """Return resolved IPv4 neighbors and whether the ARP cache was fully read."""
    lines, complete = _read(Path(root, 'proc/net/arp'))
    rows = []
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            continue
        ip, mac, device = _ipv4(fields[0]), fields[3].lower(), fields[5]
        try:
            flags = int(fields[2], 16)
        except ValueError:
            continue
        if ip is None or not _INTERFACE.fullmatch(device) or not _MAC.fullmatch(mac):
            continue
        state = ('permanent' if flags & ATF_PERM else 'complete') if flags & ATF_COM and mac not in _UNUSABLE_MACS else 'incomplete'
        rows.append(dict(ip=ip, mac=mac, interface=device, state=state))
    return rows, complete


def observe(root='/'):
    routes, routes_complete = default_gateways(root)
    rows, neighbors_complete = neighbors(root)
    resolved = [r for r in rows if r['state'] != 'incomplete']
    gateway = None
    if routes:
        route = routes[0]
        entry = next((r for r in rows if r['ip'] == route['ip'] and r['interface'] == route['interface']), None)
        gateway = dict(ip=route['ip'], interface=route['interface'],
                       mac=entry['mac'] if entry and entry['state'] != 'incomplete' else None,
                       entry=entry['state'] if entry else 'absent')
    groups = {}
    for row in resolved:
        groups.setdefault((row['interface'], row['mac']), set()).add(row['ip'])
    # The gateway's own group sorts first, so the bound below never hides the strongest signal.
    own = (gateway['interface'], gateway['mac']) if gateway and gateway['mac'] else None
    shared = sorted(((interface, mac, sorted(ips, key=ipaddress.IPv4Address)) for (interface, mac), ips in groups.items() if len(ips) > 1),
                    key=lambda g: ((g[0], g[1]) != own, -len(g[2]), g[0], g[1]))
    return dict(gateway=gateway, other_default_routes=max(0, len(routes) - 1), neighbors=len(resolved),
                shared=[dict(interface=i, mac=m, addresses=ips[:MAX_GROUP_ADDRESSES], count=len(ips)) for i, m, ips in shared[:MAX_GROUPS]],
                shared_total=len(shared), tables_complete=routes_complete and neighbors_complete)


def assess(observation, expected=None, source=None):
    """Return review findings for an observation; never an action or a verdict.

    `expected` is the gateway recorded earlier ({'interface', 'ip', 'mac'}) and
    `source` names where it came from ('baseline' or 'session').
    """
    findings = []
    def add(rule, detail, **extra):
        findings.append(dict(rule=rule, level=RULES[rule], attack=ATTACK, detail=detail, action_status='not_attempted', **extra))
    gateway = observation['gateway']
    since = 'the recorded baseline' if source == 'baseline' else 'the first observation in this HUD session'
    if gateway and expected:
        if (gateway['interface'], gateway['ip']) != (expected['interface'], expected['ip']):
            add('GATEWAY_CHANGED', f"The default gateway is {gateway['ip']} on {gateway['interface']}, not {expected['ip']} on "
                                   f"{expected['interface']} as in {since}. Joining another network also does this.")
        elif gateway['mac'] and gateway['mac'] != expected['mac']:
            add('GATEWAY_MAC_CHANGED', f"The gateway's MAC address is {gateway['mac']}, not {expected['mac']} as in {since}. "
                                       'A replaced router or a failover pair also does this.')
    for group in observation['shared']:
        if gateway and gateway['mac'] and (group['interface'], group['mac']) == (gateway['interface'], gateway['mac']):
            add('GATEWAY_MAC_SHARED', f"The gateway's MAC address is also claimed by {group['count'] - 1} other address(es) on "
                                      f"{group['interface']}. Proxy ARP and some routers also do this.", mac=group['mac'])
        else:
            add('SHARED_MAC', f"{group['count']} addresses on {group['interface']} share one MAC address. Virtual machines, "
                              'repeaters and multi-address hosts also do this.', mac=group['mac'])
    return findings


class GatewayReview:
    def __init__(self, home=None, *, root='/', now=_now):
        self.home = Path(home or Path.home())
        self.state = self.home/'.local/share/megalodon/support/gateway-review'
        self.root, self.now = root, now

    def baseline(self):
        from .host_security import read
        path = self.state/'baseline.json'
        if not os.path.lexists(path):
            return None
        value = json.loads(read(path, 4096))
        if (type(value) is not dict or set(value) != {'schema', 'created_at', 'trust', 'interface', 'ip', 'mac'}
                or value['schema'] != BASELINE_SCHEMA or value['trust'] != TRUST
                or not all(type(value[k]) is str for k in ('created_at', 'interface', 'ip', 'mac'))
                or not _STAMP.fullmatch(value['created_at']) or not _INTERFACE.fullmatch(value['interface'])
                or _ipv4(value['ip']) != value['ip']
                or not _MAC.fullmatch(value['mac'])):
            raise ValueError('Invalid gateway baseline.')
        return value

    def record_baseline(self):
        from .host_security import write
        gateway = observe(self.root)['gateway']
        if not gateway or not gateway['mac']:
            raise ValueError('No resolved IPv4 default gateway is visible, so there is nothing to record.')
        value = dict(schema=BASELINE_SCHEMA, created_at=self.now(), trust=TRUST,
                     interface=gateway['interface'], ip=gateway['ip'], mac=gateway['mac'])
        write(self.state/'baseline.json', json.dumps(value, sort_keys=True).encode())
        return dict(value, state='baseline_recorded',
                    message='Gateway baseline recorded from what is visible now. It is not a known-clean state.')

    def review(self, session=None):
        """Review against the baseline, else against the first MAC this session saw for the same gateway.

        `session` is a caller-owned dict, keyed by interface and gateway IP, that
        this call extends with a newly seen gateway (at most MAX_SESSION_GATEWAYS).
        Joining another network therefore starts a new comparison instead of
        reporting a change.
        """
        baseline = self.baseline()
        observation = observe(self.root)
        gateway = observation['gateway']
        expected, source = (baseline, 'baseline') if baseline else (None, None)
        if baseline is None and session is not None and gateway and gateway['mac']:
            key = f"{gateway['interface']} {gateway['ip']}"
            if key in session:
                expected, source = dict(session[key], interface=gateway['interface'], ip=gateway['ip']), 'session'
            elif len(session) < MAX_SESSION_GATEWAYS:
                session[key] = dict(mac=gateway['mac'], seen_at=self.now())
        gaps = []
        if not observation['tables_complete']:
            gaps.append('The routing table or ARP cache was not fully read; other entries may exist.')
        if gateway is None:
            gaps.append('No IPv4 default route through a gateway is visible (for example offline, IPv6-only or a VPN tunnel).')
        elif gateway['mac'] is None:
            gaps.append('The gateway has no resolved ARP entry yet; its MAC address appears after traffic reaches it.')
        if observation['other_default_routes']:
            gaps.append(f"{observation['other_default_routes']} other IPv4 default route(s) exist; only the lowest-metric gateway is reviewed.")
        if observation['shared_total'] > len(observation['shared']):
            gaps.append(f"{observation['shared_total']} shared-MAC groups were found; only the first {MAX_GROUPS} are listed.")
        if source != 'baseline':
            gaps.append('No gateway baseline is recorded, so a MAC address that was already different when this HUD session '
                        'first saw the gateway cannot be noticed.')
        gaps.append('IPv6 neighbors, rogue DHCP servers and new devices are not reviewed.')
        compared = None if expected is None else dict(source=source, interface=expected['interface'], ip=expected['ip'],
                                                      mac=expected['mac'],
                                                      at=expected['created_at'] if source == 'baseline' else expected['seen_at'])
        return dict(schema=SCHEMA, reviewed_at=self.now(), gateway=gateway,
                    other_default_routes=observation['other_default_routes'], neighbors=observation['neighbors'],
                    shared=observation['shared'], shared_total=observation['shared_total'],
                    tables_complete=observation['tables_complete'], compared_with=compared,
                    findings=assess(observation, expected, source), gaps=gaps, trust=TRUST, action_authority='none')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('action', choices=('review', 'baseline'))
    args = parser.parse_args(argv)
    try:
        manager = GatewayReview()
        print(json.dumps(manager.record_baseline() if args.action == 'baseline' else manager.review(), indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('Gateway review unavailable: ' + ''.join(c if c.isprintable() else '?' for c in str(exc))[:240])
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
