"""Bounded, aggregate-only projection of a completed Nmap XML report on stdin."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
import sys
import time
from xml.parsers import expat

SCHEMA = 'megalodon-nmap-inventory-v1'
MAX_BYTES = 2 * 1024 * 1024
MAX_COUNT = 1_000_000
STATES = ('open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered')
PROTOCOLS = ('tcp', 'udp', 'sctp')


def summarize_report(raw: bytes, *, now: float | None = None) -> dict:
    """Parse an inert report; discard identifiers, banners, scripts and raw text."""
    def refuse():
        raise ValueError('Unsupported or incomplete Nmap report.')

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_BYTES:
        refuse()
    try:
        text = raw.decode('utf-8-sig', errors='strict')
    except UnicodeError:
        refuse()
    if '\x00' in text:
        refuse()
    clock = time.time() if now is None else now
    path = []
    nodes = 0
    report = {'schema': SCHEMA, 'started_at': '', 'finished_at': '',
              'hosts': [0, 0], 'represented_hosts': [0, 0],
              'explicit_states': [0] * 6, 'grouped_states': [0] * 6,
              'protocols': [0] * 3}
    root_seen = finished_seen = stats_seen = hosts_seen = False
    host_status = ports_seen = False
    port_state = False
    seen_ports = set()
    host_count = 0
    start_time = 0

    def number(value, maximum=MAX_COUNT):
        if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,9}', value):
            refuse()
        result = int(value)
        if result > maximum:
            refuse()
        return result

    def timestamp(value):
        value = number(value, 253402300799)
        if value > clock + 60:
            refuse()
        return value, datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')

    def add(key, index, count):
        report[key][index] += count
        if sum(report[key]) > MAX_COUNT:
            refuse()

    def begin(name, attrs):
        nonlocal nodes, root_seen, stats_seen, finished_seen, hosts_seen
        nonlocal host_status, ports_seen, port_state, host_count, start_time
        path.append(name)
        nodes += 1
        if len(path) > 16 or nodes > 50000 or ':' in name:
            refuse()
        here = '/'.join(path)
        if len(path) == 1:
            if root_seen or name != 'nmaprun' or attrs.get('scanner') != 'nmap' or attrs.get('xmloutputversion') != '1.05' or not re.fullmatch(r'7\.[0-9]{1,3}(?:SVN)?', attrs.get('version', '')):
                refuse()
            root_seen = True
            start_time, report['started_at'] = timestamp(attrs.get('start'))
        elif here == 'nmaprun/host':
            if stats_seen or attrs.get('timedout', 'false') != 'false':
                refuse()
            host_count += 1
            if host_count > 4096:
                refuse()
            host_status = ports_seen = False
            seen_ports.clear()
        elif here == 'nmaprun/host/status':
            state = attrs.get('state')
            if host_status or state not in ('up', 'down'):
                refuse()
            host_status = True
            add('represented_hosts', ('up', 'down').index(state), 1)
        elif here == 'nmaprun/host/ports':
            if ports_seen:
                refuse()
            ports_seen = True
        elif here == 'nmaprun/host/ports/port':
            protocol = attrs.get('protocol')
            port = number(attrs.get('portid'), 65535)
            if protocol not in PROTOCOLS or (protocol, port) in seen_ports:
                refuse()
            seen_ports.add((protocol, port))
            port_state = False
            add('protocols', PROTOCOLS.index(protocol), 1)
        elif here == 'nmaprun/host/ports/port/state':
            state = attrs.get('state')
            if port_state or state not in STATES:
                refuse()
            port_state = True
            add('explicit_states', STATES.index(state), 1)
        elif here == 'nmaprun/host/ports/extraports':
            state = attrs.get('state')
            if state not in STATES:
                refuse()
            add('grouped_states', STATES.index(state), number(attrs.get('count')))
        elif here == 'nmaprun/runstats':
            if stats_seen:
                refuse()
            stats_seen = True
        elif here == 'nmaprun/runstats/finished':
            if finished_seen or attrs.get('exit') != 'success':
                refuse()
            finished_seen = True
            end, report['finished_at'] = timestamp(attrs.get('time'))
            if end < start_time:
                refuse()
        elif here == 'nmaprun/runstats/hosts':
            if hosts_seen:
                refuse()
            hosts_seen = True
            report['hosts'] = [number(attrs.get('up')), number(attrs.get('down'))]
            if sum(report['hosts']) != number(attrs.get('total')):
                refuse()
        # All other content is deliberately ignored, never rendered or retained.

    def end(name):
        here = '/'.join(path)
        if here == 'nmaprun/host' and not host_status:
            refuse()
        if here == 'nmaprun/host/ports/port' and not port_state:
            refuse()
        path.pop()

    def doctype(name, system_id, public_id, internal):
        if name != 'nmaprun' or system_id or public_id or internal:
            refuse()

    parser = expat.ParserCreate('UTF-8')
    parser.StartElementHandler = begin
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = doctype
    parser.EntityDeclHandler = lambda *args: refuse()
    parser.ExternalEntityRefHandler = lambda *args: refuse()
    parser.XmlDeclHandler = lambda version, encoding, standalone: None if version == '1.0' and (not encoding or encoding.upper() == 'UTF-8') else refuse()
    try:
        parser.Parse(text, True)
    except expat.ExpatError:
        refuse()
    if not (root_seen and stats_seen and finished_seen and hosts_seen) or any(a > b for a, b in zip(report['represented_hosts'], report['hosts'])):
        refuse()
    if sum(report['explicit_states']) + sum(report['grouped_states']) > MAX_COUNT:
        refuse()
    return report


def main(argv=None):
    argparse.ArgumentParser(description='Read one completed Nmap 7.x XML 1.05 report from stdin; print aggregate inventory JSON. No Nmap installation or scan is performed.').parse_args(argv)
    try:
        result = summarize_report(sys.stdin.buffer.read(MAX_BYTES + 1))
    except (ValueError, OSError, OverflowError):
        print('Inventory unavailable: use a completed supported XML report within the documented bounds.', file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
