"""Export aggregate-only HUD data from the existing bounded read-only projection."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime
import json
import sys
from .dashboard_traffic import TrafficDashboardStore, PROTOCOLS, DETECTORS

SCHEMA = 'megalodon-hud-snapshot-v1'
SEVERITIES = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
SOURCES = ('jsonl', 'scapy')


def snapshot_from_projection(projection: dict) -> dict:
    """Accept only the internal validated projection, never raw imported JSON."""
    if projection['status'] != 'available' or not projection['events']:
        raise ValueError('No qualified metadata is available to export.')
    events, findings = projection['events'], projection['findings']
    times = [datetime.fromisoformat(e['observed_at'].replace('Z', '+00:00')).timestamp() for e in events]
    first, last = min(times), max(times)
    timeline = [0] * 12
    for timestamp in times:
        timeline[min(11, int((timestamp-first) / max(last-first, 1) * 12))] += 1
    ranks = {name: index+1 for index, name in enumerate(SEVERITIES)}
    highest = {}
    for finding in findings:
        key = finding['event_id']
        highest[key] = max(highest.get(key, 0), ranks[finding['severity']])
    lanes = [0, 0, 0]
    for event in events:
        rank = highest.get(event['id'], 0)
        lanes[2 if rank >= 3 else 1 if rank else 0] += 1
    def counts(rows, field, labels):
        counter = Counter(row[field] for row in rows)
        return [counter[label] for label in labels]
    return {
        'schema': SCHEMA, 'generated_at': projection['generated_at'],
        'start': projection['window']['start'], 'end': projection['window']['end'],
        'events': len(events), 'findings': len(findings),
        'reported_bytes': str(sum(int(e['byte_count']) for e in events)),
        'lanes': lanes, 'timeline': timeline,
        'protocols': counts(events, 'protocol', PROTOCOLS),
        'sources': counts(events, 'source', SOURCES),
        'severities': counts(findings, 'severity', SEVERITIES),
        'detectors': counts(findings, 'rule_id', DETECTORS),
        'limited': projection['truncated'], 'quality': projection['quality'],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Print a bounded, aggregate-only HUD snapshot. No addresses, ports, paths or raw records are exported.')
    parser.add_argument('--database', required=True, help='Absolute path to your existing private MEGALODON database')
    args = parser.parse_args(argv)
    try:
        with TrafficDashboardStore(args.database) as store:
            result = snapshot_from_projection(store.traffic())
    except (OSError, ValueError, RuntimeError):
        print('Snapshot unavailable. Check the private database path, schema and qualified evidence in the local HUD.', file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
