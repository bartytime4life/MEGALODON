#!/usr/bin/env python3
"""Finite synthetic layered-review checks; no sensors, models or host effects."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.layered_review import layered_reviews
from megalodon.security_patterns import candidate

START = 1790726400
SEGMENT = 'a' * 32


def signal(rule, *, address='192.0.2.1', interface='fixture0', source='synthetic-sensor'):
    return candidate(rule, (address, interface, source, 'flow'), START, START + 3600,
                     {}, [SEGMENT + ':1'], [SEGMENT])


def main():
    scenarios = [
        ('single signal', [signal('HOST_FANOUT')], 0),
        ('same-family discovery signals', [signal('HOST_FANOUT'), signal('PORT_SCAN')], 0),
        ('different recorded addresses', [signal('HOST_FANOUT'), signal('REGULAR_INTERVAL', address='192.0.2.2')], 0),
        ('different interfaces', [signal('HOST_FANOUT'), signal('REGULAR_INTERVAL', interface='fixture1')], 0),
        ('authorized inventory and scheduled job', [signal('HOST_FANOUT'), signal('REGULAR_INTERVAL')], 1),
        ('suspicious activity with identical metadata', [signal('HOST_FANOUT'), signal('REGULAR_INTERVAL')], 1),
        ('two sensor labels without independence proof', [signal('HOST_FANOUT'), signal('REGULAR_INTERVAL', source='second-sensor')], 1),
    ]
    results = []
    for name, values, expected in scenarios:
        reviews, gaps = layered_reviews(values, START, START + 3600)
        assert len(reviews) == expected
        assert all(r['action_status'] == 'not_attempted' and r['workflow'] == 'evidence_summary' for r in reviews)
        assert all(r['facts']['independent_corroboration'] is False for r in reviews)
        results.append(dict(scenario=name, reviews=len(reviews), gaps=gaps))
    print(json.dumps(dict(schema='megalodon-layered-replay-v1', scenarios=results,
        limit='Synthetic contract checks only. Identical benign and suspicious metadata receive identical review; no operational accuracy or compromise claim.'), indent=2))


if __name__ == '__main__':
    main()
