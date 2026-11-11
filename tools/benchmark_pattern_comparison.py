#!/usr/bin/env python3
"""Compare pure hourly analysis with one trusted, immutable local Git revision.

Synthetic compacted packet metadata only. No store, capture, inference or host
actions. The baseline file is read from local Git objects, never downloaded.
"""
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
from statistics import median
import subprocess
import sys
import time
import tracemalloc
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from megalodon import security_patterns as candidate
from megalodon.evidence_storage import utc

START = 1_792_080_000
SEGMENT = 'a' * 32


def workload(groups, hours):
    rows = []
    for group in range(groups):
        for index, protocol in enumerate(('TCP', 'UDP')):
            rows.append(dict(id=f'{SEGMENT}:{2*group+index+1}', observed_at=utc(START),
                category='packet_rollups', source='packet-conversation-summary',
                data=dict(kind='conversation_v1', src_ip=f'192.0.2.{group+1}', dst_ip='198.51.100.1',
                    src_port=40000, dst_port=443, protocol=protocol, app_proto='transport',
                    interface='fixture0', packet_count=1000, first_at=utc(START), last_at=utc(START+3500))))
    templates, _, gaps = candidate.analyze_hour(rows, START, START+3600, [])
    assert len(templates) == groups and all(row['eligible'] for row in templates) and not gaps
    history = []
    for hour in range(1, hours+1):
        for template in templates:
            start = START-hour*3600
            history.append(dict(template, id=candidate.stable([template['key'], start]), start=start, end=start+3600))
    # Retain real candidate work: this one group's protocol shares move by
    # exactly 25 points, well away from the corrected admission boundary.
    rows[0]['data']['packet_count'] = 1500
    rows[1]['data']['packet_count'] = 500
    return rows, history


def run(function, rows, history):
    return function(rows, START, START+3600, history)


def costs(function, rows, history):
    class Counted(dict):
        key_reads = 0

        def get(self, key, default=None):
            if key == 'key':
                type(self).key_reads += 1
            return super().get(key, default)
    result = run(function, rows, [Counted(row) for row in history])
    reads = Counted.key_reads
    tracemalloc.start()
    try:
        assert run(function, rows, history) == result
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    return dict(history_key_reads=reads, peak_extra_traced_bytes=peak)


def benchmark(reference, groups, hours, repeats):
    rows, history = workload(groups, hours)
    expected = run(reference, rows, history)
    assert len(expected[0]) == groups and len(expected[1]) == 2 and not expected[2]
    assert run(candidate.analyze_hour, rows, history) == expected
    samples = dict(reference=[], candidate=[])
    functions = dict(reference=reference, candidate=candidate.analyze_hour)
    # Alternate order to reduce a systematic warm-cache/order advantage.
    for repeat in range(repeats):
        for name in (('reference', 'candidate') if repeat % 2 == 0 else ('candidate', 'reference')):
            started = time.perf_counter_ns()
            result = run(functions[name], rows, history)
            elapsed = (time.perf_counter_ns()-started)/1_000_000
            assert result == expected
            samples[name].append(elapsed)
    summaries = {name: dict(median_ms=median(values), minimum_ms=min(values), maximum_ms=max(values),
        samples_ms=values, **costs(functions[name], rows, history)) for name, values in samples.items()}
    encoded = json.dumps(dict(rows=rows, history=history), sort_keys=True, separators=(',', ':')).encode()
    return dict(groups=groups, hours_per_group=hours, history_rows=len(history), current_rows=len(rows),
        identical_outputs=True, candidate_rules=dict(Counter(row['rule'] for row in expected[1])),
        input_sha256=sha256(encoded).hexdigest(), output_sha256=sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest(),
        speedup=summaries['reference']['median_ms']/summaries['candidate']['median_ms'], **summaries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-revision', required=True, help='Full commit ID in this trusted local repository')
    parser.add_argument('--groups', type=int, nargs='+', default=[1, 8, 32, 128])
    parser.add_argument('--hours', type=int, default=168)
    parser.add_argument('--repeats', type=int, default=7)
    args = parser.parse_args()
    if not re.fullmatch('[a-f0-9]{40}', args.baseline_revision):
        parser.error('Use a full lowercase 40-character commit ID')
    if not 24 <= args.hours <= 168 or not 3 <= args.repeats <= 15 or not 1 <= len(args.groups) <= 4 or any(not 1 <= n <= 128 for n in args.groups):
        parser.error('Use 1–4 group counts in 1–128, 24–168 hours, and 3–15 repeats')
    source = subprocess.check_output(['git', 'show', args.baseline_revision+':megalodon/security_patterns.py'], cwd=ROOT)
    reference = ModuleType('megalodon._pattern_benchmark_reference')
    reference.__package__ = 'megalodon'
    exec(compile(source, '<trusted-local-pattern-reference>', 'exec'), reference.__dict__)
    result = dict(schema='megalodon-pattern-comparison-benchmark-v1', synthetic_only=True,
        python=platform.python_version(), platform=platform.system(), architecture=platform.machine(),
        baseline_revision=args.baseline_revision, baseline_source_sha256=sha256(source).hexdigest(),
        candidate_source_sha256=sha256(Path(candidate.__file__).read_bytes()).hexdigest(),
        benchmark_sha256=sha256(Path(__file__).read_bytes()).hexdigest(), repeats=args.repeats,
        cases=[benchmark(reference.analyze_hour, n, args.hours, args.repeats) for n in args.groups],
        scope='Pure analyze_hour on finite synthetic compacted metadata; output parity applies to these away-from-threshold cases. Timing is descriptive, not a capture throughput or malware-accuracy claim. Memory is measured separately from timing.')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
