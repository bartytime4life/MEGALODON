"""Offline synthetic evaluation of retained-hour candidates and layered reviews.

Only bundled, bounded synthetic scenarios are admitted. Labels never enter the
analyzer. There is no collection, persistence, model or response path here.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
from importlib.resources import files
import json
import platform
import random
import re
import statistics
import time
import tracemalloc

from .evidence_storage import epoch, utc
from .layered_review import layered_reviews
from .reference import ReferenceDataError
from .security_patterns import analyze_hour


CORPUS_SHA256 = 'c5bdd27538470a16609a88419b208f797cb731deb92785e09b1273e795d7d942'
LABELS_SHA256 = '6d3e9a7ae906959ff5966e0e6cd00fe3d62bd2434b82e1ca28af1948989f7bd7'
RULES = {'HOST_FANOUT', 'REGULAR_INTERVAL', 'PORT_53_BURST'}


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_digests():
    """Identify installed source bytes as well as caller-declared Git context."""
    paths = ('layered_evaluation.py', 'security_patterns.py', 'layered_review.py',
             'offline/analysis.py', 'offline/common.py', 'models.py',
             'evidence_storage.py', 'validation.py')
    result = {}
    for path in paths:
        with files('megalodon').joinpath(path).open('rb') as stream:
            raw = stream.read(262145)
        if len(raw) > 262144:
            raise ReferenceDataError('LAYERED_SOURCE_SIZE')
        result[path] = hashlib.sha256(raw).hexdigest()
    return result


def load_corpus():
    """Integrity-bound fixtures; no caller-selected paths or telemetry input."""
    documents = []
    for name, expected in [('cases.json', CORPUS_SHA256), ('labels.json', LABELS_SHA256)]:
        resource = files('megalodon.reference').joinpath('layered-v1', name)
        with resource.open('rb') as stream:
            raw = stream.read(131073)
        if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != expected:
            raise ReferenceDataError('LAYERED_CORPUS_INTEGRITY')
        documents.append(json.loads(raw))
    corpus, labels = documents
    ids = [case['id'] for case in corpus['cases']]
    if (not 1 <= len(ids) <= 32 or len(set(ids)) != len(ids)
            or set(ids) != set(labels['labels'])
            or any(v['label'] not in {'ordinary', 'useful', 'indeterminate'}
                   or not v['rationale'] for v in labels['labels'].values())):
        raise ReferenceDataError('LAYERED_LABEL_COVERAGE')
    return corpus, labels


def observations(case, start):
    """Build inert flow dictionaries and a separate hand-authored support oracle."""
    rows, oracle = [], {}
    for block_number, block in enumerate(case['blocks']):
        for index, offset in enumerate(block['offsets']):
            # Segment/record identity follows the retained evidence contract.
            reference = f"{block['segment']:032x}:{block_number * 1000 + index + 1}"
            row = dict(id=reference, category='flows', source=block.get('sensor', 'synthetic-sensor'),
                       observed_at=utc(start + block.get('observed_offset', max(0, offset))),
                       data=dict(src_ip='192.0.2.1',
                                 dst_ip=f"198.51.100.{index + 1 if block.get('fanout') else 200}",
                                 protocol='TCP', src_port=40000, dst_port=block['port'],
                                 interface=block.get('interface', 'fixture0'),
                                 source_id=block.get('identity', f'flow-{block_number}-{index}'),
                                 first_seen=utc(start + offset)))
            if block.get('missing_start'):
                del row['data']['first_seen']
            rows.append(row)
            oracle[reference] = dict(row=row, supports=block['supports'])
    return rows, oracle


def _run(rows, start, gaps):
    _, individual, coverage = analyze_hour(rows, start, start + 3600, [], gaps=gaps)
    layered, layer_gaps = layered_reviews(individual, start, start + 3600)
    # Same priority rule as process_hour; admission/cooldown/storage are NOT
    # reproduced here and are deliberately not described as measured alerts.
    room = max(0, 64 - len(individual))
    return dict(individual=individual, layered=layered[:room],
                layered_before_hourly_cap=len(layered),
                layered_omitted_by_hourly_cap=max(0, len(layered) - room),
                gaps=sorted(set(coverage + layer_gaps)))


def _canonical(result):
    value = deepcopy(result)
    # Lists of candidates are sets for this evaluator; the actual reference
    # page, facts, IDs, dependencies and coverage remain byte-sensitive.
    for name in ('individual', 'layered'):
        value[name].sort(key=lambda c: (c['id'], _digest(c)))
    return value


def evidence_errors(result, oracle, start):
    """Check actual references against scenario support, never predicted labels.

    The corpus deliberately uses only three timing rules. It does not validate
    the packet detectors or equate a well-formed reference with real provenance.
    """
    errors, checked = [], 0
    for candidate in result['individual']:
        rule = candidate['rule']
        refs = candidate['evidence_refs']
        support = []
        for ref in refs:
            checked += 1
            entry = oracle.get(ref)
            if entry is None:
                errors.append('unresolved_reference')
                continue
            row = entry['row']; data = row['data']
            if (rule not in entry['supports'] or row['source'] != candidate['sensor']
                    or data['src_ip'] != candidate['device']
                    or (data['interface'] or 'unreported') != candidate['interface']
                    or not start <= epoch(data.get('first_seen', row['observed_at'])) < start + 3600):
                errors.append('unsupported_reference')
            support.append(row)
        expected = {ref for ref, entry in oracle.items()
                    if rule in entry['supports']
                    and entry['row']['source'] == candidate['sensor']
                    and (entry['row']['data']['interface'] or 'unreported') == candidate['interface']}
        if rule == 'REGULAR_INTERVAL':
            expected = {ref for ref in expected
                        if oracle[ref]['row']['data']['dst_port'] == candidate['facts']['port']}
            # One representative per distinct time. Same-time duplicates may
            # use either reference, but repeated/permuted runs must agree.
            by_time = {}
            for ref in sorted(expected):
                by_time.setdefault(oracle[ref]['row']['data']['first_seen'], ref)
            expected = set(by_time.values())
        if rule in RULES:
            if rule == 'HOST_FANOUT':
                expected = set(sorted(expected)[:16])
            expected_segments = {ref.split(':')[0] for ref in expected}
            if set(candidate['source_segments']) != expected_segments:
                errors.append('incorrect_dependency_set')
            if len(refs) != min(24, len(expected)):
                errors.append('incorrect_reference_count')
        if candidate['action_status'] != 'not_attempted':
            errors.append('action_authority_changed')
    for review in result['layered']:
        components = []
        for signal in review['facts']['signals']:
            matches = [c for c in result['individual'] if c['device'] == review['device']
                       and c['interface'] == review['interface']
                       and all(c[key] == signal[key] for key in ('rule', 'sensor', 'measurement'))]
            components.append(sorted(matches, key=lambda c: c['id'])[0])
        checked += len(review['evidence_refs'])
        if set(review['evidence_refs']) != {ref for c in components for ref in c['evidence_refs']}:
            errors.append('incorrect_layered_reference_union')
        if set(review['source_segments']) != {s for c in components for s in c['source_segments']}:
            errors.append('incorrect_layered_dependency_union')
        if (review['facts']['independent_corroboration'] is not False
                or review['facts']['attack_sequence_established'] is not False
                or review['action_status'] != 'not_attempted' or review['workflow'] != 'evidence_summary'):
            errors.append('layered_authority_changed')
    return dict(checked_references=checked, errors=dict(sorted(Counter(errors).items())))


def evaluate_layered(*, source_commit, source_tree, repeats=3, benchmark=False):
    """Measure candidate workload with explicit synthetic case-hour denominators."""
    if (any(type(v) is not str or re.fullmatch('[a-f0-9]{40}', v) is None
            for v in (source_commit, source_tree))
            or type(repeats) is not int or not 2 <= repeats <= 10
            or type(benchmark) is not bool):
        raise ReferenceDataError('INVALID_LAYERED_EVALUATION_ARGUMENTS')
    corpus, labels = load_corpus()
    start = corpus['start']; results = []; wall = []; cpu = []
    confusion = Counter(tp=0, fp=0, fn=0, tn=0)
    peaks = []
    for case in corpus['cases']:
        rows, oracle = observations(case, start)
        original = deepcopy(rows)
        digests, permutations = [], []
        result = None
        for iteration in range(repeats):
            before_wall, before_cpu = time.perf_counter_ns(), time.process_time_ns()
            measured = _run(rows, start, case.get('gaps', []))
            cpu.append(time.process_time_ns() - before_cpu)
            wall.append(time.perf_counter_ns() - before_wall)
            digests.append(_digest(_canonical(measured)))
            if result is None:
                result = measured
            reordered = list(rows)
            random.Random(iteration).shuffle(reordered)
            permutations.append(_digest(_canonical(_run(reordered, start, case.get('gaps', [])))))
        if benchmark:
            if tracemalloc.is_tracing():
                raise ReferenceDataError('LAYERED_BENCHMARK_TRACER_ALREADY_ACTIVE')
            tracemalloc.start()
            try:
                _run(rows, start, case.get('gaps', []))
                peaks.append(tracemalloc.get_traced_memory()[1])
            finally:
                tracemalloc.stop()
        truth = labels['labels'][case['id']]
        prediction = bool(result['layered'])
        if truth['label'] != 'indeterminate':
            confusion[('tp' if prediction else 'fn') if truth['label'] == 'useful'
                      else ('fp' if prediction else 'tn')] += 1
        validation = evidence_errors(result, oracle, start)
        results.append(dict(case=case['id'], label=truth['label'], rationale=truth['rationale'],
                            observations=len(rows), candidates=len(result['individual']),
                            candidate_rules=sorted(Counter(c['rule'] for c in result['individual']).items()),
                            layered_reviews=len(result['layered']),
                            layered_before_hourly_cap=result['layered_before_hourly_cap'],
                            layered_omitted_by_hourly_cap=result['layered_omitted_by_hourly_cap'],
                            evidence=validation, gaps=result['gaps'],
                            repeat_stable=len(set(digests)) == 1,
                            permutation_stable=set(permutations) == {digests[0]},
                            input_unchanged=rows == original, result_sha256=digests[0]))
    counts = Counter(r['label'] for r in results)
    evidence_error_count = sum(sum(r['evidence']['errors'].values()) for r in results)
    stable = all(r['repeat_stable'] and r['permutation_stable'] and r['input_unchanged'] for r in results)
    report = dict(schema='megalodon-layered-evaluation-v1', synthetic_only=True,
                  source=dict(commit=source_commit, tree=source_tree, attestation='caller-declared'),
                  installed_source_sha256=source_digests(),
                  corpus_sha256=CORPUS_SHA256, labels_sha256=LABELS_SHA256,
                  label_basis=labels['basis'], unit=labels['unit'], repeats=repeats,
                  window=dict(start=utc(start), end=utc(start + 3600)),
                  evaluation_boundary='Pre-admission retained-flow candidates and layered hourly cap; no database, cooldown, packet detector or live collection.',
                  denominators=dict(total=len(results), ordinary=counts['ordinary'], useful=counts['useful'],
                                    indeterminate_excluded=counts['indeterminate']),
                  synthetic_workload=dict(confusion, false_alert_definition='Ordinary case with a layered candidate, not a malicious verdict.',
                                          missed_case_definition='Useful case without a layered candidate; individual findings can still exist.'),
                  totals=dict(candidates=sum(r['candidates'] for r in results),
                              layered_reviews=sum(r['layered_reviews'] for r in results),
                              checked_references=sum(r['evidence']['checked_references'] for r in results),
                              evidence_errors=evidence_error_count,
                              unstable_permutations=sum(not r['permutation_stable'] for r in results)),
                  cases=results, all_match=stable and evidence_error_count == 0,
                  operational_accuracy=None, operational_false_positive_rate=None,
                  limitations=['Hand-built cases have no representative traffic prevalence or time denominator.',
                               'Labels encode stipulated scenario intent, not independent human or operational ground truth.',
                               'All-match gates provenance/stability only; it is not perfect classification or acceptance.',
                               'Address/interface/hour coincidence does not establish identity or independent sensors.',
                               'No installed-PC, sustained load, retention, cooldown or response effectiveness claim.'],
                  network_access_performed=False, persistence_status='not_attempted', action_status='not_attempted')
    report['deterministic_sha256'] = _digest(report)
    if benchmark:
        report['cost'] = dict(environment=dict(python=platform.python_version(), system=platform.system(),
                                               machine=platform.machine()), calls=len(wall),
                            scope='Sequential in-process analyzer plus correlator; excludes fixture load, oracle, shuffle and tracing.',
                            wall_ns=dict(min=min(wall), median=int(statistics.median(wall)), max=max(wall)),
                            cpu_ns=dict(min=min(cpu), median=int(statistics.median(cpu)), max=max(cpu)),
                            max_traced_python_bytes=max(peaks),
                            memory_scope='Separate traced pass; Python allocations only, not process RSS.',
                            deterministic_digest_excludes_cost=True)
    return report
