"""Offline experiment on the two five-start cadence fixtures. No external input."""

from dataclasses import asdict, dataclass, replace
import re

from .evidence_storage import utc
from .layered_evaluation import _run, load_corpus, observations
from .reference import ReferenceDataError


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int
    protocol: str


@dataclass(frozen=True)
class ConnectionStart:
    time: str
    vantage: str
    interface: str
    local_address: str
    local_port: int
    remote: Endpoint


@dataclass(frozen=True)
class SocketOwner:
    producer: str
    execution: str
    connection: ConnectionStart


@dataclass(frozen=True)
class JobScope:
    """An exclusive destination for one synthetic host/boot/invocation."""

    producer: str
    execution: str
    valid_from: str
    valid_until: str
    remote: Endpoint


def _compare(starts, owners, scopes):
    """All records are internal synthetic fixtures with canonical UTC times."""
    def unknown(reason):
        return dict(status='unknown', reason=reason)

    if len(starts) != 5 or len({start.time for start in starts}) != 5:
        return unknown('five_distinct_starts_required')
    if len(scopes) != 1:
        return unknown('missing_or_ambiguous_job_scope')
    scope = scopes[0]
    if scope.producer != 'fixture-job-registry':
        return unknown('independent_job_scope_required')

    if (type(scope.execution) is not str
            or not re.fullmatch(r'host-[a-z]/boot-[a-z]/job-[1-9][0-9]{0,5}', scope.execution)):
        return unknown('execution_binding_unresolved')

    executions = set()
    # Report the earliest incomplete witness consistently if several fail.
    for start in sorted(starts, key=lambda item: item.time):
        matches = [owner for owner in owners if owner.connection == start]
        if len(matches) != 1:
            return unknown('missing_or_ambiguous_socket_owner')
        if matches[0].producer != 'fixture-socket-observer':
            return unknown('independent_socket_owner_required')
        executions.add(matches[0].execution)
    if executions != {scope.execution}:
        return unknown('execution_binding_unresolved')
    if not all(scope.valid_from <= start.time < scope.valid_until for start in starts):
        return unknown('scope_does_not_cover_every_start')

    outside = sorted(start.time for start in starts if start.remote != scope.remote)
    return dict(status='scope_mismatch' if outside else 'scope_match',
                execution=scope.execution, owner_source='fixture-socket-observer',
                scope_source=scope.producer, valid_from=scope.valid_from,
                valid_until=scope.valid_until, permitted_destination=asdict(scope.remote),
                outside_scope_starts=outside)


def _contexts():
    # Authored separately from the traffic rows. Neither producer copies input
    # to mint a witness. In a real system these identities would need attestation.
    base = 1790812800
    execution = 'host-a/boot-a/job-17'
    endpoint = Endpoint('198.51.100.200', 443, 'TCP')
    owners = tuple(SocketOwner('fixture-socket-observer', execution, ConnectionStart(
        utc(base + offset), 'synthetic-sensor', 'fixture0', '192.0.2.1', 40000, endpoint))
        for offset in (300, 310, 320, 330, 340))
    scope = JobScope('fixture-job-registry', execution, utc(base + 300),
                     utc(base + 341), endpoint)
    other_scope = replace(scope, remote=replace(endpoint, address='198.51.100.201'))
    other_owner = replace(owners[0], execution='host-a/boot-b/job-17')
    return (
        ('valid', owners, (scope,), 'scope_match'),
        ('different_permitted_destination', owners, (other_scope,), 'scope_mismatch'),
        ('missing_scope', owners, (), 'unknown'),
        ('missing_owner', (), (scope,), 'unknown'),
        ('partial_owner', owners[:-1], (scope,), 'unknown'),
        ('expired', owners, (replace(scope, valid_from=utc(base + 250), valid_until=utc(base + 299)),), 'unknown'),
        ('expires_at_last_start', owners, (replace(scope, valid_until=utc(base + 340)),), 'unknown'),
        ('wrong_execution', owners, (replace(scope, execution=other_owner.execution),), 'unknown'),
        ('pid_only', tuple(replace(owner, execution='17') for owner in owners),
         (replace(scope, execution='17'),), 'unknown'),
        ('contradictory_owner', owners + (other_owner,), (scope,), 'unknown'),
        ('contradictory_scope', owners, (scope, other_scope), 'unknown'),
        ('self_reported_owner', (replace(owners[0], producer='fixture-subject'),) + owners[1:],
         (scope,), 'unknown'),
        ('self_reported_scope', owners, (replace(scope, producer='fixture-subject'),), 'unknown'),
    )


def _support(rows, finding):
    refs = finding['evidence_refs']
    by_id = {row['id']: row for row in rows}
    if (len(rows) != 5 or len(by_id) != 5 or len(refs) != 5 or set(refs) != set(by_id)
            or finding['facts']['references_omitted'] != 0):
        raise ReferenceDataError('CADENCE_SCOPE_FIXTURE_SUPPORT')
    starts = []
    for ref in refs:
        row = by_id[ref]
        data = row['data']
        starts.append(ConnectionStart(data['first_seen'], row['source'], data['interface'],
                                      data['src_ip'], data['src_port'],
                                      Endpoint(data['dst_ip'], data['dst_port'], data['protocol'])))
    return starts


def cadence_scope_report():
    corpus, _ = load_corpus()
    by_id = {case['id']: case for case in corpus['cases']}
    results = []
    traffic = []
    unexpected = 0
    unsupported_matches = 0
    for case_id in ('scheduled_health_checks', 'suspicious_cadence_only'):
        case = by_id[case_id]
        rows, _ = observations(case, corpus['start'])
        gaps = case.get('gaps', [])
        traffic.append((sorted(rows, key=lambda row: row['id']), gaps))
        baseline = _run(rows, corpus['start'], gaps)
        if (baseline['gaps'] or baseline['layered'] or len(baseline['individual']) != 1
                or baseline['individual'][0]['rule'] != 'REGULAR_INTERVAL'):
            raise ReferenceDataError('CADENCE_SCOPE_FIXTURE_BASELINE')
        finding = baseline['individual'][0]
        starts = _support(rows, finding)
        comparisons = {}
        for name, owners, scopes, expected in _contexts():
            outcome = _compare(starts, owners, scopes)
            comparisons[name] = outcome
            if outcome['status'] != expected:
                unexpected += 1
                if outcome['status'] == 'scope_match':
                    unsupported_matches += 1
        results.append(dict(case=case_id, original_finding=finding,
                            layered_reviews=len(baseline['layered']),
                            observed_starts=[dict(time=start.time, **asdict(start.remote))
                                             for start in sorted(starts, key=lambda item: item.time)],
                            contexts=comparisons))
    twins_equal = all(results[0][key] == results[1][key] for key in
                      ('original_finding', 'observed_starts', 'contexts'))
    return dict(schema='megalodon-cadence-scope-replay-v1', synthetic_only=True,
                all_match=unexpected == 0 and twins_equal and traffic[0] == traffic[1],
                identical_detector_inputs=traffic[0] == traffic[1],
                unexpected_results=unexpected, unsupported_scope_matches=unsupported_matches,
                cases=results,
                network_access_performed=False, persistence_status='not_attempted',
                action_status='not_attempted')
