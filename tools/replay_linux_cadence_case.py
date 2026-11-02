"""Produce one read-only cadence case from five controlled loopback connections."""

from contextlib import ExitStack
from dataclasses import dataclass
import json
import multiprocessing
import os
from pathlib import Path
import secrets
import socket
import sys
import time

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from megalodon.evidence_storage import epoch, utc
from megalodon.security_patterns import analyze_hour
from tools import replay_linux_tcp_holder as tcp
from tools.replay_linux_sender_identity import _JobGrant

COUNT = 5
INTERVAL = 3.0
BUDGET = 30.0
SOURCE = 'loopback-cadence-lab'


class NoCadence(Exception):
    """The measured input did not yield the required unmodified finding."""


@dataclass(eq=False)
class Flow:
    ref: str
    peer: tuple
    destination: tuple
    first_seen: str
    accepted: float
    released: float | None = None

    def row(self):
        return dict(id=self.ref, category='flows', source=SOURCE, observed_at=self.first_seen,
                    data=dict(src_ip=self.peer[0], src_port=self.peer[1], dst_ip=self.destination[0],
                              dst_port=self.destination[1], protocol='TCP', interface='lo',
                              source_id=self.ref, first_seen=self.first_seen))


@dataclass(frozen=True)
class Witness:
    flow: Flow
    subject: object
    begin: float
    end: float


@dataclass(frozen=True, eq=False)
class Destination:
    address: tuple
    alias: str


def _assessment(finding_refs, flows, witnesses, grant, destinations):
    evidence = []
    for ref in finding_refs:
        flow = flows[ref]
        witness = witnesses.get(ref)
        target = destinations.get(flow.destination)
        reason = 'missing_holder_at_observation'
        if witness is not None:
            if witness.flow is not flow:
                reason = 'unbound_observation'
            elif flow.released is None or not flow.accepted <= witness.begin <= witness.end <= flow.released:
                reason = 'outside_held_interval'
            elif target is None:
                reason = 'unrecognized_destination'
            elif witness.subject is not None:
                first = grant.assess(witness.subject, target, flow.accepted)
                last = grant.assess(witness.subject, target, witness.end)
                reason = first if first == last else 'grant_changed_during_observation'
        evidence.append(dict(ref=ref, decision=reason,
                             observed_destination=target.alias if target is not None else 'unknown'))
    missing = [e['ref'] for e in evidence if e['decision'] not in ('in_scope', 'outside_scope')]
    outside = [e['ref'] for e in evidence if e['decision'] == 'outside_scope']
    status = 'unknown' if missing else 'scope_mismatch' if outside else 'scope_match'
    outcome = dict(status=status, permitted_destination=grant.receivers[0].alias,
                   evidence=evidence, missing_refs=missing, outside_refs=outside)
    if missing:
        outcome['needed_evidence'] = 'A holder observation bound to this invocation and grant during each missing connection.'
    return outcome


def _case(flows, live, delayed, grants, destinations, close_verified):
    rows = [flow.row() for flow in flows]
    start = int(min(epoch(flow.first_seen) for flow in flows))
    _, findings, gaps = analyze_hour(rows, start, start + 3600, [])
    if gaps or len(findings) != 1 or findings[0]['rule'] != 'REGULAR_INTERVAL':
        raise NoCadence
    finding = findings[0]
    refs = finding['evidence_refs']
    indexed = {flow.ref: flow for flow in flows}
    if (len(flows) != COUNT or len(indexed) != COUNT or len(refs) != COUNT or set(refs) != set(indexed)
            or finding['facts']['references_omitted'] or finding['facts']['unique_observations'] != COUNT):
        raise NoCadence
    match = _assessment(refs, indexed, live, grants[0], destinations)
    mismatch = _assessment(refs, indexed, live, grants[1], destinations)
    late = _assessment(refs, indexed, delayed, grants[0], destinations)
    contexts = dict(matching_grant=match, conflicting_destination=mismatch, delayed_fifth_lookup=late)
    missing = max(flows, key=lambda flow: flow.accepted).ref
    unsupported = sum(case['status'] == 'scope_match' for case in (mismatch, late))
    late_reasons = {row['ref']: row['decision'] for row in late['evidence']}
    unsupported_refs = (sum(row['decision'] == 'in_scope' for row in mismatch['evidence'])
                        + int(late_reasons[missing] == 'in_scope'))
    passed = (not unsupported_refs and match['status'] == 'scope_match' and mismatch['status'] == 'scope_mismatch'
              and set(mismatch['outside_refs']) == set(refs) and late['status'] == 'unknown'
              and late['missing_refs'] == [missing] and late_reasons[missing] == 'outside_held_interval'
              and not late['outside_refs'] and close_verified
              and finding['state'] == 'unreviewed' and finding['action_status'] == 'not_attempted')
    # The shared projection uses the detector's own ID, state and citations. The
    # unmodified candidate is never sent through an authorization or response path.
    projection = {k: finding[k] for k in ('id', 'rule', 'what_happened', 'why_it_matters',
                                                    'state', 'action_status', 'evidence_refs')}
    return dict(status='passed' if passed else 'failed', all_match=passed, finding=projection,
                timing={k: finding['facts'][k] for k in ('median_interval_us', 'interval_spread_us')},
                contexts=contexts, delayed_slot_cleared=close_verified, unsupported_matches=unsupported,
                unsupported_reference_matches=unsupported_refs)


def _connect(clients, listener, reserved, endpoint, parent, control, deadline):
    try:
        parent.close()
        listener.close()
        reserved.close()
        control.send_bytes(b'R')
        for client in clients:
            tcp._expect(control, b'G', deadline)
            client.settimeout(tcp._remaining(deadline))
            client.connect(endpoint)
            tcp._expect(control, b'C', deadline)
            client.close()
            control.send_bytes(b'C')
        tcp._expect(control, b'Q', deadline)
    except (EOFError, OSError, ValueError):
        raise SystemExit(2)


def _witness(subject, directory, slot, diag, sequence, flow, expected_inode, deadline):
    # A new query for each view. The delayed lookup receives no live cookie or
    # holder result. Both views know the flow tuple from the parent's accept.
    key = tcp._socket_id(flow.peer[1], flow.destination[1])
    begin = time.monotonic()
    obs = tcp._observe(directory, (slot,), diag, key, tcp.NO_COOKIE, sequence, deadline)
    end = time.monotonic()
    held = obs.holders() == ('observed_holder',)
    if held and obs.current.inode != expected_inode:
        raise OSError('fixture socket identity changed')
    return Witness(flow, subject if held else None, begin, end), obs.before == obs.after == (None,)


def _probe():
    mono_anchor, wall_anchor = time.monotonic(), time.time()
    deadline = mono_anchor + BUDGET
    ctx = multiprocessing.get_context('fork')
    with ExitStack() as resources:
        def bound_socket():
            sock = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.bind((tcp.LOOPBACK, 0))
            return sock

        listener = bound_socket()
        listener.listen(1)
        service = Destination(listener.getsockname(), 'fixture-listener')
        reserved = bound_socket()
        alternate = Destination(reserved.getsockname(), 'reserved-alternate')
        destinations = {d.address: d for d in (service, alternate)}
        clients = [bound_socket() for _ in range(COUNT)]
        slots = [(s.fileno(), s.getsockname(), os.fstat(s.fileno()).st_ino) for s in clients]
        parent, control = ctx.Pipe()
        resources.enter_context(parent)
        resources.enter_context(control)
        child = ctx.Process(target=_connect, args=(clients, listener, reserved, service.address, parent, control, deadline))
        # Two counterfactual exclusive grants over the same invocation, issued before launch.
        issued = time.monotonic()
        grants = tuple(_JobGrant(child, (d,), issued, deadline) for d in (service, alternate))
        child.start()
        try:
            control.close()
            for client in clients:
                client.close()
            tcp._expect(parent, b'R', deadline)
            directory = os.open(f'/proc/{child.pid}/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            resources.callback(os.close, directory)
            diag = resources.enter_context(socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, tcp.NETLINK_SOCK_DIAG))
            segment = secrets.token_hex(16)
            flows, live, delayed = [], {}, {}
            close_verified = False
            schedule = time.monotonic()
            for index, (slot, local, expected_inode) in enumerate(slots):
                time.sleep(max(0, schedule + index * INTERVAL - time.monotonic()))
                listener.settimeout(tcp._remaining(deadline))
                parent.send_bytes(b'G')
                accepted, peer = listener.accept()
                seen = time.monotonic()
                with accepted:
                    destination = accepted.getsockname()
                    if peer != local or destination != service.address:
                        raise OSError('fixture endpoint mismatch')
                    flow = Flow(f'{segment}:{index + 1}', peer, destination,
                                utc(wall_anchor + (seen - mono_anchor)), seen)
                    flows.append(flow)
                    live[flow.ref], _ = _witness(child, directory, slot, diag, index + 1, flow,
                                                 expected_inode, deadline)
                    flow.released = time.monotonic()
                    parent.send_bytes(b'C')
                    tcp._expect(parent, b'C', deadline)
                    if index == COUNT - 1:
                        delayed[flow.ref], close_verified = _witness(child, directory, slot, diag, COUNT + 1,
                                                                    flow, expected_inode, deadline)
                    else:
                        delayed[flow.ref] = live[flow.ref]
            parent.send_bytes(b'Q')
            child.join(tcp._remaining(deadline))
            if child.exitcode != 0:
                raise OSError('fixture child incomplete')
            return _case(flows, live, delayed, grants, destinations, close_verified)
        finally:
            if child.is_alive():
                child.kill()
            child.join()
            child.close()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    result = dict(schema='megalodon-native-cadence-case-v1', status='inconclusive', all_match=False,
                  timing_basis='parent_accept_monotonic_elapsed', grant_basis='supervisor_fixture',
                  historical_ownership='not_evaluated', action_status='not_attempted')
    if args:
        result['reason'] = 'no_arguments_accepted'
    elif sys.platform != 'linux' or not hasattr(socket, 'AF_NETLINK'):
        result['reason'] = 'linux_diagnostics_required'
    elif os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        result['reason'] = 'ordinary_account_required'
    else:
        try:
            result.update(_probe())
        except NoCadence:
            result['reason'] = 'measured_cadence_finding_unavailable'
        except PermissionError:
            result['reason'] = 'kernel_operation_denied'
        except (EOFError, OSError, RuntimeError, ValueError):
            result['reason'] = 'fixture_did_not_complete'
    print(json.dumps(result, sort_keys=True))
    return {'passed': 0, 'failed': 1, 'inconclusive': 2}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
