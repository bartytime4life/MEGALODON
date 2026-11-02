"""Linux-only lab for the sender-identity assumption in the cadence scope replay."""

from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass, replace
import errno
import json
import multiprocessing
import os
import socket
import struct
import sys
import time

CHANNELS = 5
CLAIM = b'fixture-job-a'
UCRED = struct.Struct('=iII')  # Linux pid_t, uid_t, gid_t
TIME_BUDGET = 8


def _sender(pairs, release_reader, release_writer, other_pid):
    """Fixed child program. Only the second sender tries a false kernel credential."""
    try:
        os.close(release_writer)
        for index, (receiver, sender) in enumerate(pairs):
            receiver.close()
            if index == 0 and other_pid is not None:
                # Exercise the same sendmsg/SCM_CREDENTIALS path with a valid
                # PID before trying the registered child's PID.
                own = UCRED.pack(os.getpid(), os.getuid(), os.getgid())
                sent = sender.sendmsg([CLAIM], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, own)])
            else:
                sent = sender.send(CLAIM)
            if sent != len(CLAIM):
                raise SystemExit(2)
        if other_pid is not None:
            cred = UCRED.pack(other_pid, os.getuid(), os.getgid())
            try:
                pairs[0][1].sendmsg([CLAIM], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, cred)])
            except OSError as exc:
                if exc.errno != errno.EPERM:
                    raise SystemExit(2)
            else:
                raise SystemExit(1)
        # The parent holds both live identities until it has read the evidence.
        if os.read(release_reader, 1) != b'x':
            raise SystemExit(2)
    except OSError:
        raise SystemExit(2)


def _classify(packet, registered_pid, second_pid, uid, gid):
    data, control, flags, _ = packet
    if (data != CLAIM or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(control) != 1 or registered_pid == second_pid):
        return 'unknown'
    level, kind, raw = control[0]
    if (level, kind, len(raw)) != (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, UCRED.size):
        return 'unknown'
    pid, real_uid, real_gid = UCRED.unpack(raw)
    if (real_uid, real_gid) != (uid, gid):
        return 'unknown'
    if pid == registered_pid:
        return 'registered_sender'
    return 'other_sender' if pid == second_pid else 'unknown'


@dataclass(frozen=True)
class _JobGrant:
    """Parent-issued permission for one live invocation and specific receiver objects."""

    subject: object
    receivers: tuple
    issued: float
    expires: float
    revoked: float | None = None

    def assess(self, sender, receiver, now):
        if sender is None:
            return 'unknown_sender'
        if sender is not self.subject:
            return 'no_matching_grant'
        if not self.issued <= now < self.expires:
            return 'inactive_grant'
        if self.revoked is not None and self.revoked <= now:
            return 'revoked_grant'
        if not any(receiver is allowed for allowed in self.receivers):
            return 'outside_scope'
        return 'in_scope'


def _scope_summary(by_channel):
    # Independent expected outcomes for this fixed five-channel experiment.
    expected = ('in_scope', 'in_scope', 'outside_scope', 'revoked_grant', 'revoked_grant')
    totals = Counter()
    matches = len(by_channel) == len(expected)
    unexpected_permits = 0
    for index, records in enumerate(by_channel):
        wanted = expected[index] if index < len(expected) else None
        if sorted(records) != [('other_sender', 'no_matching_grant'), ('registered_sender', wanted)]:
            matches = False
        permits = sum(decision == 'in_scope' for _, decision in records)
        supported = wanted == 'in_scope' and ('registered_sender', 'in_scope') in records
        unexpected_permits += permits - int(supported)
        totals.update(decision for _, decision in records)
    return dict(all_match=matches, decisions=dict(sorted(totals.items())),
                would_permit=totals['in_scope'], would_deny=totals.total() - totals['in_scope'],
                unsupported_permits=unexpected_permits)


def _remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError
    return seconds


def _reap(child):
    # Only a process started by this invocation is eligible for cleanup.
    if child.is_alive():
        child.kill()
    child.join()
    child.close()


def _probe(*, job_scope=False):
    deadline = time.monotonic() + TIME_BUDGET
    ctx = multiprocessing.get_context('fork')
    with ExitStack() as resources:
        pairs = []
        for _ in range(CHANNELS):
            receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            resources.enter_context(receiver)
            resources.enter_context(sender)
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            sender.settimeout(TIME_BUDGET)
            pairs.append((receiver, sender))
        reader, writer = os.pipe()
        resources.callback(os.close, reader)
        resources.callback(os.close, writer)

        children = []
        grant = None
        scope_records = []
        for _ in range(2):
            other_pid = children[0].pid if children else None
            child = ctx.Process(target=_sender, args=(pairs, reader, writer, other_pid))
            if job_scope and not children:
                # Issue before either child starts. The grant binds object
                # identities, which cannot cross invocations or socket pairs.
                receivers = tuple(pairs[i][0] for i in (0, 1, 3, 4))
                grant = _JobGrant(child, receivers, time.monotonic(), deadline)
            child.start()
            resources.callback(_reap, child)
            children.append(child)
        for _, sender in pairs:
            sender.close()

        totals = Counter()
        complete_channels = 0
        subjects = dict(registered_sender=children[0], other_sender=children[1])
        for index, (receiver, _) in enumerate(pairs):
            if grant is not None and index == 3:
                # Policy time is the parent's decision time, even for queued packets.
                grant = replace(grant, revoked=time.monotonic())
            decisions = []
            seen = []
            for _ in children:
                receiver.settimeout(_remaining(deadline))
                packet = receiver.recvmsg(len(CLAIM), socket.CMSG_SPACE(UCRED.size))
                label = _classify(packet, children[0].pid, children[1].pid,
                                  os.getuid(), os.getgid())
                seen.append(label)
                if grant is not None:
                    decision = grant.assess(subjects.get(label), receiver, time.monotonic())
                    decisions.append((label, decision))
            if grant is not None:
                scope_records.append(decisions)
            totals.update(seen)
            if sorted(seen) == ['other_sender', 'registered_sender']:
                complete_channels += 1

        os.write(writer, b'xx')
        for child in children:
            child.join(_remaining(deadline))
            if child.exitcode is None:
                raise TimeoutError
        if children[0].exitcode != 0 or children[1].exitcode not in (0, 1):
            raise OSError('fixture child did not complete')
        forgery_refused = children[1].exitcode == 0
        # Reaping the only writers must leave EOF on every channel. The two
        # expected records alone cannot demonstrate the absence of an extra one.
        extra = False
        for receiver, _ in pairs:
            receiver.settimeout(_remaining(deadline))
            if receiver.recv(1):
                extra = True
        passed = complete_channels == CHANNELS and forgery_refused and not extra
        result = dict(complete_channels=complete_channels, sender_counts=dict(sorted(totals.items())),
                      other_pid_claim_refused=forgery_refused, extra_record=extra)
        if job_scope and passed:
            result['job_scope'] = _scope_summary(scope_records)
            result['job_authorization'] = 'fixture_policy_at_receipt'
            passed = result['job_scope']['all_match']
        result.update(status='passed' if passed else 'failed', all_match=passed)
        return result


def main(argv=None):
    args = tuple(sys.argv[1:] if argv is None else argv)
    result = dict(schema='megalodon-linux-sender-replay-v1', all_match=False,
                  evidence_scope='disposable_local_unix_sockets',
                  job_authorization='not_evaluated', tcp_ownership='not_evaluated')
    job_scope = args == ('--job-scope',)
    if job_scope:
        result['schema'] = 'megalodon-linux-job-scope-replay-v1'
    if args and not job_scope:
        result.update(status='inconclusive', reason='no_arguments_accepted')
    elif (sys.platform != 'linux' or not hasattr(socket, 'SCM_CREDENTIALS')
          or not hasattr(socket, 'SO_PASSCRED') or not hasattr(socket, 'SOCK_SEQPACKET')):
        result.update(status='inconclusive', reason='linux_credentials_required')
    elif os.getuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
        result.update(status='inconclusive', reason='ordinary_account_required')
    else:
        try:
            result.update(_probe(job_scope=job_scope))
        except PermissionError:
            result.update(status='inconclusive', reason='kernel_operation_denied')
        except (OSError, RuntimeError):
            result.update(status='inconclusive', reason='fixture_did_not_complete')
    print(json.dumps(result, sort_keys=True))
    return {'passed': 0, 'failed': 1, 'inconclusive': 2}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
