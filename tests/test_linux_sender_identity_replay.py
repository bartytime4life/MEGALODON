"""Checks for the private Linux sender lab. The CI CLI step exercises the kernel."""

import errno
from io import BytesIO
import json
import os
import socket
import sys

import pytest

from tools import replay_linux_sender_identity as lab


linux = pytest.mark.skipif(not hasattr(socket, 'SCM_CREDENTIALS'), reason='Linux credentials')


@linux
def test_same_claim_and_account_distinguishes_only_the_registered_process():
    for pid, uid, gid, expected in (
        (11, 1000, 1000, 'registered_sender'), (12, 1000, 1000, 'other_sender'),
        (13, 1000, 1000, 'unknown'), (11, 1001, 1000, 'unknown'), (11, 1000, 1001, 'unknown'),
    ):
        control = [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, lab.UCRED.pack(pid, uid, gid))]
        packet = (lab.CLAIM, control, 0, None)
        assert lab._classify(packet, 11, 12, 1000, 1000) == expected
        assert lab._classify(packet, 11, 11, 1000, 1000) == 'unknown'


@linux
def test_missing_truncated_extra_or_wrong_credentials_cannot_identify_a_sender():
    raw = lab.UCRED.pack(11, 1000, 1000)
    credential = (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, raw)
    for control in ([], [credential, credential], [(0, credential[1], raw)],
                    [(credential[0], socket.SCM_RIGHTS, raw)],
                    [(credential[0], credential[1], raw[:-1])]):
        assert lab._classify((lab.CLAIM, control, 0, None), 11, 12, 1000, 1000) == 'unknown'
    for data, flags in ((b'', 0), (b'job-b', 0), (lab.CLAIM, socket.MSG_TRUNC),
                        (lab.CLAIM, socket.MSG_CTRUNC)):
        assert lab._classify((data, [credential], flags, None), 11, 12, 1000, 1000) == 'unknown'


def test_cli_rejects_external_input_and_unsupported_platforms_before_start(monkeypatch, capsys):
    monkeypatch.setattr(lab, '_probe', lambda: pytest.fail('unexpected process or socket'))
    assert lab.main(['--file', 'private-data']) == 2
    refusal = json.loads(capsys.readouterr().out)
    assert refusal['reason'] == 'no_arguments_accepted' and 'private-data' not in str(refusal)
    monkeypatch.setattr(sys, 'platform', 'not-linux')
    assert lab.main([]) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'linux_credentials_required'


@linux
def test_elevated_identity_is_refused_even_on_supported_systems(monkeypatch, capsys):
    monkeypatch.setattr(lab.os, 'getuid', lambda: 0)
    monkeypatch.setattr(lab, '_probe', lambda: pytest.fail('unexpected process or socket'))
    assert lab.main([]) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'ordinary_account_required'


@linux
@pytest.mark.parametrize('error, reason', [(PermissionError, 'kernel_operation_denied'),
                                           (TimeoutError, 'fixture_did_not_complete')])
def test_unavailable_kernel_evidence_is_inconclusive(monkeypatch, capsys, error, reason):
    def unavailable():
        raise error('untrusted diagnostic')

    for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
        monkeypatch.setattr(lab.os, name, lambda: 1000)
    monkeypatch.setattr(lab, '_probe', unavailable)
    assert lab.main([]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result['all_match'] is False and result['reason'] == reason
    assert 'untrusted diagnostic' not in str(result)


@linux
@pytest.mark.parametrize('self_errno, other_errno, exit_code', [
    (None, errno.EPERM, 0), (errno.EPERM, None, 2), (None, errno.EACCES, 2), (None, None, 1),
])
def test_forgery_probe_requires_successful_self_control_and_exact_eperm(self_errno, other_errno, exit_code):
    seen = []
    own = os.getpid()
    other = own + 1  # Only a field for the simulated syscall below.

    class Sender:
        def sendmsg(self, parts, control):
            level, kind, raw = control[0]
            assert parts == [lab.CLAIM] and (level, kind) == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS)
            pid, uid, gid = lab.UCRED.unpack(raw)
            assert (uid, gid) == (os.getuid(), os.getgid())
            seen.append(pid)
            error = self_errno if pid == own else other_errno
            if error is not None:
                raise OSError(error, 'fixture')
            return len(lab.CLAIM)

    reader, writer = os.pipe()
    try:
        os.write(writer, b'x')
        if exit_code:
            with pytest.raises(SystemExit) as stopped:
                lab._sender([(BytesIO(), Sender())], reader, writer, other)
            assert stopped.value.code == exit_code
        else:
            lab._sender([(BytesIO(), Sender())], reader, writer, other)
        assert seen == ([own] if self_errno else [own, other])
    finally:
        os.close(reader)  # The child function closes its copy of the write end.
