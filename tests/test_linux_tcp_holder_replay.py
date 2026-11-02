"""Boundary and oracle tests; Ubuntu CI separately runs the native loopback lab."""
import errno
import json
import os
import socket
import struct
import sys

import pytest

from tools import replay_linux_tcp_holder as lab


KEY = lab._socket_id(13579, 24680)
COOKIE = b'cookie01'
UID = 1234
ROW = lab.KernelSocket(345, COOKIE)
linux = pytest.mark.skipif(sys.platform != 'linux', reason='Linux diagnostic ABI')


def packet(body, *, kind=20, flags=0, seq=1, peer=(0, 0), recv_flags=0):
    header = lab.HEADER.pack(16 + len(body), kind, flags, seq, 12345)
    return header + body, [], recv_flags, peer


def tcp_body(key=KEY, state=1, cookie=COOKIE, uid=UID, inode=345):
    return bytes((socket.AF_INET, state, 0, 0)) + key + bytes(4) + cookie + struct.pack('=5I', 0, 0, 0, uid, inode)


def test_request_is_ipv4_tcp_and_targets_one_oriented_tuple_without_dump_flags():
    request = lab._request(KEY, COOKIE, 7)
    assert lab.HEADER.unpack_from(request) == (72, 20, 1, 7, 0)
    assert struct.unpack_from('=BBBBI', request, 16) == (socket.AF_INET, socket.IPPROTO_TCP, 0, 0, 2)
    addr = b'\x7f\0\0\x01' + bytes(12)
    assert request[24:60] == struct.pack('!HH', 13579, 24680) + addr + addr
    assert request[60:] == bytes(4) + COOKIE
    for ports in [(0, 10), (65536, 4), (5, 5)]:
        with pytest.raises(ValueError):
            lab._socket_id(*ports)


@linux
def test_requires_one_complete_established_socket_reply_from_the_kernel():
    valid = packet(tcp_body())
    assert lab._decode(valid, KEY, lab.NO_COOKIE, 1, UID) == ROW
    assert lab._decode(valid, KEY, COOKIE, 1, UID) == ROW
    assert lab._decode(packet(tcp_body(state=6, inode=0)), KEY, COOKIE, 1, UID) is None
    for bad in (packet(tcp_body(), seq=2), packet(tcp_body(), peer=(99, 0)),
                packet(tcp_body(), flags=2), packet(tcp_body(), recv_flags=socket.MSG_TRUNC),
                packet(tcp_body(), recv_flags=socket.MSG_CTRUNC), packet(tcp_body()[:-1]),
                packet(tcp_body(key=lab._socket_id(24680, 13579))), packet(tcp_body(uid=UID + 1)),
                packet(tcp_body(cookie=b'cookie02')), packet(tcp_body(inode=0)),
                packet(tcp_body(cookie=lab.NO_COOKIE)), packet(tcp_body(cookie=bytes(8))),
                (valid[0] + b'x', [], 0, (0, 0))):
        with pytest.raises(ValueError):
            lab._decode(bad, KEY, COOKIE, 1, UID)


@linux
def test_matched_absence_differs_from_access_denial_or_incomplete_error():
    header = lab._request(KEY, COOKIE, 1)[:16]
    for error in (errno.ENOENT, errno.ESTALE):
        assert lab._decode(packet(struct.pack('=i', -error) + header, kind=2), KEY, COOKIE, 1, UID) is None
    with pytest.raises(PermissionError):
        lab._decode(packet(struct.pack('=i', -errno.EPERM) + header, kind=2), KEY, COOKIE, 1, UID)
    for echo in (b'', header[:-1], bytes(16)):
        with pytest.raises(ValueError):
            lab._decode(packet(struct.pack('=i', -errno.ENOENT) + echo, kind=2), KEY, COOKIE, 1, UID)


def test_each_live_holder_needs_stable_descriptor_evidence_on_both_sides_of_lookup():
    assert lab.Observation((345, 999), ROW, (345, 999)).holders() == ('observed_holder', 'unknown')
    assert lab.Observation((345, None), ROW, (None, 345)).holders() == ('unknown', 'unknown')
    assert lab.Observation((345, 999), None, (345, 999)).holders() == ('unknown', 'unknown')


@linux
def test_only_named_descriptor_links_qualify(tmp_path):
    (tmp_path / '4').symlink_to('socket:[345]')
    (tmp_path / '5').symlink_to('pipe:[345]')
    (tmp_path / '6').symlink_to('socket:[456]')
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert lab._links(directory, (4, 5, 7)) == (345, None, None)
    finally:
        os.close(directory)


def test_move_and_close_need_independent_controls_even_when_output_labels_agree():
    opened = lab.Observation((345, 40), ROW, (345, 40))
    moved = lab.Observation((55, 345), ROW, (55, 345))
    closed = lab.Observation((55, None), None, (55, None))
    phases = dict(open=opened, moved=moved, closed=closed)
    assert lab._result(phases)['all_match'] is True
    for phase, bad in [('moved', moved._replace(current=lab.KernelSocket(345, b'cookie02'))),
                       ('moved', moved._replace(before=(None, 345), after=(None, 345))),
                       ('closed', closed._replace(before=(55, 345), after=(55, 345)))]:
        assert bad.holders() == phases[phase].holders()
        assert lab._result({**phases, phase: bad})['all_match'] is False


def test_cli_refuses_external_targets_before_any_probe(monkeypatch, capsys):
    monkeypatch.setattr(lab, '_probe', lambda: pytest.fail('unexpected socket'))
    assert lab.main(['--pid', 'private']) == 2
    result = capsys.readouterr().out
    assert 'private' not in result
    assert json.loads(result)['reason'] == 'no_arguments_accepted'
    monkeypatch.setattr(sys, 'platform', 'other')
    assert lab.main([]) == 2
    assert json.loads(capsys.readouterr().out)['reason'] == 'linux_diagnostics_required'


@linux
def test_restricted_kernel_cannot_supply_positive_evidence(monkeypatch, capsys):
    def denied():
        raise PermissionError('untrusted detail')

    for name in ('getuid', 'geteuid', 'getgid', 'getegid'):
        monkeypatch.setattr(lab.os, name, lambda: 1000)
    monkeypatch.setattr(lab, '_probe', denied)
    assert lab.main([]) == 2
    result = json.loads(capsys.readouterr().out)
    assert not result['all_match'] and result['reason'] == 'kernel_operation_denied'
    assert 'holder_by_slot' not in result and 'untrusted detail' not in str(result)
