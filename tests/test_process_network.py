"""Read-only socket-to-program map over synthetic /proc trees."""
import ipaddress
import json
import os
import socket
import subprocess
import sys

import pytest

from megalodon import process_network
from megalodon.process_network import MAX_PROGRAMS, SCHEMA, review, sockets

NOW = '2026-10-18T08:00:00Z'
HEAD = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
UID = os.getuid()


@pytest.fixture(autouse=True)
def passive(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError('the process review must never send traffic or run a program')
    for name in ('create_connection', 'getaddrinfo'):
        monkeypatch.setattr(socket, name, refuse)
    for name in ('run', 'Popen', 'call', 'check_call', 'check_output'):
        monkeypatch.setattr(subprocess, name, refuse)
    monkeypatch.setattr(os, 'kill', refuse)


def endpoint(address, port, order=sys.byteorder):
    packed = ipaddress.ip_address(address).packed
    return ''.join(f'{int.from_bytes(packed[i:i + 4], order):08X}' for i in range(0, len(packed), 4)) + f':{port:04X}'


def row(local, remote, state, inode):
    return f'   0: {endpoint(*local)} {endpoint(*remote)} {state} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1\n'


def proc(root, pid, exe, inodes, comm='prog', ppid=1, cmdline=b''):
    base = root/'proc'/str(pid)
    (base/'fd').mkdir(parents=True)
    os.symlink(exe, base/'exe')
    (base/'comm').write_text(comm + '\n')
    (base/'stat').write_text(f'{pid} ({comm}) S {ppid} 1 1 0\n')
    (base/'cmdline').write_bytes(cmdline)
    for index, inode in enumerate(inodes):
        os.symlink(f'socket:[{inode}]', base/'fd'/str(index + 3))
    os.symlink('/dev/null', base/'fd'/'0')


def tables(root, tcp=(), tcp6=(), udp=(), udp6=(), ipv6=True):
    (root/'proc/net').mkdir(parents=True, exist_ok=True)
    for name, rows in (('tcp', tcp), ('udp', udp)) + ((('tcp6', tcp6), ('udp6', udp6)) if ipv6 else ()):
        (root/'proc/net'/name).write_text(HEAD + ''.join(rows))
    if ipv6:
        (root/'proc/net/if_inet6').write_text('')


@pytest.fixture
def host(tmp_path):
    tables(tmp_path,
           tcp=[row(('192.168.1.5', 51000), ('203.0.113.9', 443), '01', 101),
                row(('0.0.0.0', 8080), ('0.0.0.0', 0), '0A', 102),
                row(('127.0.0.1', 5000), ('127.0.0.1', 51001), '01', 103),
                row(('127.0.0.1', 631), ('0.0.0.0', 0), '0A', 104),
                row(('192.168.1.5', 51002), ('203.0.113.10', 443), '01', 105)],
           tcp6=[row(('::ffff:192.168.1.5', 51003), ('::ffff:198.51.100.7', 22), '01', 106),
                 row(('2001:db8::5', 51004), ('2001:db8::9', 443), '06', 107)],
           udp=[row(('0.0.0.0', 5353), ('0.0.0.0', 0), '07', 108)])
    (tmp_path/'proc/1').mkdir(parents=True)
    (tmp_path/'proc/1/comm').write_text('systemd\n')
    proc(tmp_path, 200, '/usr/bin/curl', [101, 103], comm='curl', cmdline=b'curl\0--token=SECRET-VALUE\0')
    proc(tmp_path, 201, '/usr/bin/curl', [105], comm='curl')
    proc(tmp_path, 300, '/home/u/.cache/x (deleted)', [102], comm='x')
    proc(tmp_path, 301, '/memfd:payload (deleted)', [106], comm='payload')
    proc(tmp_path, 302, '/tmp/tool', [107, 108], comm='tool')
    proc(tmp_path, 303, '/usr/sbin/cupsd', [104], comm='cupsd')
    proc(tmp_path, 304, '/usr/bin/idle', [], comm='idle')
    return tmp_path


def by_exe(result):
    return {r['executable']: r for r in result['programs']}


def test_programs_are_named_by_executable_with_counts_and_remotes(host):
    result = review(host, uid=UID, now=lambda: NOW)
    rows = by_exe(result)
    curl = rows['/usr/bin/curl']
    assert curl['processes'] == 2 and curl['established'] == 2 and curl['parent'] == 'systemd'
    assert curl['remotes'] == ['203.0.113.10:443', '203.0.113.9:443'] and curl['flags'] == []
    assert rows['/memfd:payload']['remotes'] == ['198.51.100.7:22']  # IPv4-mapped peers show as IPv4
    assert rows['/tmp/tool']['other'] == 1 and rows['/tmp/tool']['listening'] == 1  # TIME_WAIT and a bound UDP socket
    assert '/usr/sbin/cupsd' not in rows and '/usr/bin/idle' not in rows  # loopback-only and socket-free programs
    assert result['schema'] == SCHEMA and result['action_authority'] == 'none' and result['action_status'] == 'not_attempted'
    assert 'SECRET-VALUE' not in json.dumps(result)


def test_flags_and_review_ordering(host):
    result = review(host, uid=UID, now=lambda: NOW)
    rows = by_exe(result)
    assert rows['/home/u/.cache/x']['flags'] == ['EXECUTABLE_DELETED']
    assert rows['/memfd:payload']['flags'] == ['EXECUTABLE_IN_MEMORY']  # not also reported as deleted
    assert rows['/tmp/tool']['flags'] == ['EXECUTABLE_IN_TEMPORARY']
    assert [bool(r['flags']) for r in result['programs']] == [True, True, True, False]
    assert result['flagged_total'] == 3 and result['programs_total'] == 4


def test_other_accounts_are_not_reviewed(host):
    result = review(host, uid=UID + 1, now=lambda: NOW)
    assert result['programs'] == [] and result['processes_reviewed'] == 0
    assert any('other accounts and of root' in gap for gap in result['gaps'])


def test_program_list_is_bounded_with_flagged_programs_first(tmp_path):
    rows = [row(('192.168.1.5', 40000 + i), ('203.0.113.9', 443), '01', 1000 + i) for i in range(MAX_PROGRAMS + 4)]
    tables(tmp_path, tcp=rows)
    for i in range(MAX_PROGRAMS + 3):
        proc(tmp_path, 400 + i, f'/usr/bin/p{i:02d}', [1000 + i])
    proc(tmp_path, 900, '/tmp/late', [1000 + MAX_PROGRAMS + 3])
    result = review(tmp_path, uid=UID, now=lambda: NOW)
    assert len(result['programs']) == MAX_PROGRAMS and result['programs_total'] == MAX_PROGRAMS + 4
    assert result['programs'][0]['executable'] == '/tmp/late'
    assert any(gap.startswith(f'{MAX_PROGRAMS + 4} programs hold network sockets') for gap in result['gaps'])


def test_scan_and_table_bounds_are_disclosed(host, monkeypatch):
    monkeypatch.setattr(process_network, 'MAX_FD_LINKS', 2)
    result = review(host, uid=UID, now=lambda: NOW)
    assert result['scan_complete'] is False and any('process scan stopped' in gap for gap in result['gaps'])
    monkeypatch.setattr(process_network, 'MAX_FD_LINKS', 65536)
    monkeypatch.setattr(process_network, 'MAX_TABLE_READ', 200)
    result = review(host, uid=UID, now=lambda: NOW)
    assert result['tables_complete'] is False and any('not fully read' in gap for gap in result['gaps'])


def test_missing_ipv6_tables_are_complete_only_without_ipv6(tmp_path):
    tables(tmp_path, tcp=[row(('192.168.1.5', 1), ('203.0.113.9', 443), '01', 5)], ipv6=False)
    assert sockets(tmp_path)[1] is True
    (tmp_path/'proc/net/if_inet6').write_text('')
    assert sockets(tmp_path)[1] is False


def test_addresses_decode_in_host_byte_order(tmp_path, monkeypatch):
    monkeypatch.setattr(process_network, '_BYTE_ORDER', 'big')
    (tmp_path/'proc/net').mkdir(parents=True)
    line = (f"   0: {endpoint('192.168.1.5', 1, 'big')} {endpoint('203.0.113.9', 443, 'big')} 01 0:0 0:0 0 0 0 9 1\n")
    (tmp_path/'proc/net/tcp').write_text(HEAD + line)
    six = f"   0: {endpoint('2001:db8::5', 1, 'big')} {endpoint('2001:db8::9', 443, 'big')} 01 0:0 0:0 0 0 0 10 1\n"
    (tmp_path/'proc/net/tcp6').write_text(HEAD + six)
    found, _ = sockets(tmp_path)
    assert found[9]['remote'] == '203.0.113.9:443' and found[10]['remote'] == '[2001:db8::9]:443'


def test_text_is_bounded_by_escaped_size(tmp_path):
    long = '/opt/' + '\U0001F600' * 200
    tables(tmp_path, tcp=[row(('192.168.1.5', 1), ('203.0.113.9', 443), '01', 7)])
    proc(tmp_path, 500, long, [7], comm='\U0001F600' * 5)
    shown = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert all(len(json.dumps(shown[k])) <= process_network.MAX_TEXT_BYTES for k in ('program', 'executable', 'parent'))
    assert shown['executable'].endswith('...')


@pytest.mark.parametrize('field', ['-0000001:01BB', '0000_001:01BB', '0A00000+:01BB', 'C0A80105:-001', 'zzzzzzzz:01BB'])
def test_signed_or_non_hex_endpoints_are_skipped(tmp_path, field):
    (tmp_path/'proc/net').mkdir(parents=True)
    good = f"   0: {endpoint('192.168.1.5', 1)} {endpoint('203.0.113.9', 443)} 01 0:0 0:0 0 0 0 9 1\n"
    bad = f"   1: {field} {endpoint('203.0.113.9', 443)} 01 0:0 0:0 0 0 0 10 1\n"
    (tmp_path/'proc/net/tcp').write_text(HEAD + good + bad)
    found, _ = sockets(tmp_path)
    assert set(found) == {9}
