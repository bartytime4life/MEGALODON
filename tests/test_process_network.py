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


def namespace(root, pid, name, rows=()):
    (root/'proc'/str(pid)/'ns').mkdir(parents=True, exist_ok=True)
    os.symlink(f'net:[{name}]', root/'proc'/str(pid)/'ns/net')
    if rows is not None:
        (root/'proc'/str(pid)/'net').mkdir(parents=True, exist_ok=True)
        (root/'proc'/str(pid)/'net/tcp').write_text(HEAD + ''.join(rows))
        (root/'proc'/str(pid)/'net/udp').write_text(HEAD)


def test_processes_in_another_network_namespace_use_its_tables(host):
    (host/'proc/self/ns').mkdir(parents=True)
    os.symlink('net:[1]', host/'proc/self/ns/net')
    proc(host, 700, '/usr/bin/podman-app', [900], comm='app')
    namespace(host, 700, 2, [row(('10.88.0.5', 40000), ('198.51.100.20', 443), '01', 900)])
    proc(host, 701, '/usr/bin/curl', [101], comm='curl')
    namespace(host, 701, 1, rows=None)  # the HUD's own namespace reads /proc/net
    result = review(host, uid=UID, now=lambda: NOW)
    rows = by_exe(result)
    assert rows['/usr/bin/podman-app']['remotes'] == ['198.51.100.20:443']
    assert rows['/usr/bin/curl']['processes'] == 3 and result['tables_complete'] is True


def test_namespaces_beyond_the_limit_are_disclosed(host, monkeypatch):
    monkeypatch.setattr(process_network, 'MAX_NAMESPACES', 1)
    for index in range(3):
        proc(host, 710 + index, f'/usr/bin/ns{index}', [910 + index])
        namespace(host, 710 + index, 10 + index, [row(('10.88.0.5', 40000), ('198.51.100.20', 443), '01', 910 + index)])
    result = review(host, uid=UID, now=lambda: NOW)
    assert '/usr/bin/ns0' in by_exe(result) and '/usr/bin/ns2' not in by_exe(result)
    assert result['tables_complete'] is False
    assert any(gap.startswith('2 more network namespaces were not read') for gap in result['gaps'])


def test_shared_sockets_are_counted_once_per_program(tmp_path):
    tables(tmp_path, tcp=[row(('0.0.0.0', 8080), ('0.0.0.0', 0), '0A', 1), row(('192.168.1.5', 2), ('203.0.113.9', 443), '01', 2)])
    proc(tmp_path, 800, '/usr/sbin/server', [1, 1, 2], comm='server')  # a duplicated descriptor
    proc(tmp_path, 801, '/usr/sbin/server', [1], comm='server')        # a worker inheriting the listener
    server = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert server['processes'] == 2 and server['listening'] == 1 and server['established'] == 1


def test_proc_entries_are_chosen_in_bounded_memory(host, monkeypatch):
    monkeypatch.setattr(process_network, 'MAX_PROC_ENTRIES', 3)
    result = review(host, uid=UID, now=lambda: NOW)
    assert result['scan_complete'] is False and result['processes_reviewed'] <= 3
    assert any(gap.startswith('The process scan stopped at 3 process entries') for gap in result['gaps'])


def test_a_socket_from_another_namespace_is_still_matched(host):
    # Socket activation: a PrivateNetwork= service holds a listener created in the host namespace.
    (host/'proc/self/ns').mkdir(parents=True)
    os.symlink('net:[1]', host/'proc/self/ns/net')
    proc(host, 720, '/usr/lib/activated', [102, 920], comm='activated')
    namespace(host, 720, 3, [row(('10.0.3.2', 41000), ('198.51.100.30', 443), '01', 920)])
    rows = by_exe(review(host, uid=UID, now=lambda: NOW))
    assert rows['/usr/lib/activated']['listening'] == 1 and rows['/usr/lib/activated']['established'] == 1


def hashed_host(tmp_path, content=b'\x7fELF fake program'):
    binary = tmp_path/'bin-store'/'tool'
    binary.parent.mkdir()
    binary.write_bytes(content)
    tables(tmp_path, tcp=[row(('192.168.1.5', 1), ('203.0.113.9', 443), '01', 7)])
    proc(tmp_path, 500, str(binary), [7], comm='tool')
    return binary


@pytest.fixture(autouse=True)
def fresh_hash_cache(monkeypatch):
    process_network._hashes.clear()
    monkeypatch.setattr(process_network, '_hasher', None)
    yield
    process_network._hashes.clear()


def test_listed_executables_are_hashed_once_per_file_identity(tmp_path, monkeypatch):
    import hashlib
    binary = hashed_host(tmp_path)
    shown = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert shown['hash_status'] == 'hashed' and shown['sha256'] == hashlib.sha256(binary.read_bytes()).hexdigest()
    hashing = []
    original = hashlib.sha256
    monkeypatch.setattr(process_network.hashlib, 'sha256', lambda *a: hashing.append(1) or original(*a))
    again = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert again['sha256'] == shown['sha256'] and hashing == []  # served from the identity cache, not re-read
    binary.write_bytes(b'\x7fELF a different program')  # a new identity is hashed again
    same_size = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]['sha256']
    stamp = binary.stat()
    binary.write_bytes(b'\x7fELF a sneakier program!')  # same size, modification time set back
    os.utime(binary, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    assert review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]['sha256'] != same_size
    assert review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]['sha256'] != shown['sha256']


@pytest.mark.parametrize('setting, value, status', [('MAX_HASH_FILE', 4, 'too_large'), ('MAX_HASH_REVIEW', 4, 'deferred')])
def test_hash_bounds_are_reported(tmp_path, monkeypatch, setting, value, status):
    hashed_host(tmp_path)
    monkeypatch.setattr(process_network, setting, value)
    result = review(tmp_path, uid=UID, now=lambda: NOW)
    assert result['programs'][0]['hash_status'] == status and result['programs'][0]['sha256'] is None
    assert any('were not hashed in this review' in gap for gap in result['gaps']) == (status == 'deferred')


def test_unreadable_and_changing_executables_are_not_hashed(tmp_path, monkeypatch):
    binary = hashed_host(tmp_path)
    original = os.read
    def growing(fd, n):
        data = original(fd, n)
        if data:
            with open(binary, 'ab') as handle:
                handle.write(b'more')
        return data
    monkeypatch.setattr(os, 'read', growing)
    assert review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]['hash_status'] == 'changed'
    monkeypatch.setattr(os, 'read', original)
    binary.unlink()
    shown = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert shown['hash_status'] == 'unreadable' and shown['sha256'] is None


def test_processes_running_different_files_at_one_path_get_separate_rows(tmp_path, monkeypatch):
    # A rolling update: the old process still runs the replaced file at the same path.
    old, new = hashed_host(tmp_path, b'\x7fELF old build'), tmp_path/'bin-store'/'tool-new'
    new.write_bytes(b'\x7fELF new build!')
    tables(tmp_path, tcp=[row(('192.168.1.5', 1), ('203.0.113.9', 443), '01', 7),
                          row(('192.168.1.5', 2), ('203.0.113.9', 443), '01', 8)])
    proc(tmp_path, 501, str(old), [8], comm='tool')
    (tmp_path/'proc/501/exe').unlink()
    os.symlink(str(old), tmp_path/'proc/501/exe')
    real_stat = os.stat
    def stat(path, *a, **k):
        # Same path text for both, but process 501 runs the new file.
        return real_stat(new if str(path).endswith('/501/exe') else path, *a, **k)
    monkeypatch.setattr(process_network.os, 'stat', stat)
    monkeypatch.setattr(process_network, '_executable_hash',
                        lambda proc, budget, identity: (('b' if proc.name == '501' else 'a') * 64, 'hashed', 0))
    rows = review(tmp_path, uid=UID, now=lambda: NOW)['programs']
    assert [(r['executable'], r['processes'], r['sha256'][0]) for r in sorted(rows, key=lambda r: r['sha256'])] == [
        (str(old), 1, 'a'), (str(old), 1, 'b')]


def test_a_same_size_rewrite_during_hashing_is_changed(tmp_path, monkeypatch):
    binary = hashed_host(tmp_path)
    stamp, original, done = binary.stat(), os.read, []
    def rewriting(fd, n):
        data = original(fd, n)
        if data and not done and os.fstat(fd).st_ino == stamp.st_ino:
            done.append(1)
            binary.write_bytes(b'X' * stamp.st_size)  # same size, then the modification time set back
            os.utime(binary, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        return data
    monkeypatch.setattr(os, 'read', rewriting)
    shown = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert shown['hash_status'] == 'changed' and shown['sha256'] is None and not process_network._hashes


def test_every_coverage_gap_at_once_stays_within_the_bound(host, monkeypatch):
    for index in range(2):  # two extra namespaces, one beyond the limit
        proc(host, 205 + index, f'/usr/bin/ns{index}', [930 + index])
        namespace(host, 205 + index, 30 + index, [row(('10.88.0.5', 40000), ('198.51.100.20', 443), '01', 930 + index)])
    binary = host/'bin-store'/'tool'  # a real, temporary-folder executable that sorts first and is deferred
    binary.parent.mkdir()
    binary.write_bytes(b'\x7fELF tool')
    tcp = (host/'proc/net/tcp').read_text() + ''.join(row(('192.168.1.5', 60000 + i), ('203.0.113.50', 443), '01', 960 + i) for i in range(4))
    (host/'proc/net/tcp').write_text(tcp)
    proc(host, 210, str(binary), [960, 961, 962, 963], comm='tool')
    (host/'proc/2').mkdir()  # a process of this account whose descriptors cannot be listed
    (host/'proc/net/udp6').unlink()
    (host/'proc/net/udp6').mkdir()  # an unreadable table
    entries = sum(1 for name in os.listdir(host/'proc') if name.isdigit())
    for name, value in (('MAX_NAMESPACES', 1), ('MAX_PROGRAMS', 1), ('MAX_HASH_REVIEW', 0), ('MAX_PROC_ENTRIES', entries - 1)):
        monkeypatch.setattr(process_network, name, value)
    result = review(host, uid=UID, now=lambda: NOW)
    assert result['programs'][0]['hash_status'] == 'deferred'
    assert len(result['gaps']) == 7 <= process_network.MAX_GAPS, result['gaps']


def test_an_executable_replaced_after_the_scan_is_not_hashed(tmp_path, monkeypatch):
    # The process calls exec (or its PID is reused) between the scan and hashing.
    binary = hashed_host(tmp_path)
    other = tmp_path/'bin-store'/'other'
    other.write_bytes(b'\x7fELF a different program')
    original = process_network.review.__globals__['_executable_hash']
    def swapped(proc, budget, identity):
        (proc/'exe').unlink()
        os.symlink(str(other), proc/'exe')
        return original(proc, budget, identity)
    monkeypatch.setattr(process_network, '_executable_hash', swapped)
    shown = review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]
    assert shown['executable'] == str(binary) and shown['hash_status'] == 'changed' and shown['sha256'] is None


def test_bytes_read_before_a_failure_count_against_the_budget(tmp_path, monkeypatch):
    first = hashed_host(tmp_path, b'A' * 100)
    second = tmp_path/'bin-store'/'second'
    second.write_bytes(b'B' * 100)
    tables(tmp_path, tcp=[row(('192.168.1.5', 1), ('203.0.113.9', 443), '01', 7),
                          row(('192.168.1.5', 2), ('203.0.113.9', 443), '01', 8)])
    proc(tmp_path, 501, str(second), [8], comm='second')
    original, failing = os.read, second.stat().st_ino  # 'second' sorts, and is hashed, first
    calls = []
    def flaky(fd, n):
        if os.fstat(fd).st_ino == failing:
            calls.append(1)
            if len(calls) > 1:
                raise OSError(5, 'I/O error')
        return original(fd, n)
    monkeypatch.setattr(os, 'read', flaky)
    monkeypatch.setattr(process_network, 'MAX_HASH_REVIEW', 150)
    rows = {r['executable']: r for r in review(tmp_path, uid=UID, now=lambda: NOW)['programs']}
    assert rows[str(second)]['hash_status'] == 'unreadable'
    assert rows[str(first)]['hash_status'] == 'deferred'  # the failed read's 100 bytes were charged


def test_an_exec_between_reading_the_path_and_the_stat_drops_the_row(tmp_path, monkeypatch):
    hashed_host(tmp_path)
    real_readlink, calls = os.readlink, []
    def readlink(path, *a, **k):
        if str(path).endswith('/500/exe'):
            calls.append(1)
            if len(calls) == 2:  # the re-read after the stat sees the new program
                return '/usr/bin/other'
        return real_readlink(path, *a, **k)
    monkeypatch.setattr(process_network.os, 'readlink', readlink)
    result = review(tmp_path, uid=UID, now=lambda: NOW)
    # The old path is never paired with the new file's identity.
    assert result['programs'] == [] and any('exited or could not be read' in gap for gap in result['gaps'])


def test_a_stalled_read_is_bounded_by_time_and_never_stacks_threads(tmp_path, monkeypatch):
    from threading import Event
    import threading
    hashed_host(tmp_path)
    release = Event()
    original = process_network._executable_hash
    def stalled(proc, budget, identity):
        assert release.wait(10)  # a read blocked on a stalled network or FUSE mount
        return original(proc, budget, identity)
    monkeypatch.setattr(process_network, '_executable_hash', stalled)
    monkeypatch.setattr(process_network, 'MAX_HASH_SECONDS', 0.2)
    first = review(tmp_path, uid=UID, now=lambda: NOW)
    assert first['programs'][0]['hash_status'] == 'deferred'
    assert any('hashing limit was reached' in gap for gap in first['gaps'])
    second = review(tmp_path, uid=UID, now=lambda: NOW)
    assert any('an earlier executable read has not finished' in gap for gap in second['gaps'])
    assert sum(1 for t in threading.enumerate() if t.name == 'megalodon-executable-hash') == 1
    release.set()
    process_network._hasher.join(10)
    assert review(tmp_path, uid=UID, now=lambda: NOW)['programs'][0]['hash_status'] == 'hashed'
