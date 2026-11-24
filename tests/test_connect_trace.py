"""Connect tracing: BTF offsets, the eBPF program, joining connect and its addresses, and the egress watch naming
short connections. The live test runs only where an eBPF raw tracepoint can be loaded (root, BTF, Linux 5.8+)."""
from __future__ import annotations

import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

from megalodon import connect_trace as ct
from megalodon import egress_watch as ew


# ------------------------------------------------------------- a small BTF, built as the kernel lays it out

class BTFBuilder:
    def __init__(self):
        self.strings, self.types = bytearray(b'\0'), []

    def name(self, text):
        if not text:
            return 0
        offset = len(self.strings)
        self.strings += text.encode() + b'\0'
        return offset

    def add(self, kind, name, size, members=(), trailer=b'', kind_flag=False):
        info = (kind << 24) | len(members) | (1 << 31 if kind_flag else 0)
        data = struct.pack('<III', self.name(name), info, size) + trailer
        for member_name, member_type, bits in members:
            data += struct.pack('<III', self.name(member_name), member_type, bits)
        self.types.append(data)
        return len(self.types)

    def blob(self):
        types = b''.join(self.types)
        header = struct.pack('<HBBIIIII', 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(self.strings))
        return header + types + bytes(self.strings)


def kernel_like_btf():
    b = BTFBuilder()
    u32 = b.add(1, 'unsigned int', 4, trailer=struct.pack('<I', 32))
    pointer = b.add(2, '', u32)
    const = b.add(10, '', u32)                                   # a qualifier, resolved through
    inner = b.add(4, '', 8, [('skc_daddr', u32, 0), ('skc_rcv_saddr', u32, 32)])
    union = b.add(5, '', 8, [('skc_addrpair', u32, 0), ('', inner, 0)])
    const_union = b.add(10, '', union)                         # an anonymous member behind a qualifier
    # kind_flag: each offset's high 8 bits hold a bitfield size, not part of the offset.
    ports = b.add(4, '', 4, [('skc_dport', u32, (16 << 24) | 0), ('skc_num', u32, (16 << 24) | 16)],
                  kind_flag=True)
    b.add(4, 'sock_common', 64, [('', const_union, 0), ('', ports, 96), ('skc_family', u32, 128),
                                 ('skc_net', pointer, 192), ('skc_v6_daddr', const, 256),
                                 ('skc_v6_rcv_saddr', u32, 384)])
    b.add(4, 'task_struct', 4096, [('mm', pointer, 8192), ('real_parent', pointer, 16384), ('tgid', u32, 16448)])
    b.add(12, 'tcp_connect', 0)
    return b.blob()


def test_btf_offsets_look_into_anonymous_members_and_qualifiers():
    btf = ct.BTF(kernel_like_btf())
    layout = btf.offsets(btf.struct('sock_common'), ct.SOCK_FIELDS)
    assert layout == dict(skc_daddr=0, skc_rcv_saddr=4, skc_dport=12, skc_num=14, skc_family=16,
                          skc_v6_daddr=32, skc_v6_rcv_saddr=48)
    assert btf.offsets(btf.struct('task_struct'), ('real_parent', 'tgid')) == dict(real_parent=2048, tgid=2056)
    assert btf.function('tcp_connect') == len(btf.types) - 1
    with pytest.raises(ct.TraceError, match='no skc_missing'):
        btf.offsets(btf.struct('sock_common'), ('skc_missing',))
    with pytest.raises(ct.TraceError):
        btf.struct('not_there')
    with pytest.raises(ct.TraceError, match='not kernel BTF'):
        ct.BTF(b'\0' * 64)


def test_the_real_kernel_btf_is_read_where_there_is_one():
    if not os.path.exists(ct.BTF_PATH):
        pytest.skip('no kernel BTF here')
    with open(ct.BTF_PATH, 'rb') as stream:
        btf = ct.BTF(stream.read())
    layout = btf.offsets(btf.struct('sock_common'), ct.SOCK_FIELDS)
    assert layout['skc_dport'] + 2 == layout['skc_num']   # struct sock_common keeps the two ports side by side
    assert ct._net_offsets(btf) is not None and ct._exe_offsets(btf) is not None


# ------------------------------------------------------------- the program

def decode(code):
    return [struct.unpack('<BBhi', code[i:i + 8]) for i in range(0, len(code), 8)]


@pytest.mark.parametrize('extras', [dict(), dict(net=(48, 176)),
                                    dict(net=(48, 176), exe=(1136, 1320, 72, 40, 24, 64, 276))])
def test_the_program_filters_syn_sent_and_every_jump_lands_on_an_instruction(extras):
    code = ct.program(7, 80, 2048, 2056, **extras)
    insns = decode(code)
    assert insns[-1][0] == 0x95 and insns[-2][0] == 0xB7, 'ends by returning 0'
    exit_at = len(insns) - 2
    jumps = [(i, op, off, imm) for i, (op, _, off, imm) in enumerate(insns) if op in (0x15, 0x55)]
    for i, op, off, imm in jumps:
        assert 0 <= i + 1 + off <= exit_at, f'jump at {i} lands outside the program'
    # Leaving SYN_SENT is reported; else entering it; anything else skips straight to the return.
    (i1, _, off1, imm1), (_, op2, off2, imm2) = [(i, op, off, imm) for i, op, off, imm in jumps[:2]]
    assert imm1 == imm2 == ct.TCP_SYN_SENT and op2 == 0x55 and jumps[1][0] + 1 + off2 == exit_at
    reserve = next(i for i, (op, *_) in enumerate(insns) if op == 0x18)
    assert i1 + 1 + off1 == reserve, 'leaving SYN_SENT goes straight to the report'
    # The reserve's failure check jumps to the return as well.
    assert jumps[2][0] + 1 + jumps[2][2] == exit_at
    assert [imm for op, _, _, imm in insns if op == 0x18][0] == 7, 'the ring buffer map is the one created'
    helpers = [imm for op, _, _, imm in insns if op == 0x85]
    assert helpers[0] == ct.RINGBUF_RESERVE and helpers[-1] == ct.RINGBUF_SUBMIT
    assert helpers.count(ct.PROBE_READ_KERNEL_STR) == (ct.EXE_LEVELS if 'exe' in extras else 0)


@pytest.mark.parametrize('names, mount, tail', [
    (['agent', '.x', 'tmp', '/', '', ''], ('/', '/'), '/tmp/.x/agent'),
    # The names stop at the root of the file system the file is on: here /dev/shm, a mount of its own.
    (['helper', '.x', '/', '', '', ''], ('/', '/dev/shm'), '/dev/shm/.x/helper'),
    (['tool', 'sub', 'data', '/', '', ''], ('/data', '/mnt/x'), '/mnt/x/sub/tool'),   # a bind mount of a folder
    (['tool', 'other', '/', '', '', ''], ('/data', '/mnt/x'), '…/other/tool'),
    (['helper', '.x', '/', '', '', ''], None, '…/.x/helper'),                          # a mount not ours to read
    (['python3.13', 'bin', 'local', 'usr', 'opt', 'srv'], ('/', '/'), '…/srv/opt/usr/local/bin/python3.13'),
    (['', '', '', '', '', ''], ('/', '/'), None),
])
def test_the_kernel_path_tail(names, mount, tail):
    assert ct._tail(names, mount) == tail


def test_mount_points_are_read_from_mountinfo(tmp_path):
    info = tmp_path / 'mountinfo'
    info.write_text('22 27 0:21 / /proc rw - proc proc rw\n35 25 0:27 / /dev/shm rw - tmpfs tmpfs rw\n'
                    '40 27 8:1 /data /mnt/with\\040space rw - ext4 /dev/sda1 rw\n')
    assert ct.mounts(str(info)) == {22: ('/', '/proc'), 35: ('/', '/dev/shm'), 40: ('/data', '/mnt/with space')}
    assert ct.mounts(str(tmp_path / 'missing')) == {}


# ------------------------------------------------------------- joining a connect with its addresses

def record(trace, *, pid=40, parent=1, comm=b'curl', old, new, sk, netns=4026531833, family=socket.AF_INET,
           remote='9.9.9.9', local='10.0.0.2', rport=443, lport=51000, names=(), mount=1):
    data = bytearray(ct.EVENT_SOCK + trace.sock_bytes + (ct.EXE_LEVELS * ct.EXE_NAME if trace.exe_chain else 0))
    struct.pack_into('<QQ', data, 0, (pid << 32) | pid, (1000 << 32) | 1000)
    data[16:16 + len(comm)] = comm
    struct.pack_into('<III', data, ct.EVENT_PARENT, parent, old, new)
    struct.pack_into('<Q', data, ct.EVENT_SK, sk)
    struct.pack_into('<II', data, ct.EVENT_NETNS, netns, mount)
    sock, layout = ct.EVENT_SOCK, trace.layout
    struct.pack_into('<H', data, sock + layout['skc_family'], family)
    struct.pack_into('>H', data, sock + layout['skc_dport'], rport)
    struct.pack_into('<H', data, sock + layout['skc_num'], lport)
    if family == socket.AF_INET:
        data[sock + layout['skc_daddr']:sock + layout['skc_daddr'] + 4] = socket.inet_aton(remote)
        data[sock + layout['skc_rcv_saddr']:sock + layout['skc_rcv_saddr'] + 4] = socket.inet_aton(local)
    elif family == socket.AF_INET6:
        data[sock + layout['skc_v6_daddr']:sock + layout['skc_v6_daddr'] + 16] = socket.inet_pton(socket.AF_INET6,
                                                                                                remote)
    base = ct.EVENT_SOCK + trace.sock_bytes
    for level, name in enumerate(names):
        data[base + level * ct.EXE_NAME:base + level * ct.EXE_NAME + len(name)] = name.encode()
    return bytes(data)


@pytest.fixture
def trace():
    made = ct.ConnectTrace.__new__(ct.ConnectTrace)        # The joining and parsing, without the kernel.
    btf = ct.BTF(kernel_like_btf())
    made.layout = btf.offsets(btf.struct('sock_common'), ct.SOCK_FIELDS)
    made.sock_bytes = (max(made.layout.values()) + 16 + 7) // 8 * 8
    made.exe_chain, made.pending, made.fds, made.lost = (1, 2, 3, 4, 5, 6, 7), {}, [], 0
    made.known_mounts = {1: ('/', '/')}
    made.now = 100.0
    made.clock = lambda: made.now
    made.process = lambda pid: dict(path=f'/usr/bin/prog{pid}')
    return made


def test_a_connect_is_named_by_the_process_seen_entering_syn_sent(trace):
    out = trace.join([record(trace, old=7, new=2, sk=0xA, lport=0, names=['curl', 'bin', 'usr', '/'])])
    assert out == [], 'entering SYN_SENT has no local port yet'
    out = trace.join([record(trace, pid=0, comm=b'swapper/0', old=2, new=1, sk=0xA)])   # In softirq: not the owner.
    [named] = out
    assert named['pid'] == 40 and named['comm'] == 'curl' and named['process'] == dict(path='/usr/bin/prog40')
    assert named['exe_tail'] == '/usr/bin/curl' and named['connected'] is True
    assert (named['address'], named['port'], named['local_port']) == ('9.9.9.9', 443, 51000)
    assert (named['uid'], named['parent'], named['netns']) == (1000, 1, 4026531833)
    assert trace.pending == {}


def test_failed_and_unmatched_connects(trace):
    trace.join([record(trace, old=7, new=2, sk=0xB, lport=0)])
    [failed] = trace.join([record(trace, old=2, new=7, sk=0xB, lport=0)])
    assert failed['connected'] is False and failed['local_port'] == 0
    assert trace.join([record(trace, old=2, new=1, sk=0xC)]) == [], 'its connect came before the trace started'
    assert trace.join([record(trace, old=1, new=4, sk=0xD)]) == [], 'other state changes are not connects'
    trace.join([record(trace, old=7, new=2, sk=0xE, family=socket.AF_INET6, remote='2001:db8::7')])
    [six] = trace.join([record(trace, old=2, new=1, sk=0xE, family=socket.AF_INET6, remote='2001:db8::7')])
    assert six['address'] == '2001:db8::7'
    assert trace.join([record(trace, old=2, new=1, sk=0xF, family=99)]) == []


def test_pending_connects_expire_and_are_bounded(trace, monkeypatch):
    trace.join([record(trace, old=7, new=2, sk=0x1)])
    trace.now += ct.PENDING_SECONDS + 1
    trace.join([])
    assert trace.pending == {}
    monkeypatch.setattr(ct, 'MAX_PENDING', 2)
    trace.join([record(trace, old=7, new=2, sk=sk) for sk in (0x2, 0x3, 0x4)])
    assert set(trace.pending) == {0x3, 0x4} and trace.lost == 1


def test_truncated_records_are_ignored(trace):
    assert trace.parse(b'\0' * 16) is None


# ------------------------------------------------------------- the egress watch

class FakeTrace:
    def __init__(self):
        self.items, self.closed = [], False

    def wait(self, seconds):
        time.sleep(min(seconds, 0.01))
        return False

    def drain(self):
        items, self.items = self.items, []
        return items

    def close(self):
        self.closed = True


def traced(**kw):
    base = dict(protocol='tcp', pid=4242, parent=1, uid=0, gid=0, comm='agent', netns=None,
                process=dict(path='/tmp/.x/agent', deleted=False, argv=['/tmp/.x/agent', '-q'], start=9, cwd='/'),
                exe_tail='/tmp/.x/agent', local_address='10.0.0.2', local_port=51000, address='9.9.9.9',
                port=443, connected=True)
    base.update(kw)
    return base


def test_naming_matches_a_closing_and_forgets_old_ones():
    fake = FakeTrace()
    naming = ew.Naming(trace=fake, clock=lambda: now[0])
    now = [0.0]
    try:
        fake.items.append(traced())
        assert naming.lookup(None, '9.9.9.9', 443, 51000)['pid'] == 4242, 'read before the lookup'
        assert naming.lookup(None, '9.9.9.9', 443, 51000) is None, 'matched once'
        naming.add([traced(netns=7)])
        assert naming.lookup(None, '9.9.9.9', 443, 51000) is None, 'another namespace'
        assert naming.lookup('net:[7]', '9.9.9.9', 443, 51000)['pid'] == 4242
        naming.add([traced()])
        now[0] = ew.NAMED_SECONDS + 1
        naming.add([])
        assert naming.lookup(None, '9.9.9.9', 443, 51000) is None, 'too old to be matched'
    finally:
        naming.close()
    assert fake.closed


def test_a_named_closing_is_judged_by_its_program():
    connection = ew.heard(dict(protocol='tcp', address=__import__('ipaddress').ip_address('9.9.9.9'), port=443,
                               local_port=51000, sent=10, received=20))
    found = ew.named(connection, traced())
    assert found['program'] == '/tmp/.x/agent' and found['argv'] == ['/tmp/.x/agent', '-q']
    assert found['traced']['parent'] == 1
    rules = {f['rule_id'] for f in ew.judge(dict(programs={}), found)}
    assert rules == {'OUTBOUND_FROM_TEMPORARY', 'NEW_OUTBOUND_PROGRAM'}
    # Gone before it was read: a full kernel path still names a plain program...
    gone = ew.named(connection, traced(process=None, exe_tail='/usr/bin/curl', comm='curl'))
    assert gone['program'] == '/usr/bin/curl' and gone['argv'] == []
    # ... but not a partial path, nor an interpreter, whose script would be unknown.
    assert ew.named(connection, traced(process=None, exe_tail='…/bin/curl')) is None
    assert ew.named(connection, traced(process=None, exe_tail='/usr/bin/python3.12', comm='python3')) is None
    copied = ew.named(connection, traced(process=None, exe_tail='/dev/shm/.x/sh', comm='sh'))
    assert copied['program'] == '/dev/shm/.x/sh', 'a shell run from a temporary folder is the finding itself'
    assert {f['rule_id'] for f in ew.judge(dict(programs={}), copied)} >= {'OUTBOUND_FROM_TEMPORARY'}
    inside = ew.named(dict(connection, namespace='net:[9]', container='docker:abc'), traced())
    assert inside['program'] == '[container] /tmp/.x/agent'


class FakeClosings:
    def __init__(self, closed):
        self.closed, self.gaps, self.missed = closed, set(), 0

    def drain(self):
        closed, self.closed = self.closed, []
        return closed

    def subscribe(self, spaces):
        pass

    def filenos(self):
        return []

    def close(self):
        pass


def test_the_watch_names_a_short_connection_it_would_otherwise_report_by_destination(tmp_path):
    import ipaddress
    manifest = tmp_path / 'egress.json'
    ew._write(manifest, ew._empty())
    closed = dict(protocol='tcp', address=ipaddress.ip_address('9.9.9.9'), port=443, local_port=51000, sent=5,
                  received=0)
    plain = ew.Watcher(manifest, emit=lambda f: None, closings=FakeClosings([(None, closed)]))
    assert [f['rule_id'] for f in plain.hear()] == ['BRIEF_OUTBOUND_CONNECTION']
    fake = FakeTrace()
    naming = ew.Naming(trace=fake)
    try:
        fake.items.append(traced())
        watcher = ew.Watcher(manifest, emit=lambda f: None, closings=FakeClosings([(None, closed)]), naming=naming)
        found = watcher.hear()
        assert {f['rule_id'] for f in found} == {'OUTBOUND_FROM_TEMPORARY', 'NEW_OUTBOUND_PROGRAM'}
        assert all(f['evidence']['traced']['pid'] == 4242 for f in found) and watcher.stats['named'] == 1
        # Partly named: still a brief connection, with the trace's lead in its evidence.
        fake.items.append(traced(process=None, exe_tail='…/.x/agent', local_port=51001))
        watcher.closings = FakeClosings([(None, dict(closed, local_port=51001))])
        [brief] = watcher.hear()
        assert brief['rule_id'] == 'BRIEF_OUTBOUND_CONNECTION'
        assert brief['evidence']['traced']['executable_in_kernel'] == '…/.x/agent'
    finally:
        naming.close()


def test_the_command_line_falls_back_when_tracing_is_unavailable(tmp_path, monkeypatch, capsys):
    manifest = tmp_path / 'egress.json'
    ew._write(manifest, ew._empty())

    def refuse(*a, **k):
        raise ct.TraceError(1, 'the kernel refused the program')
    monkeypatch.setattr(ew, 'Naming', refuse)
    ran = {}

    class Stopper(ew.Watcher):
        def run(self, stop):
            ran['naming'] = self.naming
    monkeypatch.setattr(ew, 'Watcher', Stopper)
    from megalodon.cli import main
    with pytest.raises(SystemExit) as exit_:
        main(['egress', 'watch', '--manifest', str(manifest), '--trace-connects', '--no-names'])
    assert exit_.value.code == 0 and ran['naming'] is None
    assert 'connect tracing unavailable: the kernel refused the program' in capsys.readouterr().err


# ------------------------------------------------------------- live, where eBPF can be loaded

def loaded():
    try:
        return ct.ConnectTrace()
    except (ct.TraceError, OSError) as exc:
        pytest.skip(f'connect tracing cannot be loaded here: {exc}')


def test_live_a_short_connection_is_named_by_the_program_that_made_it(tmp_path):
    trace = loaded()
    server = socket.socket()
    server.bind(('127.0.0.1', 0))
    server.listen(8)
    port = server.getsockname()[1]
    folder = tmp_path / '.x'
    folder.mkdir()
    copy = folder / 'agent'
    shutil.copy(sys.executable, copy)
    seen, stop = [], threading.Event()

    def read():
        while not stop.is_set():
            if trace.wait(0.1):
                seen.extend(trace.drain())
    reader = threading.Thread(target=read)
    reader.start()
    try:
        subprocess.run([str(copy), '-c', f'import socket; socket.create_connection(("127.0.0.1", {port})).close()'],
                       env=dict(os.environ, PYTHONHOME=sys.base_prefix), check=True, timeout=30)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(e['port'] == port for e in seen):
            time.sleep(0.05)
    finally:
        stop.set()
        reader.join()
        trace.close()
        server.close()
    [event] = [e for e in seen if e['port'] == port]
    assert event['comm'] == 'agent' and event['connected'] and event['local_port'] > 0
    assert event['process']['executable'] == str(copy)
    assert event['exe_tail'].endswith('/.x/agent') and event['parent'] == os.getpid()
    assert event['netns'] == os.stat('/proc/self/ns/net').st_ino
