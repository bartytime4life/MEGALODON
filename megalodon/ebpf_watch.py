"""eBPF programs: the kernel code that modern rootkits load instead of kernel modules.

An eBPF program can hide files and processes from every program that lists
them, rewrite what system calls return, or wake a backdoor on a magic network
packet, with no kernel module to find (ATT&CK T1014, T1547.006, T1205). The
rootkit cross-checks look at modules, not at these. `megalodon ebpf` records the
loaded programs and reports new and changed ones:

* each program by its type, name and tag (a hash of its instructions), its
  owner, load time and the processes holding it, read through the kernel's own
  bpf() interface;
* programs held by a process but missing from the kernel's program list, which
  is how a rootkit hiding its own programs looks;
* pinned objects under /sys/fs/bpf, and whether unprivileged users may load
  programs.

Root is needed to list programs. Read-only: programs are only listed.
"""
from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import platform
import stat
import struct
import tempfile

from .egress_watch import _proc_info, script
from .process_network import TEMPORARY

SCHEMA = 'megalodon-ebpf-watch-v1'
REPORT_SCHEMA = 'megalodon-ebpf-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/ebpf.json'
MAX_PROGRAMS = 8192
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
_SYSCALL = {'x86_64': 321, 'aarch64': 280, 'arm64': 280, 'riscv64': 280, 'i686': 357, 'i386': 357, 'armv7l': 386}
BPF_PROG_GET_NEXT_ID, BPF_PROG_GET_FD_BY_ID, BPF_OBJ_GET_INFO_BY_FD = 11, 13, 15
PROG_TYPES = ('unspec', 'socket_filter', 'kprobe', 'sched_cls', 'sched_act', 'tracepoint', 'xdp', 'perf_event',
              'cgroup_skb', 'cgroup_sock', 'lwt_in', 'lwt_out', 'lwt_xmit', 'sock_ops', 'sk_skb', 'cgroup_device',
              'sk_msg', 'raw_tracepoint', 'cgroup_sock_addr', 'lwt_seg6local', 'lirc_mode2', 'sk_reuseport',
              'flow_dissector', 'cgroup_sysctl', 'raw_tracepoint_writable', 'cgroup_sockopt', 'tracing',
              'struct_ops', 'ext', 'lsm', 'sk_lookup', 'syscall', 'netfilter')
# Types that can watch or change what the kernel does or every packet it sees.
POWERFUL = {'kprobe', 'tracepoint', 'perf_event', 'raw_tracepoint', 'raw_tracepoint_writable', 'tracing', 'lsm',
            'struct_ops', 'ext', 'syscall', 'xdp', 'sched_cls', 'sched_act', 'netfilter', 'sk_skb', 'sk_msg'}

RULES = {
    'EBPF_HIDDEN_PROGRAM': ('CRITICAL', ['T1014'], 'A process holds an eBPF program that the kernel\'s program list '
                                                   'does not show: a rootkit hiding its own programs.'),
    'EBPF_LOADED_BY_DROPPED_TOOL': ('CRITICAL', ['T1014', 'T1547.006'],
                                    'An eBPF program is held by a program run from a temporary folder, a deleted '
                                    'file or memory.'),
    'EBPF_PROGRAM_CHANGED': ('HIGH', ['T1014'], 'A known eBPF program now has different instructions.'),
    'EBPF_NEW_PROGRAM': ('HIGH', ['T1014', 'T1205'], 'A new eBPF program of a kind that can watch or change the '
                                                     'kernel or network traffic.'),
    'EBPF_UNPRIVILEGED_ENABLED': ('HIGH', ['T1068'], 'Unprivileged users may now load eBPF programs.'),
    'EBPF_NEW_FILTER': ('MEDIUM', ['T1014'], 'A new eBPF program of a less powerful kind, such as a socket or '
                                             'cgroup filter.'),
    'EBPF_PINNED_ADDED': ('MEDIUM', ['T1014'], 'A new object was pinned under /sys/fs/bpf, keeping a program or map '
                                               'alive without any process.'),
}


class EbpfError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class Bpf:
    """The few bpf() commands needed to list programs."""

    def __init__(self):
        self.number = _SYSCALL.get(platform.machine())
        if self.number is None:
            raise EbpfError(f'bpf() is not known on {platform.machine()}')
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long

    def call(self, command, attr):
        buffer = ctypes.create_string_buffer(attr, 128)
        result = self.libc.syscall(ctypes.c_long(self.number), ctypes.c_int(command), buffer, ctypes.c_uint(128))
        return result, ctypes.get_errno(), buffer.raw

    def ids(self):
        found, start = [], 0
        while len(found) < MAX_PROGRAMS:
            result, error, raw = self.call(BPF_PROG_GET_NEXT_ID, struct.pack('=II', start, 0))
            if result < 0:
                if error == errno.ENOENT:
                    return found
                raise OSError(error, os.strerror(error))
            start = struct.unpack_from('=II', raw)[1]
            found.append(start)
        return found

    def info(self, prog_id):
        result, error, _ = self.call(BPF_PROG_GET_FD_BY_ID, struct.pack('=III', prog_id, 0, 0))
        if result < 0:
            return None
        fd = result
        try:
            out = ctypes.create_string_buffer(256)
            attr = struct.pack('=IIQ', fd, 256, ctypes.addressof(out))
            result, error, _ = self.call(BPF_OBJ_GET_INFO_BY_FD, attr)
            if result < 0:
                return None
            raw = out.raw
            kind, ident = struct.unpack_from('=II', raw, 0)
            load_time, uid = struct.unpack_from('=QI', raw, 40)
            name = raw[64:80].split(b'\0', 1)[0].decode('ascii', 'replace')
            return dict(id=ident, type=PROG_TYPES[kind] if kind < len(PROG_TYPES) else str(kind),
                        tag=raw[8:16].hex(), name=name, uid=uid, load_time_ns=load_time)
        finally:
            os.close(fd)


def holders(root='/'):
    """{program id: [(pid, info)]} from the descriptors processes hold (programs and links)."""
    found = {}
    base = Path(root, 'proc')
    for entry in os.scandir(base):
        if not entry.name.isdigit():
            continue
        try:
            fds = os.scandir(base / entry.name / 'fd')
        except OSError:
            continue
        with fds:
            for fd in fds:
                try:
                    target = os.readlink(fd.path)
                except OSError:
                    continue
                # Links are bpf_link when created and bpf-link when reopened by ID.
                if target not in ('anon_inode:bpf-prog', 'anon_inode:bpf_link', 'anon_inode:bpf-link'):
                    continue
                try:
                    text = (base / entry.name / 'fdinfo' / fd.name).read_text('ascii', 'replace')
                except OSError:
                    continue
                for line in text.splitlines():
                    if line.startswith('prog_id:') and line.split()[1].isdigit():
                        found.setdefault(int(line.split()[1]), []).append(int(entry.name))
    return found


def pinned(root='/'):
    out, base = [], os.path.join(root, 'sys/fs/bpf')
    for folder, dirs, names in os.walk(base):
        dirs.sort()
        out += [os.path.join(folder, n)[len(root.rstrip('/')):] if root != '/' else os.path.join(folder, n)
                for n in sorted(names)]
    return out[:MAX_PROGRAMS]


def _key(program):
    return f"{program['type']}:{program['name'] or '-'}:{program['tag']}"


def _dropped(info):
    run = script(info) or ''
    return info['deleted'] or info['path'].startswith(TEMPORARY) or info['path'].startswith('/memfd:') \
        or run.startswith(TEMPORARY)


def snapshot(*, root='/', bpf=None):
    gaps, programs, hidden = [], {}, []
    try:
        bpf = bpf or Bpf()
        ids = bpf.ids()
    except (OSError, EbpfError) as exc:
        code = getattr(exc, 'errno', None)
        gaps.append('listing eBPF programs needs root' if code in (errno.EPERM, errno.EACCES)
                    else f'eBPF programs cannot be listed: {exc}')
        ids, bpf = None, None
    held = holders(root)
    if ids is not None:
        for prog_id in ids:
            program = bpf.info(prog_id)
            if program is None:
                continue
            processes = []
            for pid in held.get(prog_id, [])[:16]:
                info = _proc_info(Path(root, 'proc', str(pid)))
                if info is not None:
                    processes.append(dict(pid=pid, start=info['start'], program=info['path'],
                                          script=script(info), dropped=_dropped(info)))
            program['holders'] = processes
            programs.setdefault(_key(program), []).append(program)
        # Held by a process, missing from the list: read the list again so a program loaded meanwhile is not taken
        # for a hidden one.
        again = bpf.ids()
        listed = set(ids) | set(again)
        if len(ids) >= MAX_PROGRAMS or len(again) >= MAX_PROGRAMS:
            # A list cut short at the limit is not the kernel's whole list: nothing missing from it is hidden.
            gaps.append(f'more than {MAX_PROGRAMS} eBPF programs are loaded: only the first {MAX_PROGRAMS} were '
                        'checked, and hidden programs were not looked for')
            held = {}
        for prog_id, pids in sorted(held.items()):
            if prog_id not in listed:
                infos = [_proc_info(Path(root, 'proc', str(p))) for p in pids[:8]]
                hidden.append(dict(id=prog_id, processes=[dict(pid=p, program=i['path'] if i else None,
                                                               start=i['start'] if i else None)
                                                          for p, i in zip(pids[:8], infos)]))
    try:
        unprivileged = Path(root, 'proc/sys/kernel/unprivileged_bpf_disabled').read_text().strip()
    except OSError:
        unprivileged = None
    return dict(programs=programs, hidden=hidden, pinned=pinned(root), unprivileged_bpf_disabled=unprivileged,
                listed=ids is not None, gaps=gaps)


# ------------------------------------------------------------------ baseline and check

def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.ebpf-', dir=path.parent)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def _read(path):
    path = Path(path).expanduser()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        raise EbpfError(f'no eBPF baseline at {path}; run megalodon ebpf baseline') from None
    except OSError as exc:
        raise EbpfError(f'eBPF baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise EbpfError(f'eBPF baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise EbpfError('eBPF baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('programs')) is not dict:
        raise EbpfError('eBPF baseline has an unsupported format')
    return value


def _finding(rule, subject, detail, **extra):
    severity, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


def _holder_text(program):
    names = [f"{h['program']}{' ' + h['script'] if h.get('script') else ''} (pid {h['pid']})"
             for h in program.get('holders', [])]
    return ', '.join(names) if names else 'no process (kept by an attachment or a pin)'


def compare(old, new):
    findings = []
    known_names = {k.rsplit(':', 1)[0] for k in old['programs']}
    for key, programs in sorted(new['programs'].items()):
        program = programs[0]
        for one in programs:
            for holder in one.get('holders', []):
                if holder.get('dropped'):
                    findings.append(_finding('EBPF_LOADED_BY_DROPPED_TOOL', f'ebpf:{key}',
                                             f"{one['type']} program {one['name'] or '(unnamed)'} is held by "
                                             f"{holder['program']}"
                                             f"{' ' + holder['script'] if holder.get('script') else ''} "
                                             f"(pid {holder['pid']})",
                                             evidence=dict(processes=[dict(program=holder['program'],
                                                                           pid=holder['pid'],
                                                                           start=holder['start'])])))
        if key in old['programs']:
            continue
        where = f"{program['type']} program {program['name'] or '(unnamed)'} (tag {program['tag']}, loaded by UID " \
                f"{program['uid']}, held by {_holder_text(program)})"
        if key.rsplit(':', 1)[0] in known_names:
            findings.append(_finding('EBPF_PROGRAM_CHANGED', f'ebpf:{key}', f'{where} replaced a known program',
                                     program=program))
        elif program['type'] in POWERFUL:
            findings.append(_finding('EBPF_NEW_PROGRAM', f'ebpf:{key}', f'new {where}', program=program))
        else:
            findings.append(_finding('EBPF_NEW_FILTER', f'ebpf:{key}', f'new {where}', program=program))
    for item in new.get('hidden', []):
        findings.append(_finding('EBPF_HIDDEN_PROGRAM', f"ebpf:hidden:{item['id']}",
                                 f"program {item['id']} is held by "
                                 + ', '.join(f"{p['program']} (pid {p['pid']})" for p in item['processes'])
                                 + ' but the kernel does not list it', processes=item['processes']))
    for path in sorted(set(new.get('pinned', [])) - set(old.get('pinned', []))):
        findings.append(_finding('EBPF_PINNED_ADDED', f'pin:{path}', f'{path} was pinned'))
    if old.get('unprivileged_bpf_disabled') not in (None, '0') and new.get('unprivileged_bpf_disabled') == '0':
        findings.append(_finding('EBPF_UNPRIVILEGED_ENABLED', 'kernel:unprivileged_bpf_disabled',
                                 'unprivileged users may now load eBPF programs (unprivileged_bpf_disabled=0)'))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    removed = sorted(set(old['programs']) - set(new['programs']))
    return findings, removed


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, root='/', bpf=None):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise EbpfError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(root=root, bpf=bpf)
    if not state['listed']:
        raise EbpfError('; '.join(state['gaps']) or 'eBPF programs cannot be listed')
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), **state))
    # A program already hiding, or held by a dropped tool, is reported now rather than recorded as normal.
    present, _ = compare(dict(programs=dict(state['programs']), pinned=state['pinned']), state)
    present = [f for f in present if f['rule_id'] in ('EBPF_HIDDEN_PROGRAM', 'EBPF_LOADED_BY_DROPPED_TOOL')]
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path),
                programs=sum(len(v) for v in state['programs'].values()), pinned=len(state['pinned']),
                findings=present, gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, *, root='/', bpf=None):
    old = _read(manifest)
    new = snapshot(root=root, bpf=bpf)
    findings, removed = compare(old, new) if new['listed'] else ([], [])
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_now(),
                baseline_recorded_at=old.get('recorded_at'), findings=findings, removed=removed,
                programs=sum(len(v) for v in new['programs'].values()), gaps=new['gaps'],
                note='After review, `megalodon ebpf accept` records the current programs.')


def accept(manifest=DEFAULT_MANIFEST, *, root='/', bpf=None):
    _read(manifest)
    return dict(baseline(manifest, replace=True, root=root, bpf=bpf), action='accept')
