"""Containers: the ways out of a container and onto the machine.

A container shares the host's kernel. Run privileged, given the container
runtime's socket, the host's root folder, its process table or a dangerous
capability, it is root on the machine in all but name; a process that leaves
its container for the host's own mount namespace has escaped (ATT&CK T1611,
T1610). `megalodon containers` records the running containers and the host's
container exposures, and reports what gets riskier:

* every container, found from its processes' control groups (Docker, Podman,
  containerd and Kubernetes, CRI-O, LXC, systemd-nspawn), with what it shares
  with the host: privileges, capabilities, the host's process or network
  namespace, host folders and runtime sockets mounted into it, and whether
  seccomp is off;
* processes in a container's control group that run in the host's mount
  namespace, which is how an escape looks;
* the kernel hooks container escapes overwrite (core_pattern, modprobe,
  uevent_helper and cgroup release_agent);
* the runtime API on unencrypted TCP port 2375, runtime sockets anyone can
  write to, and new members of root-equivalent groups such as docker and lxd.

Everything is read from /proc, /sys and /etc; when the Docker socket can be
read, container names and images are asked of it with read-only GET requests.
Nothing is started, stopped or changed. Run as root to see every container.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile

SCHEMA = 'megalodon-container-watch-v1'
REPORT_SCHEMA = 'megalodon-container-report-v1'
DEFAULT_MANIFEST = '~/.config/megalodon/containers.json'
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PROCESSES = 65536
MAX_READ = 1024 * 1024
MAX_API_BYTES = 4 * 1024 * 1024
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

# Control-group paths name the container: docker-<id>.scope, /docker/<id>, libpod-<id>.scope, kubepods/.../<id>.
_CGROUP = (
    ('docker', re.compile(r'docker-([0-9a-f]{64})\.scope|/docker/([0-9a-f]{64})')),
    ('podman', re.compile(r'libpod-(?!conmon-)([0-9a-f]{64})(?:\.scope)?')),
    ('cri-o', re.compile(r'crio-(?!conmon-)([0-9a-f]{64})\.scope')),
    ('containerd', re.compile(r'cri-containerd-([0-9a-f]{64})\.scope|/kubepods[^\n]*?/([0-9a-f]{64})')),
    ('lxc', re.compile(r'lxc\.payload\.([A-Za-z0-9_.-]{1,128})')),
    ('nspawn', re.compile(r'machine-([A-Za-z0-9_.\\-]{1,128})\.scope')),
)
# Runtime helpers that sit in the container's group but stay in the host's namespaces by design.
RUNTIME_HELPERS = frozenset({'runc', 'crun', 'youki', 'runsc', 'conmon', 'containerd-shim', 'containerd-shim-runc-v2',
                             'systemd-nspawn', 'lxc-start', 'catatonit', 'runc:[1:CHILD]', 'runc:[2:INIT]'})
CAPS = ('CHOWN', 'DAC_OVERRIDE', 'DAC_READ_SEARCH', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETPCAP',
        'LINUX_IMMUTABLE', 'NET_BIND_SERVICE', 'NET_BROADCAST', 'NET_ADMIN', 'NET_RAW', 'IPC_LOCK', 'IPC_OWNER',
        'SYS_MODULE', 'SYS_RAWIO', 'SYS_CHROOT', 'SYS_PTRACE', 'SYS_PACCT', 'SYS_ADMIN', 'SYS_BOOT', 'SYS_NICE',
        'SYS_RESOURCE', 'SYS_TIME', 'SYS_TTY_CONFIG', 'MKNOD', 'LEASE', 'AUDIT_WRITE', 'AUDIT_CONTROL', 'SETFCAP',
        'MAC_OVERRIDE', 'MAC_ADMIN', 'SYSLOG', 'WAKE_ALARM', 'BLOCK_SUSPEND', 'AUDIT_READ', 'PERFMON', 'BPF',
        'CHECKPOINT_RESTORE')
# Each of these alone is a known way from a container to the host.
DANGEROUS_CAPS = ('DAC_READ_SEARCH', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE', 'SYS_ADMIN', 'MAC_ADMIN', 'MAC_OVERRIDE',
                  'BPF')
SOCKETS = frozenset({'docker.sock', 'containerd.sock', 'podman.sock', 'crio.sock', 'cri-dockerd.sock',
                     'dockershim.sock'})
# Host folders that hand over the machine when mounted into a container.
HOST_FOLDERS = frozenset({'/', '/etc', '/root', '/home', '/boot', '/usr', '/bin', '/sbin', '/lib', '/var', '/run',
                          '/var/run', '/proc', '/dev', '/var/lib/docker', '/var/lib/containerd', '/var/lib/kubelet',
                          '/run/containerd', '/run/docker', '/run/podman'})
HOST_PREFIXES = ('/root/', '/boot/', '/etc/shadow', '/etc/sudoers', '/etc/ssh', '/etc/cron', '/etc/systemd',
                 '/etc/pam.d', '/etc/ld.so.preload', '/etc/passwd', '/etc/group')
SYSTEM_DIRS = ('/usr/', '/bin/', '/sbin/', '/lib/', '/lib64/', '/lib32/')
HOST_SOCKETS = ('/run/docker.sock', '/var/run/docker.sock', '/run/containerd/containerd.sock',
                '/run/podman/podman.sock', '/run/crio/crio.sock')
ROOT_GROUPS = ('docker', 'lxd', 'incus-admin', 'microk8s')
API_PORT = 2375

RULES = {
    'CONTAINER_ESCAPE': ('CRITICAL', ['T1611'], 'A process in a container\'s control group runs in the host\'s '
                                                'mount namespace: it has left its container.'),
    'ESCAPE_HOOK_SET': ('CRITICAL', ['T1611', 'T1546'],
                        'A kernel hook that container escapes overwrite now runs a program outside the system '
                        'folders, or one the host does not have.'),
    'RUNTIME_API_EXPOSED': ('CRITICAL', ['T1610', 'T1611'], 'The container runtime\'s API listens on unencrypted '
                                                             'TCP port 2375: anyone who reaches it is root.'),
    'RUNTIME_SOCKET_WORLD_WRITABLE': ('CRITICAL', ['T1611'], 'A container runtime socket can be written by every '
                                                              'account: every account is root.'),
    'CONTAINER_PRIVILEGED': ('HIGH', ['T1611'], 'A container now runs privileged, with every capability.'),
    'CONTAINER_RUNTIME_SOCKET': ('HIGH', ['T1610', 'T1611'], 'A container runtime socket is mounted into a '
                                                             'container: the container controls the runtime.'),
    'CONTAINER_HOST_PATH_MOUNTED': ('HIGH', ['T1611'], 'A host folder or file that hands over the machine is '
                                                        'mounted into a container.'),
    'CONTAINER_DANGEROUS_CAPABILITY': ('HIGH', ['T1611'], 'A container holds a capability that is a known way out '
                                                           'to the host.'),
    'CONTAINER_HOST_PID': ('HIGH', ['T1611'], 'A container shares the host\'s process namespace.'),
    'ESCAPE_HOOK_CHANGED': ('HIGH', ['T1546'], 'A kernel hook that container escapes overwrite changed.'),
    'RUNTIME_GROUP_MEMBER_ADDED': ('HIGH', ['T1098'], 'An account joined a group that controls containers, which '
                                                      'is as good as root.'),
    'CONTAINER_HOST_NETWORK': ('MEDIUM', ['T1611'], 'A container shares the host\'s network namespace.'),
    'CONTAINER_UNCONFINED': ('MEDIUM', ['T1611'], 'A container runs with seccomp off.'),
}
RISK_RULES = (('privileged', 'CONTAINER_PRIVILEGED'), ('socket:', 'CONTAINER_RUNTIME_SOCKET'),
              ('mount:', 'CONTAINER_HOST_PATH_MOUNTED'), ('cap:', 'CONTAINER_DANGEROUS_CAPABILITY'),
              ('host_pid', 'CONTAINER_HOST_PID'), ('host_net', 'CONTAINER_HOST_NETWORK'),
              ('seccomp_off', 'CONTAINER_UNCONFINED'))


class ContainerError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _text(path, limit=MAX_READ):
    try:
        with open(path, 'rb') as handle:
            return handle.read(limit).decode('utf-8', 'replace')
    except OSError:
        return None


def _link(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def _unescape(text):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), text)


def mounts(text):
    """[(device, root, mountpoint, options, fstype)] from a mountinfo table."""
    out = []
    for line in (text or '').splitlines():
        fields = line.split(' ')
        if '-' not in fields or len(fields) < 7:
            continue
        sep = fields.index('-')
        if sep + 1 >= len(fields):
            continue
        out.append((fields[2], _unescape(fields[3]), _unescape(fields[4]), fields[5], fields[sep + 1]))
    return out


def _host_paths(host_mounts):
    """{device: host mountpoint} for the host's mounts of whole filesystems, the root one first."""
    found = {}
    for device, root, point, _, _ in sorted(host_mounts, key=lambda m: len(m[2])):
        if root == '/':
            found.setdefault(device, point)
    return found


def _join(base, rest):
    return '/' + '/'.join(p for p in (base.strip('/'), rest.strip('/')) if p)


def _risky_path(path):
    return path in HOST_FOLDERS or path.startswith(HOST_PREFIXES)


def container_of(cgroup_text):
    """(runtime, id) from a process's /proc/<pid>/cgroup, or None for a host process."""
    for runtime, pattern in _CGROUP:
        found = pattern.search(cgroup_text or '')
        if found:
            return runtime, next(g for g in found.groups() if g)
    return None


def _status(text):
    out = {}
    for line in (text or '').splitlines():
        key, _, value = line.partition(':')
        out[key] = value.strip()
    return out


def _start(proc):
    text = _text(proc / 'stat', 4096) or ''
    try:
        return int(text[text.rindex(')') + 2:].split()[19])
    except (ValueError, IndexError):
        return None


def docker_api(path, request='/containers/json'):
    """Ask the Docker socket a read-only question; None when it cannot be reached."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(3)
            conn.connect(path)
            conn.sendall(f'GET {request} HTTP/1.0\r\nHost: docker\r\n\r\n'.encode())
            data = b''
            while len(data) <= MAX_API_BYTES:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return None
    head, _, body = data.partition(b'\r\n\r\n')
    if not head.startswith(b'HTTP/1.') or b' 200 ' not in head.split(b'\r\n', 1)[0] + b' ':
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


def _names(root, api):
    """{container id: (name, image)} from the Docker API, when it answers."""
    if api is None:
        sock = next((p for p in (Path(root, 'run/docker.sock'), Path(root, 'var/run/docker.sock'),
                                 Path(root, 'run/podman/podman.sock')) if p.exists()), None)
        listed = docker_api(str(sock)) if sock else None
    else:
        listed = api()
    found = {}
    for item in listed if isinstance(listed, list) else []:
        if isinstance(item, dict) and isinstance(item.get('Id'), str):
            names = item.get('Names') or ['']
            found[item['Id']] = (str(names[0]).lstrip('/')[:128], str(item.get('Image', ''))[:256])
    return found


def hooks(root='/'):
    """The kernel hooks escapes overwrite: {name: value}."""
    found = {}
    for name, path in (('core_pattern', 'proc/sys/kernel/core_pattern'), ('modprobe', 'proc/sys/kernel/modprobe'),
                       ('uevent_helper', 'sys/kernel/uevent_helper')):
        value = _text(Path(root, path), 4096)
        if value is not None:
            found[name] = value.strip()
    cgroups = Path(root, 'sys/fs/cgroup')
    try:
        folders = sorted(cgroups.iterdir())[:64]
    except OSError:
        folders = []
    for folder in folders:
        value = _text(folder / 'release_agent', 4096)
        if value is not None:
            found[f'release_agent:{folder.name}'] = value.strip()
    return found


def _hook_program(name, value):
    """The program a hook runs, or None when it runs nothing (or the kernel's own default)."""
    if name == 'core_pattern':
        return value[1:].split()[0] if value.startswith('|') and value[1:].split() else None
    if name == 'modprobe' and value == '/sbin/modprobe':
        return None
    return value.split()[0] if value.strip() else None


def _hook_findings(old, new, root):
    """Hooks that now run something: CRITICAL from outside the system folders, HIGH otherwise."""
    findings = []
    for name, value in sorted(new.items()):
        was = None if old is None else old.get(name)
        program = _hook_program(name, value)
        if program is None or (old is not None and (was is None or was == value)):
            continue
        if not program.startswith(SYSTEM_DIRS) or not os.path.exists(Path(root, program.lstrip('/'))):
            findings.append(_finding('ESCAPE_HOOK_SET', f'hook:{name}', f'{name} runs {program}', value=value[:512]))
        elif old is not None:
            findings.append(_finding('ESCAPE_HOOK_CHANGED', f'hook:{name}', f'{name} changed from {was!r} to {value!r}',
                                     value=value[:512]))
    return findings


def _api_listeners(root):
    from .listener_watch import _listening
    try:
        found, _ = _listening(root)
    except OSError:
        return []
    return sorted({f'{address}:{port}' for protocol, address, port in found.values()
                   if protocol == 'tcp' and port == API_PORT})


def _open_sockets(root):
    out, seen = [], set()
    for shown in HOST_SOCKETS:
        try:
            info = os.stat(Path(root, shown.lstrip('/')))
        except OSError:
            continue
        if (info.st_dev, info.st_ino) in seen:
            continue
        seen.add((info.st_dev, info.st_ino))
        if stat.S_ISSOCK(info.st_mode) and info.st_mode & 0o002:
            out.append(shown)
    return out


def _group_members(root):
    found = {}
    for line in (_text(Path(root, 'etc/group')) or '').splitlines():
        fields = line.split(':')
        if len(fields) >= 4 and fields[0] in ROOT_GROUPS:
            found[fields[0]] = sorted(m for m in fields[3].split(',') if m)
    return found


def snapshot(*, root='/', api=None):
    """Containers and what they share with the host, escaped processes, hooks and exposures."""
    proc = Path(root, 'proc')
    host = proc / '1'
    host_ns = {kind: _link(host / 'ns' / kind) for kind in ('mnt', 'pid', 'net', 'user')}
    gaps = []
    if host_ns['mnt'] is None:
        gaps.append('the host\'s namespaces cannot be read; run as root')
    last = _text(proc / 'sys/kernel/cap_last_cap', 64)
    last = int(last) if last and last.strip().isdigit() else 40
    everything = (1 << (last + 1)) - 1
    devices = _host_paths(mounts(_text(host / 'mountinfo')))
    names = _names(root, api)
    containers, escaped, hidden = {}, [], 0
    try:
        pids = sorted((int(p.name) for p in proc.iterdir() if p.name.isdigit()))[:MAX_PROCESSES]
    except OSError:
        pids = []
        gaps.append('/proc cannot be listed')
    for pid in pids:
        here = proc / str(pid)
        owner = container_of(_text(here / 'cgroup', 64 * 1024))
        if owner is None:
            continue
        runtime, ident = owner
        mnt = _link(here / 'ns/mnt')
        if mnt is None:
            hidden += 1
            continue
        exe = (_link(here / 'exe') or '').removesuffix(' (deleted)')
        comm = (_text(here / 'comm', 256) or '').strip()
        if host_ns['mnt'] and mnt == host_ns['mnt']:
            if os.path.basename(exe) not in RUNTIME_HELPERS and comm not in RUNTIME_HELPERS:
                escaped.append(dict(pid=pid, start=_start(here), program=exe or comm, container=f'{runtime}:{ident}'))
            continue
        status = _status(_text(here / 'status', 64 * 1024))
        try:
            caps = int(status.get('CapEff', '0'), 16)
        except ValueError:
            caps = 0
        name, image = names.get(ident, ('', ''))
        key = f"{runtime}:{name or ident[:12]}"
        entry = containers.setdefault(key, dict(runtime=runtime, id=ident, name=name, image=image, risks=set(),
                                                processes=[]))
        if len(entry['processes']) < 5:
            entry['processes'].append(dict(pid=pid, start=_start(here), program=exe or comm))
        risks = entry['risks']
        # In its own user namespace, a container's root and capabilities are not the host's.
        if _link(here / 'ns/user') == host_ns['user']:
            if caps & everything == everything:
                risks.add('privileged')
            else:
                risks.update(f'cap:{n}' for n in DANGEROUS_CAPS if caps >> CAPS.index(n) & 1)
        if host_ns['pid'] and _link(here / 'ns/pid') == host_ns['pid']:
            risks.add('host_pid')
        if host_ns['net'] and _link(here / 'ns/net') == host_ns['net']:
            risks.add('host_net')
        if status.get('Seccomp') == '0' and 'privileged' not in risks:
            risks.add('seccomp_off')
        for device, inner, point, options, _ in mounts(_text(here / 'mountinfo')):
            outside = _join(devices[device], inner) if device in devices else None
            if os.path.basename(point) in SOCKETS or (outside and os.path.basename(outside) in SOCKETS):
                risks.add(f'socket:{outside or point}')
            elif outside and _risky_path(outside) and point != '/':
                risks.add(f'mount:{outside}' + ('' if options.split(',')[0] == 'rw' else ' (read-only)'))
    if hidden:
        gaps.append(f'{hidden} container processes could not be inspected; run as root')
    for entry in containers.values():
        if 'privileged' in entry['risks']:
            entry['risks'] = {r for r in entry['risks'] if not r.startswith('cap:') and r != 'seccomp_off'}
        entry['risks'] = sorted(entry['risks'])
    return dict(containers=containers, escaped=escaped, hooks=hooks(root), api_listeners=_api_listeners(root),
                open_sockets=_open_sockets(root), groups=_group_members(root), gaps=gaps)


# ------------------------------------------------------------------ baseline and check

def _write(path, value):
    path = Path(path).expanduser()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix='.containers-', dir=path.parent)
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
        raise ContainerError(f'no container baseline at {path}; run megalodon containers baseline') from None
    except OSError as exc:
        raise ContainerError(f'container baseline {path} cannot be opened: {exc.strerror}') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ContainerError(f'container baseline {path} must be a mode-600 file owned by you')
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    finally:
        os.close(fd)
    try:
        value = json.loads(raw)
    except ValueError:
        raise ContainerError('container baseline is not valid JSON') from None
    if type(value) is not dict or value.get('schema') != SCHEMA or type(value.get('containers')) is not dict:
        raise ContainerError('container baseline has an unsupported format')
    return value


def _finding(rule, subject, detail, **extra):
    severity, techniques, summary = RULES[rule]
    return dict(rule_id=rule, severity=severity, techniques=techniques, subject=subject, detail=detail,
                summary=summary, **extra)


def _label(key, entry):
    image = f" ({entry['image']})" if entry.get('image') else ''
    return f'{key}{image}'


def _always(state, root):
    """What is reported on every run, accepted or not: escapes, the open API and open sockets."""
    findings = []
    for item in state['escaped']:
        findings.append(_finding('CONTAINER_ESCAPE', f"process:{item['pid']}",
                                 f"{item['program']} (pid {item['pid']}) is in {item['container']}'s control group "
                                 'but runs in the host\'s mount namespace',
                                 evidence=dict(processes=[dict(pid=item['pid'], start=item['start'],
                                                               program=item['program'])])))
    for listener in state['api_listeners']:
        findings.append(_finding('RUNTIME_API_EXPOSED', f'listener:{listener}',
                                 f'the container runtime API listens unencrypted on {listener}'))
    for path in state['open_sockets']:
        findings.append(_finding('RUNTIME_SOCKET_WORLD_WRITABLE', f'file:{path}', f'{path} can be written by everyone',
                                 path=path))
    return findings


def compare(old, new, *, root='/'):
    findings = _always(new, root) + _hook_findings(old.get('hooks', {}), new['hooks'], root)
    for key, entry in sorted(new['containers'].items()):
        before = set(old['containers'].get(key, {}).get('risks', []))
        for risk in entry['risks']:
            if risk in before:
                continue
            rule = next(r for prefix, r in RISK_RULES if risk.startswith(prefix))
            what = risk.split(':', 1)[1] if ':' in risk else risk.replace('_', ' ')
            findings.append(_finding(rule, f'container:{key}:{risk}', f'{_label(key, entry)}: {what}',
                                     container=key, evidence=dict(processes=entry['processes'][:1])))
    for group, members in sorted(new['groups'].items()):
        for member in sorted(set(members) - set(old.get('groups', {}).get(group, []))):
            findings.append(_finding('RUNTIME_GROUP_MEMBER_ADDED', f'account:{member}',
                                     f'{member} joined the {group} group', account=member, group=group))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    added = sorted(set(new['containers']) - set(old['containers']))
    removed = sorted(set(old['containers']) - set(new['containers']))
    return findings, added, removed


def _recorded(state):
    return dict(containers={k: dict(runtime=v['runtime'], name=v['name'], image=v['image'], risks=v['risks'])
                            for k, v in state['containers'].items()},
                hooks=state['hooks'], groups=state['groups'])


def _summary(state):
    return [dict(container=k, runtime=v['runtime'], image=v['image'], risks=v['risks'])
            for k, v in sorted(state['containers'].items())]


def baseline(manifest=DEFAULT_MANIFEST, *, replace=False, root='/', api=None):
    path = Path(manifest).expanduser()
    if path.exists() and not replace:
        raise ContainerError(f'{path} exists; use accept to record the reviewed state')
    state = snapshot(root=root, api=api)
    _write(path, dict(schema=SCHEMA, recorded_at=_now(), root=os.path.realpath(root), **_recorded(state)))
    # An escape, an open API or socket, or a hook run from outside the system is reported now, not recorded.
    return dict(schema=REPORT_SCHEMA, action='baseline', manifest=str(path), containers=_summary(state),
                findings=sorted(_always(state, root) + _hook_findings(None, state['hooks'], root),
                                key=lambda f: (RANK.index(f['severity']), f['subject'])),
                gaps=state['gaps'])


def check(manifest=DEFAULT_MANIFEST, *, root=None, api=None):
    old = _read(manifest)
    root = root or old.get('root', '/')
    new = snapshot(root=root, api=api)
    findings, added, removed = compare(old, new, root=root)
    return dict(schema=REPORT_SCHEMA, action='check', manifest=str(Path(manifest).expanduser()), checked_at=_now(),
                baseline_recorded_at=old.get('recorded_at'), findings=findings, added=added, removed=removed,
                containers=_summary(new), gaps=new['gaps'],
                note='After review, `megalodon containers accept` records the current containers.')


def accept(manifest=DEFAULT_MANIFEST, *, root=None, api=None):
    old = _read(manifest)
    return dict(baseline(manifest, replace=True, root=root or old.get('root', '/'), api=api), action='accept')
