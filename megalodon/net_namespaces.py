"""Every network namespace on this machine, and a process to read each one's socket tables through.

Socket tables are per network namespace. `/proc/net` is the namespace the
reader runs in; a container with its own network (Docker and Podman by
default, every Kubernetes pod) has tables of its own, which `/proc/net` never
shows. `/proc/PID/net` shows the tables of the namespace process PID is in, so
one process per namespace is enough to read them all. Nothing is entered or
changed: this only reads `/proc`.

Socket inode numbers are unique across the whole machine, so the processes
holding a socket are found the same way in every namespace: by the socket
links under `/proc/*/fd`.

Only root can see which namespace another account's processes are in. Without
root, only this namespace and those of your own processes are found.
"""
from __future__ import annotations

import os
from pathlib import Path

MAX_NAMESPACES = 512
MAX_PROCESSES = 65536


def _link(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


def _container(base):
    """(runtime, short id) of the container process `base` (/proc/PID) runs in, or None."""
    from .container_watch import container_of
    try:
        text = Path(base, 'cgroup').read_text('utf-8', 'replace')[:65536]
    except OSError:
        return None
    found = container_of(text)
    return (found[0], found[1][:12]) if found else None


def namespaces(root='/'):
    """This namespace first, then every other one seen: [dict(id, net, own, pid, container)], and gaps.

    `net` is the folder under `root` holding that namespace's tables: `proc/net` for this one, `proc/PID/net` for
    another. `container` is 'runtime:id' when the reader process is in a container, else None.
    """
    base = Path(root, 'proc')
    own = _link(base / 'self/ns/net')
    found = {own: dict(id=own, net='proc/net', own=True, pid=None, container=None)} if own else {}
    gaps, hidden = [], 0
    try:
        with os.scandir(base) as listing:
            pids = sorted(int(e.name) for e in listing if e.name.isdigit())[:MAX_PROCESSES]
    except OSError:
        return list(found.values()) or [dict(id=None, net='proc/net', own=True, pid=None, container=None)], \
            ['/proc could not be listed: only this network namespace is read']
    for pid in pids:
        space = _link(base / str(pid) / 'ns/net')
        if space is None:
            hidden += 1
            continue
        if space in found:
            continue
        if len(found) >= MAX_NAMESPACES:
            gaps.append(f'more than {MAX_NAMESPACES} network namespaces: only the first are read')
            break
        if not os.access(base / str(pid) / 'net/tcp', os.R_OK):
            continue                  # a process that exited, or one whose tables we may not read: try the next
        runtime = _container(base / str(pid))
        found[space] = dict(id=space, net=f'proc/{pid}/net', own=False, pid=pid,
                            container=f'{runtime[0]}:{runtime[1]}' if runtime else None)
    if hidden and os.geteuid() != 0:
        gaps.append(f"{hidden} processes' network namespaces could not be seen: run as root to read every one")
    if not found:
        found[None] = dict(id=None, net='proc/net', own=True, pid=None, container=None)
    return list(found.values()), gaps


def label(space):
    """How a namespace that is not this one is named in a finding: its container, or its namespace."""
    if space is None or space.get('own'):
        return None
    return f"container {space['container']}" if space.get('container') else f"namespace {space['id']}"
