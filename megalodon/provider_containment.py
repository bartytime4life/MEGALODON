"""Bounded, read-only observation of the Qwen/Ollama loopback provider.

`docs/model-containment-review.md` maps the existing client-side boundary
(one bounded request to a compiled-in `127.0.0.1:11434`) and names what still
lacks evidence: "ownership and integrity of the process bound to that
port... observation from outside the provider process." This module is
exactly that observation, and nothing more.

It never blocks, gates, delays, or authorizes an advisory request:
`megalodon.qwen_advisory` does not import this module, and no code path here
feeds back into whether a request is sent. It launches no process, contacts
no network destination (including the provider itself), and changes nothing
on the host. Everything it reports comes from parsing `/proc/net/tcp`,
`/proc/net/tcp6`, and, best-effort, `/proc/<pid>/fd`, `/proc/<pid>/ns/net`,
and `/proc/<pid>/cgroup` for whichever process (if any) a non-root caller has
permission to inspect.

A hardened deployment that runs Ollama as its own dedicated, unprivileged
user will correctly make most of the process-level fields below
unresolvable to MEGALODON's own unprivileged process — that is the intended,
honest outcome of least privilege, not a defect in this module. A denied or
inconclusive lookup is always reported as such (`"permission_denied"`,
`"unknown"`, `null`); it is never treated as evidence of absence, and no
field here is inferred, guessed, or filled from a default.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import ipaddress
import os
import socket
import time
from types import MappingProxyType
from typing import Any

from .offline.common import require_unprivileged_linux
from .qwen_advisory import LOOPBACK_HOST, LOOPBACK_PORT

SCHEMA_VERSION = "megalodon-qwen-provider-posture-v1"
OBSERVATION_MODE = "read_only_proc_introspection"
MAX_ELAPSED_SECONDS = 5
MAX_BINDINGS = 16
MAX_PID_SCAN = 8_192

_TCP_TABLES = (("ipv4", "/proc/net/tcp", 4), ("ipv6", "/proc/net/tcp6", 16))
_LISTEN_STATE = "0A"

CAVEATS = (
    "Read-only /proc introspection only; nothing here blocks, gates, or authorizes an advisory request.",
    "A permission-denied or inconclusive lookup is reported as such, never treated as absence of exposure.",
    "This does not prove the listening process is genuinely Ollama, model provenance, or resource containment.",
    "Only the exact configured host/port is inspected; this is not a general port or process scanner.",
    "PID and namespace resolution require the same UID as the target process or CAP_SYS_PTRACE; a hardened,"
    " separately privileged deployment correctly denies both to this unprivileged observer.",
)


def _fmt(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_address(hex_addr: str, byte_length: int) -> str | None:
    try:
        raw = bytes.fromhex(hex_addr)
    except ValueError:
        return None
    if len(raw) != byte_length:
        return None
    try:
        if byte_length == 4:
            return socket.inet_ntop(socket.AF_INET, raw[::-1])
        words = (raw[index:index + 4][::-1] for index in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, b"".join(words))
    except (OSError, ValueError):
        return None


def _read_bindings(
    path: str, family: str, byte_length: int, port: int, limit: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Return matching listeners and whether the whole table was examined."""
    bindings: list[dict[str, Any]] = []
    complete = True
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            next(handle, None)  # header
            for line in handle:
                fields = line.split()
                if len(fields) < 8:
                    continue
                local = fields[1]
                if ":" not in local:
                    continue
                addr_hex, _, port_hex = local.partition(":")
                try:
                    if int(port_hex, 16) != port:
                        continue
                    state = fields[3]
                    uid = int(fields[7])
                except ValueError:
                    continue
                if state != _LISTEN_STATE:
                    continue
                address = _parse_address(addr_hex, byte_length)
                if address is None:
                    continue
                inode = fields[9] if len(fields) > 9 else None
                try:
                    is_loopback = ipaddress.ip_address(address).is_loopback
                except ValueError:
                    is_loopback = False
                bindings.append({
                    "family": family,
                    "address": address,
                    "is_loopback": is_loopback,
                    "uid": uid,
                    "uid_matches_self": uid == os.geteuid(),
                    "_inode": inode,
                })
                if len(bindings) >= limit:
                    complete = False
                    break
    except OSError:
        return [], False
    return bindings, complete


def _find_owning_pid(inode: str, deadline: float) -> tuple[str, int | None]:
    target = f"socket:[{inode}]"
    try:
        entries = os.listdir("/proc")
    except OSError:
        return "unknown", None
    scanned = 0
    denied_any = False
    for name in entries:
        if not name.isdigit():
            continue
        scanned += 1
        if scanned > MAX_PID_SCAN or time.monotonic() > deadline:
            return "timeout", None
        fd_dir = f"/proc/{name}/fd"
        try:
            fd_names = os.listdir(fd_dir)
        except PermissionError:
            denied_any = True
            continue
        except OSError:
            continue
        for fd_name in fd_names:
            try:
                link = os.readlink(f"{fd_dir}/{fd_name}")
            except OSError:
                continue
            if link == target:
                return "resolved", int(name)
    return ("permission_denied" if denied_any else "not_found"), None


def _process_details(pid: int) -> Mapping[str, Any]:
    exe_basename: str | None = None
    try:
        exe_path = os.readlink(f"/proc/{pid}/exe")
        exe_basename = os.path.basename(exe_path) or None
    except OSError:
        pass

    distinct_cgroup: bool | None = None
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="utf-8", errors="replace") as handle:
            other_cgroup = handle.read(4_096)
        with open("/proc/self/cgroup", "r", encoding="utf-8", errors="replace") as handle:
            self_cgroup = handle.read(4_096)
        distinct_cgroup = other_cgroup != self_cgroup
    except OSError:
        pass

    distinct_netns: bool | None = None
    try:
        other_ns = os.readlink(f"/proc/{pid}/ns/net")
        self_ns = os.readlink("/proc/self/ns/net")
        distinct_netns = other_ns != self_ns
    except OSError:
        pass

    return MappingProxyType({
        "exe_basename": exe_basename,
        "distinct_cgroup_from_self": distinct_cgroup,
        "distinct_net_namespace_from_self": distinct_netns,
    })


def qwen_provider_posture(
    *, host: str = LOOPBACK_HOST, port: int = LOOPBACK_PORT,
) -> Mapping[str, Any]:
    """Observe, without contacting or gating, whatever is bound to `host:port`.

    Defaults to the exact fixed destination `megalodon.qwen_advisory` uses.
    `bindings` reports every listener found on `port` across *all* bound
    addresses, not only `host`: the whole point of `loopback_only` is
    noticing a listener the advisory client was never told about (for
    example, the same port also exposed on `0.0.0.0`), which filtering by
    `host` first would hide. `owning_process` resolves at most one
    representative socket's inode, since a dual-stack listener normally
    presents one process across two address families.

    Returns a closed, versioned Mapping; this function does not raise for
    any observational outcome (missing provider, permission denial, an
    unreadable `/proc`) — those are all reported fields, not exceptions.
    """
    require_unprivileged_linux()
    if type(host) is not str or type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("PROVIDER_CONTAINMENT:INVALID_TARGET")

    started = time.monotonic()
    deadline = started + MAX_ELAPSED_SECONDS
    checked_at = _fmt(datetime.now(timezone.utc))

    raw_bindings: list[dict[str, Any]] = []
    tables_complete = True
    for family, path, byte_length in _TCP_TABLES:
        remaining = MAX_BINDINGS - len(raw_bindings)
        if remaining <= 0:
            break
        table_bindings, table_readable = _read_bindings(
            path, family, byte_length, port, remaining,
        )
        raw_bindings.extend(table_bindings)
        tables_complete = tables_complete and table_readable

    if raw_bindings:
        listening = "yes"
    elif not tables_complete:
        listening = "unknown"
    else:
        listening = "no"

    bindings = tuple(
        MappingProxyType({k: v for k, v in binding.items() if not k.startswith("_")})
        for binding in raw_bindings
    )
    loopback_only = (
        all(b["is_loopback"] for b in bindings)
        if bindings and tables_complete else None
    )

    owning_process: Mapping[str, Any] = MappingProxyType({
        "resolution": "not_attempted", "pid": None,
        "exe_basename": None, "distinct_cgroup_from_self": None,
        "distinct_net_namespace_from_self": None,
    })
    inode = next((b["_inode"] for b in raw_bindings if b.get("_inode")), None)
    if inode is not None and time.monotonic() < deadline:
        resolution, pid = _find_owning_pid(inode, deadline)
        if resolution == "resolved" and pid is not None:
            details = _process_details(pid)
            owning_process = MappingProxyType({
                "resolution": resolution, "pid": pid, **details,
            })
        else:
            owning_process = MappingProxyType({
                "resolution": resolution, "pid": None,
                "exe_basename": None, "distinct_cgroup_from_self": None,
                "distinct_net_namespace_from_self": None,
            })

    return MappingProxyType({
        "schema_version": SCHEMA_VERSION,
        "checked_at": checked_at,
        "observation_mode": OBSERVATION_MODE,
        "target": MappingProxyType({"host": host, "port": port}),
        "listening": listening,
        "bindings": bindings,
        "loopback_only": loopback_only,
        "owning_process": owning_process,
        "caveats": CAVEATS,
    })
