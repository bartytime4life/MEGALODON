"""Listener watch: new listeners, ports taken over by another program, and wider exposure."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import socket
import stat
import sys

import pytest

from megalodon import listener_watch as lw

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def _hex(address):
    packed = ipaddress.ip_address(address).packed
    return "".join(f"{int.from_bytes(packed[i:i + 4], sys.byteorder):08X}" for i in range(0, len(packed), 4))


def fake_proc(root, sockets, processes):
    """sockets: (table, address, port, state, inode); processes: {pid: (exe, comm, [inodes])}."""
    net = root / "proc/net"
    net.mkdir(parents=True, exist_ok=True)
    rows = {name: [] for name in ("tcp", "tcp6", "udp", "udp6")}
    for table, address, port, state, inode in sockets:
        unspecified = "::" if table.endswith("6") else "0.0.0.0"
        rows[table].append(f"   0: {_hex(address)}:{port:04X} {_hex(unspecified)}:0000 {state} 00000000:00000000 "
                           f"00:00000000 00000000     0        0 {inode} 1 0000000000000000 100 0 0 10 0\n")
    for name, lines in rows.items():
        (net / name).write_text(HEADER + "".join(lines), encoding="ascii")
    (net / "if_inet6").write_text("", encoding="ascii")
    sysctl = root / "proc/sys/net/ipv4"
    sysctl.mkdir(parents=True, exist_ok=True)
    (sysctl / "ip_local_port_range").write_text("32768\t60999\n", encoding="ascii")
    for pid, (exe, comm, inodes) in processes.items():
        proc = root / "proc" / str(pid)
        (proc / "fd").mkdir(parents=True)
        (proc / "comm").write_text(comm + "\n", encoding="utf-8")
        os.symlink(exe, proc / "exe")
        for fd, inode in enumerate(inodes, start=3):
            os.symlink(f"socket:[{inode}]", proc / "fd" / str(fd))
    return str(root)


BASE_SOCKETS = [("tcp", "0.0.0.0", 22, "0A", 101), ("tcp6", "::", 22, "0A", 102),
                ("tcp", "127.0.0.1", 5432, "0A", 103), ("udp", "0.0.0.0", 5353, "07", 104),
                ("udp", "0.0.0.0", 45000, "07", 105), ("tcp", "192.168.1.5", 50000, "01", 106)]
BASE_PROCESSES = {100: ("/usr/sbin/sshd", "sshd", [101, 102]), 200: ("/usr/lib/postgresql/bin/postgres", "postgres", [103]),
                  300: ("/usr/sbin/avahi-daemon", "avahi-daemon", [104, 105]), 400: ("/usr/bin/curl", "curl", [106])}


def state(tmp_path, name, extra_sockets=(), extra_processes=None, replace=None):
    sockets = [s for s in BASE_SOCKETS if not replace or s[4] not in replace] + list(extra_sockets)
    processes = {**BASE_PROCESSES, **(extra_processes or {})}
    return lw.snapshot(root=fake_proc(tmp_path / name, sockets, processes))


def by_key(findings):
    return {(f["rule_id"], f["listener"]): f for f in findings}


# ------------------------------------------------------------- snapshot

def test_snapshot_groups_families_and_skips_clients(tmp_path):
    snap = state(tmp_path, "a")
    assert sorted(snap["listeners"]) == ["tcp:22", "tcp:5432", "udp:5353"], "no clients or outgoing UDP"
    ssh = snap["listeners"]["tcp:22"]
    assert ssh["scope"] == "all" and ssh["addresses"] == ["0.0.0.0:22", "[::]:22"]
    assert ssh["programs"] == [{"path": "/usr/sbin/sshd", "name": "sshd"}] and ssh["owners_known"]
    assert snap["listeners"]["tcp:5432"]["scope"] == "loopback"
    assert snap["gaps"] == []
    orphan = lw.snapshot(root=fake_proc(tmp_path / "b", [("tcp", "0.0.0.0", 8080, "0A", 900)], {}))
    assert orphan["listeners"]["tcp:8080"]["owners_known"] is False
    assert orphan["gaps"] == ["no visible program owns tcp:8080"]


# ------------------------------------------------------------- compare

@pytest.mark.parametrize("exe,comm,address,severity,technique", [
    ("/usr/bin/nginx", "nginx", "0.0.0.0", "MEDIUM", None),
    ("/usr/bin/nginx", "nginx", "127.0.0.1", "LOW", None),
    ("/usr/bin/python3.12", "python3", "0.0.0.0", "MEDIUM", None),
    ("/bin/sh", "sh", "0.0.0.0", "HIGH", "T1059"),
    ("/usr/bin/ncat", "ncat", "127.0.0.1", "HIGH", "T1059"),
    ("/tmp/.x/agent", "agent", "0.0.0.0", "HIGH", None),
    ("/dev/shm/agent (deleted)", "agent", "0.0.0.0", "HIGH", None),
])
def test_new_listener_severity_follows_owner_and_reach(tmp_path, exe, comm, address, severity, technique):
    old = state(tmp_path, "old")
    new = state(tmp_path, "new", [("tcp", address, 4444, "0A", 500)], {500: (exe, comm, [500])})
    findings, closed = lw.compare(old, new)
    assert [f["rule_id"] for f in findings] == ["NEW_LISTENER"] and closed == []
    found = findings[0]
    assert (found["listener"], found["severity"]) == ("tcp:4444", severity)
    assert ("T1059" in found["techniques"]) == (technique == "T1059")
    if comm == "python3":
        assert found["detail"]["reasons"] == ["/usr/bin/python3.12 is a script interpreter"]
    if "deleted" in exe:
        assert found["programs"][0]["flags"] == ["deleted", "temporary"]


def test_a_port_taken_over_by_another_program(tmp_path):
    old = state(tmp_path, "old")
    swapped = state(tmp_path, "swap", [("tcp", "0.0.0.0", 22, "0A", 601)], {600: ("/usr/local/bin/sshd2", "sshd2", [601])},
                    replace={101, 102})
    found = by_key(lw.compare(old, swapped)[0])
    changed = found[("LISTENER_PROGRAM_CHANGED", "tcp:22")]
    assert changed["severity"] == "MEDIUM" and changed["detail"]["previous_programs"] == ["/usr/sbin/sshd"]
    dropped = state(tmp_path, "tmp", [("tcp", "0.0.0.0", 22, "0A", 701)], {700: ("/var/tmp/sshd", "sshd", [701])},
                    replace={101, 102})
    assert by_key(lw.compare(old, dropped)[0])[("LISTENER_PROGRAM_CHANGED", "tcp:22")]["severity"] == "HIGH"
    hidden = state(tmp_path, "hidden", [("tcp", "0.0.0.0", 22, "0A", 801)], {}, replace={101, 102})
    assert ("LISTENER_PROGRAM_CHANGED", "tcp:22") not in by_key(lw.compare(old, hidden)[0]), \
        "an owner that is not visible is not a change"


def test_wider_exposure_and_closed_listeners(tmp_path):
    old = state(tmp_path, "old")
    exposed = state(tmp_path, "wide", [("tcp", "0.0.0.0", 5432, "0A", 103)], replace={103})
    found = by_key(lw.compare(old, exposed)[0])[("LISTENER_EXPOSED", "tcp:5432")]
    assert found["severity"] == "MEDIUM" and found["detail"]["previous_scope"] == "loopback"
    assert found["techniques"] == ["T1133"]
    narrowed = state(tmp_path, "narrow", [("tcp", "127.0.0.1", 22, "0A", 101)], replace={101, 102})
    findings, closed = lw.compare(old, narrowed)
    assert findings == [], "less exposure is not a finding"
    gone = state(tmp_path, "gone", replace={104, 105})
    findings, closed = lw.compare(old, gone)
    assert findings == [] and closed == [{"listener": "udp:5353", "programs": ["/usr/sbin/avahi-daemon"]}]


# ------------------------------------------------------------- baseline files

def test_baseline_check_and_accept_files(tmp_path, monkeypatch):
    root = fake_proc(tmp_path / "root", BASE_SOCKETS, BASE_PROCESSES)
    manifest = tmp_path / "conf" / "listeners.json"
    with pytest.raises(lw.ListenerError, match="run megalodon listeners baseline"):
        lw.check(manifest, root=root)
    result = lw.baseline(manifest, root=root)
    assert result["listeners"] == 3 and stat.S_IMODE(manifest.stat().st_mode) == 0o600
    assert b"curl" not in manifest.read_bytes(), "a client's socket is not recorded"
    with pytest.raises(lw.ListenerError, match="exists"):
        lw.baseline(manifest, root=root)
    assert lw.check(manifest, root=root)["findings"] == []
    newer = fake_proc(tmp_path / "root2", BASE_SOCKETS + [("tcp", "0.0.0.0", 8443, "0A", 900)],
                      {**BASE_PROCESSES, 900: ("/usr/bin/caddy", "caddy", [900])})
    assert [f["listener"] for f in lw.check(manifest, root=newer)["findings"]] == ["tcp:8443"]
    assert lw.accept(manifest, root=newer)["action"] == "accept"
    assert lw.check(manifest, root=newer)["findings"] == []
    os.chmod(manifest, 0o644)
    with pytest.raises(lw.ListenerError, match="mode-600"):
        lw.check(manifest, root=newer)
    os.chmod(manifest, 0o600)
    manifest.write_text("{}", encoding="utf-8")
    with pytest.raises(lw.ListenerError, match="unsupported format"):
        lw.check(manifest, root=newer)


@linux
def test_a_real_listener_is_found_with_its_program(tmp_path):
    manifest = tmp_path / "listeners.json"
    lw.baseline(manifest)
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        found = [f for f in lw.check(manifest)["findings"] if f["port"] == port]
    assert [(f["rule_id"], f["severity"], f["scope"]) for f in found] == [("NEW_LISTENER", "LOW", "loopback")]
    assert found[0]["programs"][0]["path"] == os.path.realpath(f"/proc/{os.getpid()}/exe")


def test_cli_exit_codes(tmp_path, monkeypatch, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    manifest = str(tmp_path / "listeners.json")
    roots = iter([fake_proc(tmp_path / "r1", BASE_SOCKETS, BASE_PROCESSES)] * 2
                 + [fake_proc(tmp_path / "r2", BASE_SOCKETS + [("tcp", "0.0.0.0", 31337, "0A", 990)],
                              {**BASE_PROCESSES, 990: ("/bin/bash", "bash", [990])})])
    real = lw.snapshot
    monkeypatch.setattr(lw, "snapshot", lambda **_: real(root=next(roots)))
    assert code("listeners", "check", "--manifest", manifest) == 2
    assert code("listeners", "baseline", "--manifest", manifest) == 0
    assert code("listeners", "check", "--manifest", manifest) == 0
    capsys.readouterr()
    assert code("listeners", "check", "--manifest", manifest) == 1
    report = json.loads(capsys.readouterr().out)
    assert [(f["rule_id"], f["severity"]) for f in report["findings"]] == [("NEW_LISTENER", "HIGH")]
