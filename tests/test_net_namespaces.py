"""Every network namespace: a container's connections and listeners are watched, named, and kept apart."""
from __future__ import annotations

import json
import os

import pytest

from megalodon import egress_watch as ew
from megalodon import listener_watch as lw
from megalodon import net_namespaces as nn
from megalodon import response_engine as re_
from test_process_network import HEAD, proc, row, tables

HOST_NS, CONTAINER_NS, OTHER_NS = "net:[4026531840]", "net:[4026532501]", "net:[4026532777]"
CONTAINER = "ab12cd34ef56" + "0" * 52


def namespace(root, pid, space):
    (root / f"proc/{pid}/ns").mkdir(parents=True, exist_ok=True)
    os.symlink(space, root / f"proc/{pid}/ns/net")


def own_tables(root, pid, tcp=()):
    folder = root / f"proc/{pid}/net"
    folder.mkdir(parents=True, exist_ok=True)
    for name in ("tcp", "udp", "tcp6", "udp6"):
        (folder / name).write_text(HEAD + "".join(tcp if name == "tcp" else ()))
    (folder / "if_inet6").write_text("")


def stat_line(root, pid, start):
    fields = ["S", "1"] + ["0"] * 17 + [str(start)]
    (root / f"proc/{pid}/stat").write_text(f"{pid} (prog) {' '.join(fields)} 0 0\n")


@pytest.fixture
def machine(tmp_path):
    """A host with ssh out and sshd listening, and one Docker container with its own network."""
    root = tmp_path
    tables(root, tcp=[row(("192.168.1.5", 50001), ("140.82.112.3", 22), "01", 702),
                      row(("0.0.0.0", 22), ("0.0.0.0", 0), "0A", 710)])
    (root / "proc/self/ns").mkdir(parents=True)
    os.symlink(HOST_NS, root / "proc/self/ns/net")
    proc(root, 101, "/usr/bin/ssh", [702], cmdline=b"ssh\0host\0")
    proc(root, 102, "/usr/sbin/sshd", [710], comm="sshd", cmdline=b"sshd\0")
    for pid, start in ((101, 6000), (102, 6100)):
        stat_line(root, pid, start)
        namespace(root, pid, HOST_NS)
    # The container: a web server listening on 8080 and calling an API, in its own namespace.
    proc(root, 300, "/usr/bin/python3", [901, 902], cmdline=b"python3\0/app/server.py\0")
    stat_line(root, 300, 9000)
    namespace(root, 300, CONTAINER_NS)
    (root / "proc/300/cgroup").write_text(f"0::/system.slice/docker-{CONTAINER}.scope\n")
    own_tables(root, 300, tcp=[row(("172.17.0.2", 8080), ("0.0.0.0", 0), "0A", 901),
                               row(("172.17.0.2", 40000), ("93.184.216.34", 443), "01", 902)])
    return root


def plant(root, pid, inode, exe, remote, space=CONTAINER_NS, start=9500):
    """A process in a namespace that already has tables, connecting out."""
    proc(root, pid, exe, [inode], cmdline=exe.encode() + b"\0")
    stat_line(root, pid, start)
    namespace(root, pid, space)
    with open(root / "proc/300/net/tcp", "a") as table:
        table.write(row(("172.17.0.2", 41000 + inode % 1000), remote, "01", inode))


def test_each_namespace_is_found_once_with_its_container(machine):
    # On a real machine every process has /proc/PID/net: the host's own processes, and more than one per container.
    own_tables(machine, 101)
    proc(machine, 305, "/usr/bin/python3", [], cmdline=b"python3\0worker.py\0")
    namespace(machine, 305, CONTAINER_NS)
    own_tables(machine, 305)
    spaces, gaps = nn.namespaces(str(machine))
    assert [(s["id"], s["net"], s["own"], s["container"]) for s in spaces] == [
        (HOST_NS, "proc/net", True, None),
        (CONTAINER_NS, "proc/300/net", False, "docker:ab12cd34ef56")]
    assert gaps == []
    assert nn.label(spaces[1]) == "container docker:ab12cd34ef56" and nn.label(spaces[0]) is None


def test_a_container_s_connections_are_seen_and_kept_apart(machine, tmp_path):
    seen, _ = ew.observe(str(machine))
    inside = next(c for c in seen if c["pid"] == 300)
    assert (inside["program"], inside["executable"], inside["namespace"], inside["container"]) == (
        "[container] /usr/bin/python3 /app/server.py", "/usr/bin/python3", CONTAINER_NS, "docker:ab12cd34ef56")
    assert next(c for c in seen if c["pid"] == 101).get("namespace") is None, "the host's own, unlabelled"
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine), all_namespaces=True)
    assert ew.check(manifest, root=str(machine))["findings"] == []
    plant(machine, 301, 950, "/tmp/.cache/x", ("93.184.215.66", 4444))
    report = ew.check(manifest, root=str(machine))
    assert sorted((f["rule_id"], f["program"]) for f in report["findings"]) == [
        ("NEW_OUTBOUND_PROGRAM", "[container] /tmp/.cache/x"), ("OUTBOUND_FROM_TEMPORARY", "[container] /tmp/.cache/x")]
    found = report["findings"][0]
    assert found["detail"].startswith("in container docker:ab12cd34ef56: ")
    assert found["evidence"]["processes"] == [dict(program="/tmp/.cache/x", pid=301, start=9500)], \
        "the process is named exactly, so it can be paused"


def test_a_baseline_from_before_lists_containers_instead_of_reporting_them_new(machine, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine), all_namespaces=False)
    report = ew.check(manifest, root=str(machine))
    assert report["findings"] == []
    assert report["newly_watched"] == [dict(program="[container] /usr/bin/python3 /app/server.py",
                                            where="docker:ab12cd34ef56")]
    plant(machine, 301, 950, "/tmp/.cache/x", ("93.184.215.66", 4444))
    assert [f["rule_id"] for f in ew.check(manifest, root=str(machine))["findings"]] == ["OUTBOUND_FROM_TEMPORARY"], \
        "a dropped tool is reported whatever the baseline knows"
    ew.learn(manifest, root=str(machine), all_namespaces=True)
    assert "newly_watched" not in ew.check(manifest, root=str(machine))


def test_a_container_s_listeners_never_merge_with_the_host_s(machine, tmp_path):
    state = lw.snapshot(root=str(machine), all_namespaces=True)
    assert sorted(state["listeners"]) == ["container/tcp:8080", "tcp:22"]
    assert state["listeners"]["container/tcp:8080"]["where"] == ["docker:ab12cd34ef56"]
    manifest = tmp_path / "listeners.json"
    lw.baseline(manifest, root=str(machine), all_namespaces=True)
    proc(machine, 302, "/usr/bin/nc", [960], comm="nc", cmdline=b"nc\0-lp\0004444\0")
    namespace(machine, 302, CONTAINER_NS)
    with open(machine / "proc/300/net/tcp", "a") as table:
        table.write(row(("0.0.0.0", 4444), ("0.0.0.0", 0), "0A", 960))
    report = lw.check(manifest, root=str(machine), all_namespaces=True)
    [found] = report["findings"]
    assert (found["rule_id"], found["listener"], found["severity"], found["where"]) == (
        "NEW_LISTENER", "container/tcp:4444", "HIGH", ["docker:ab12cd34ef56"])
    # Without root, the container cannot be read: a gap, not a closed port.
    without = lw.check(manifest, root=str(machine), all_namespaces=False)
    assert without["findings"] == [] and without["closed"] == []


def test_a_listener_baseline_from_before_lists_containers(machine, tmp_path):
    manifest = tmp_path / "listeners.json"
    lw.baseline(manifest, root=str(machine), all_namespaces=False)
    report = lw.check(manifest, root=str(machine), all_namespaces=True)
    assert report["findings"] == [] and report["newly_watched"] == [
        dict(listener="container/tcp:8080", where=["docker:ab12cd34ef56"], programs=["/usr/bin/python3"])]


def test_a_namespace_without_a_container_is_named_by_its_namespace(machine):
    proc(machine, 400, "/usr/bin/openvpn", [970], cmdline=b"openvpn\0")
    stat_line(machine, 400, 9900)
    namespace(machine, 400, OTHER_NS)
    own_tables(machine, 400, tcp=[row(("10.8.0.2", 40100), ("151.101.1.70", 1194), "01", 970)])
    seen, _ = ew.observe(str(machine))
    vpn = next(c for c in seen if c["pid"] == 400)
    assert (vpn["program"], vpn["namespace"], vpn["container"]) == ("[namespace] /usr/bin/openvpn", OTHER_NS, None)


def test_a_container_s_address_is_never_a_block_target(machine, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(machine), all_namespaces=True)
    plant(machine, 301, 950, "/tmp/.cache/x", ("93.184.215.66", 4444))
    signals = re_.egress_signals(ew.check(manifest, root=str(machine)))
    assert all(not s.entities["address"] and s.entities["peer"] == {"93.184.215.66"} for s in signals), \
        "this machine's blocks do not stop a container's routed traffic"
    assert signals[0].entities["process_id"] == {"301@9500:/tmp/.cache/x"}
    host = re_.egress_signals(dict(findings=[dict(rule_id="NEW_OUTBOUND_PROGRAM", severity="HIGH", address="203.0.113.7",
                                                  protocol="tcp", port=443, program="/opt/x", evidence={})]))
    assert host[0].entities["address"] == {"203.0.113.7"}
    [piped] = re_.ingest_signals([json.dumps(dict(rule_id="X", severity="HIGH", dst_ip="203.0.113.9",
                                                  namespace=CONTAINER_NS))], re_._now())[0]
    assert not piped.entities["address"] and piped.entities["peer"] == {"203.0.113.9"}


def test_without_root_other_accounts_namespaces_are_a_gap(machine, monkeypatch):
    os.remove(machine / "proc/300/ns/net")
    monkeypatch.setattr(nn.os, "geteuid", lambda: 1000)
    spaces, gaps = nn.namespaces(str(machine))
    assert [s["id"] for s in spaces] == [HOST_NS]
    assert gaps == ["1 processes' network namespaces could not be seen: run as root to read every one"]
