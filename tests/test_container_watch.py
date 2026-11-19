"""Containers: escapes, privileged and exposed containers, escape hooks and runtime exposures, from a stand-in /proc."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading

import pytest

from megalodon import container_watch as cw
from megalodon import response_engine as re_

WEB, TOOLS, ROOTLESS = "a" * 64, "b" * 64, "c" * 64
DEFAULT_CAPS = 0x00000000A80425FB          # Docker's default set
EVERYTHING = (1 << 41) - 1                 # cap_last_cap 40
HOST_NS = dict(mnt="mnt:[1]", pid="pid:[2]", net="net:[3]", user="user:[4]")
HOST_MOUNTS = ("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
               "25 22 0:25 / /run rw,nosuid shared:5 - tmpfs tmpfs rw\n")
OWN_ROOT = "100 99 0:50 / / rw,relatime - overlay overlay rw\n" \
           "101 100 8:1 /var/lib/docker/containers/x/hosts /etc/hosts rw,relatime - ext4 /dev/sda1 rw\n"


def process(root, pid, *, cgroup, ns, exe, caps=DEFAULT_CAPS, seccomp="2", mountinfo=OWN_ROOT, comm=None,
            start=5000):
    base = root / "proc" / str(pid)
    (base / "ns").mkdir(parents=True)
    for kind, value in ns.items():
        os.symlink(value, base / "ns" / kind)
    os.symlink(exe, base / "exe")
    (base / "cgroup").write_text(cgroup + "\n")
    (base / "status").write_text(f"Name:\tx\nCapEff:\t{caps:016x}\nSeccomp:\t{seccomp}\n")
    (base / "mountinfo").write_text(mountinfo)
    (base / "comm").write_text((comm or os.path.basename(exe)) + "\n")
    (base / "stat").write_text(f"{pid} (x) S 1 " + " ".join(["0"] * 17) + f" {start} 0 0\n")


def in_container(ident, number, **ns):
    own = dict(mnt=f"mnt:[{number}]", pid=f"pid:[{number + 1}]", net=f"net:[{number + 2}]", user=HOST_NS["user"])
    own.update(ns)
    return dict(cgroup=f"0::/system.slice/docker-{ident}.scope", ns=own)


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "root"
    process(base, 1, cgroup="0::/init.scope", ns=HOST_NS, exe="/usr/lib/systemd/systemd", caps=EVERYTHING,
            mountinfo=HOST_MOUNTS)
    process(base, 300, exe="/usr/sbin/nginx", **in_container(WEB, 10))
    (base / "proc/sys/kernel").mkdir(parents=True)
    (base / "proc/sys/kernel/cap_last_cap").write_text("40\n")
    (base / "proc/sys/kernel/core_pattern").write_text("|/usr/share/apport/apport -p%p -s%s\n")
    (base / "proc/sys/kernel/modprobe").write_text("/sbin/modprobe\n")
    (base / "usr/share/apport").mkdir(parents=True)
    (base / "usr/share/apport/apport").write_text("")
    (base / "sys/fs/cgroup/memory").mkdir(parents=True)
    (base / "sys/fs/cgroup/memory/release_agent").write_text("\n")
    (base / "etc").mkdir()
    (base / "etc/group").write_text("root:x:0:\ndocker:x:999:alice\n")
    return base


def names(*pairs):
    return lambda: [dict(Id=ident, Names=[f"/{name}"], Image=image) for ident, name, image in pairs]


API = names((WEB, "web", "nginx:1.27"), (TOOLS, "tools", "alpine:3"))


def rules(report):
    return sorted((f["rule_id"], f["subject"]) for f in report["findings"])


def test_a_quiet_host_and_containers_that_gain_ways_out(root, tmp_path):
    manifest = tmp_path / "containers.json"
    result = cw.baseline(manifest, root=str(root), api=API)
    assert result["findings"] == [] and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert result["containers"] == [dict(container="docker:web", runtime="docker", image="nginx:1.27", risks=[])]
    assert cw.check(manifest, api=API)["findings"] == []
    # A new container: privileged, in the host's process namespace, with the host's root and the Docker socket.
    process(root, 400, exe="/bin/sh", caps=EVERYTHING, seccomp="0",
            mountinfo=OWN_ROOT + "102 100 8:1 / /host rw - ext4 /dev/sda1 rw\n"
                                 "103 100 0:25 /docker.sock /var/run/docker.sock rw - tmpfs tmpfs rw\n",
            **in_container(TOOLS, 20, pid=HOST_NS["pid"]))
    # The known one gains a capability that is a way out, and loses seccomp.
    (root / "proc/300/status").write_text(f"CapEff:\t{DEFAULT_CAPS | 1 << 21:016x}\nSeccomp:\t0\n")
    report = cw.check(manifest, api=API)
    assert rules(report) == [
        ("CONTAINER_DANGEROUS_CAPABILITY", "container:docker:web:cap:SYS_ADMIN"),
        ("CONTAINER_HOST_PATH_MOUNTED", "container:docker:tools:mount:/"),
        ("CONTAINER_HOST_PID", "container:docker:tools:host_pid"),
        ("CONTAINER_PRIVILEGED", "container:docker:tools:privileged"),
        ("CONTAINER_RUNTIME_SOCKET", "container:docker:tools:socket:/run/docker.sock"),
        ("CONTAINER_UNCONFINED", "container:docker:web:seccomp_off")]
    assert report["added"] == ["docker:tools"]
    privileged = next(f for f in report["findings"] if f["rule_id"] == "CONTAINER_PRIVILEGED")
    assert privileged["detail"] == "docker:tools (alpine:3): privileged"
    assert privileged["evidence"]["processes"] == [dict(pid=400, start=5000, program="/bin/sh")]
    cw.accept(manifest, api=API)
    assert cw.check(manifest, api=API)["findings"] == []


def test_a_process_that_left_its_container_is_an_escape(root, tmp_path):
    manifest = tmp_path / "containers.json"
    cw.baseline(manifest, root=str(root), api=API)
    escaped = in_container(WEB, 10, mnt=HOST_NS["mnt"])
    process(root, 500, exe="/tmp/.x", start=777, **escaped)
    process(root, 501, exe="/usr/bin/runc", comm="runc:[2:INIT]", **escaped)    # the runtime, mid-start
    report = cw.check(manifest, api=API)
    assert rules(report) == [("CONTAINER_ESCAPE", "process:500")]
    finding = report["findings"][0]
    assert finding["severity"] == "CRITICAL" and f"docker:{WEB}" in finding["detail"]
    assert finding["evidence"]["processes"] == [dict(pid=500, start=777, program="/tmp/.x")]
    cw.accept(manifest, api=API)
    assert rules(cw.check(manifest, api=API)) == [("CONTAINER_ESCAPE", "process:500")], "never accepted"


def test_rootless_containers_and_runtimes_without_names(root, tmp_path):
    manifest = tmp_path / "containers.json"
    cw.baseline(manifest, root=str(root))
    # Every capability, but inside its own user namespace: not the host's root.
    process(root, 600, exe="/usr/bin/podman-app", caps=EVERYTHING,
            cgroup=f"0::/user.slice/user-1000.slice/libpod-{ROOTLESS}.scope",
            ns=dict(mnt="mnt:[30]", pid="pid:[31]", net="net:[32]", user="user:[33]"))
    # A Kubernetes pod sharing the host's network.
    process(root, 601, exe="/usr/bin/agent", cgroup="0::/kubepods.slice/kubepods-pod1.slice/cri-containerd-"
            + "d" * 64 + ".scope", ns=dict(mnt="mnt:[40]", pid="pid:[41]", net=HOST_NS["net"], user=HOST_NS["user"]))
    report = cw.check(manifest)
    assert rules(report) == [("CONTAINER_HOST_NETWORK", "container:containerd:dddddddddddd:host_net")]
    assert sorted(report["added"]) == ["containerd:dddddddddddd", "podman:cccccccccccc"]


def test_escape_hooks_the_runtime_api_open_sockets_and_root_groups(root, tmp_path):
    manifest = tmp_path / "containers.json"
    assert cw.baseline(manifest, root=str(root), api=API)["findings"] == []
    (root / "proc/sys/kernel/core_pattern").write_text("|/var/lib/docker/overlay2/x/diff/payload %P\n")
    (root / "sys/fs/cgroup/memory/release_agent").write_text("/tmp/.agent\n")      # exists, but not a system folder
    (root / "tmp").mkdir()
    (root / "tmp/.agent").write_text("")
    (root / "proc/sys/kernel/modprobe").write_text("/usr/sbin/modprobe\n")
    (root / "usr/sbin").mkdir(parents=True)
    (root / "usr/sbin/modprobe").write_text("")
    (root / "etc/group").write_text("root:x:0:\ndocker:x:999:alice,mallory\n")
    (root / "proc/net").mkdir()
    (root / "proc/net/tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000:0947 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1\n")
    (root / "run").mkdir()
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(root / "run/docker.sock"))
    os.chmod(root / "run/docker.sock", 0o666)
    try:
        report = cw.check(manifest, api=API)
    finally:
        server.close()
    assert [(f["severity"], f["rule_id"], f["subject"]) for f in report["findings"]] == [
        ("CRITICAL", "RUNTIME_SOCKET_WORLD_WRITABLE", "file:/run/docker.sock"),
        ("CRITICAL", "ESCAPE_HOOK_SET", "hook:core_pattern"), ("CRITICAL", "ESCAPE_HOOK_SET", "hook:release_agent:memory"),
        ("CRITICAL", "RUNTIME_API_EXPOSED", "listener:0.0.0.0:2375"),
        ("HIGH", "RUNTIME_GROUP_MEMBER_ADDED", "account:mallory"), ("HIGH", "ESCAPE_HOOK_CHANGED", "hook:modprobe")]


def test_names_come_from_the_docker_socket_with_a_read_only_request(root, tmp_path):
    (root / "run").mkdir()
    path = root / "run/docker.sock"
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(1)
    asked = []

    def answer():
        conn, _ = server.accept()
        with conn:
            asked.append(conn.recv(4096))
            body = json.dumps([dict(Id=WEB, Names=["/web"], Image="nginx:1.27")]).encode()
            conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + body)

    thread = threading.Thread(target=answer)
    thread.start()
    try:
        state = cw.snapshot(root=str(root))
    finally:
        thread.join(5)
        server.close()
    assert list(state["containers"]) == ["docker:web"] and state["containers"]["docker:web"]["image"] == "nginx:1.27"
    assert asked and asked[0].startswith(b"GET /containers/json HTTP/1.0\r\n")


def test_findings_become_shadow_decisions_and_the_cli(root, tmp_path, capsys, monkeypatch):
    manifest = tmp_path / "containers.json"
    cw.baseline(manifest, root=str(root), api=API)
    process(root, 500, exe="/tmp/.x", start=777, **in_container(WEB, 10, mnt=HOST_NS["mnt"]))
    process(root, 400, exe="/bin/sh", caps=EVERYTHING, **in_container(TOOLS, 20))
    signals = re_.container_signals(cw.check(manifest, api=API))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert {d["playbook"] for d in decisions} == {"container-escape", "container-exposure"}
    assert any(a["action"] == "suspend_process" and a["target"] == "500@777:/tmp/.x" and a["status"] == "would_apply"
               for d in decisions for a in d["actions"])
    from megalodon.cli import main
    monkeypatch.setattr(cw, "_names", lambda root, api: {WEB: ("web", "nginx:1.27"), TOOLS: ("tools", "alpine:3")})
    with pytest.raises(SystemExit) as exit_:
        main(["containers", "check", "--manifest", str(manifest)])
    assert exit_.value.code == 1
    assert {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]} == {
        "CONTAINER_ESCAPE", "CONTAINER_PRIVILEGED"}
