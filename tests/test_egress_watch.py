"""Egress watch: programs that connect out, learned, and the first time a new one does."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest

from megalodon import egress_watch as ew
from megalodon import response_engine as re_
from test_process_network import proc, row, tables  # noqa: F401

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
ME = ("192.168.1.5", 50000)


def stat_line(root, pid, start):
    fields = ["S", "1"] + ["0"] * 17 + [str(start)]
    (root / f"proc/{pid}/stat").write_text(f"{pid} (prog) {' '.join(fields)} 0 0\n")


@pytest.fixture
def host(tmp_path):
    tables(tmp_path, tcp=[
        row(ME, ("151.101.1.69", 443), "01", 701),         # the package manager, known
        row(("192.168.1.5", 50001), ("140.82.112.3", 22), "01", 702),   # ssh to a public host
        row(("192.168.1.5", 50002), ("127.0.0.1", 8080), "01", 703),    # loopback: not outgoing
        row(("0.0.0.0", 22), ("0.0.0.0", 0), "0A", 704),                # a listener: not outgoing
        row(("192.168.1.5", 50003), ("192.168.1.1", 53), "01", 705),    # LAN: off by default
    ])
    proc(tmp_path, 100, "/usr/lib/apt/methods/https", [701], cmdline=b"/usr/lib/apt/methods/https\0")
    proc(tmp_path, 101, "/usr/bin/ssh", [702, 705], cmdline=b"ssh\0host\0")
    proc(tmp_path, 102, "/usr/bin/curl", [703], cmdline=b"curl\0localhost:8080\0")
    for pid, start in ((100, 5000), (101, 6000), (102, 7000)):
        stat_line(tmp_path, pid, start)
    return tmp_path


def add_connection(root, inode, remote, pid, exe, cmdline, start=9000, deleted=False):
    with open(root / "proc/net/tcp", "a") as table:
        table.write(row(("192.168.1.5", 51000 + inode % 1000), remote, "02", inode))
    proc(root, pid, exe + (" (deleted)" if deleted else ""), [inode], cmdline=cmdline)
    stat_line(root, pid, start)


def rules(report):
    return sorted((f["rule_id"], f["program"], f["port"]) for f in report["findings"])


def test_learned_programs_are_quiet_and_new_ones_are_reported(host, tmp_path):
    manifest = tmp_path / "egress.json"
    result = ew.learn(manifest, root=str(host))
    assert result["programs"] == 2 and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert sorted(ew.read(manifest)["programs"]) == ["/usr/bin/ssh", "/usr/lib/apt/methods/https"]
    assert ew.check(manifest, root=str(host))["findings"] == []
    add_connection(host, 801, ("93.184.215.50", 8443), 200, "/opt/vendor/agent", b"/opt/vendor/agent\0")
    add_connection(host, 802, ("93.184.215.51", 4444), 201, "/tmp/.x/kworker", b"kworker\0")
    add_connection(host, 803, ("140.82.112.3", 2222), 202, "/usr/bin/ssh", b"ssh\0-p\0002222\0h\0")
    add_connection(host, 804, ("93.184.216.7", 443), 203, "/usr/bin/python3.12",
                   b"/usr/bin/python3.12\0/home/u/.cache/sync.py\0")
    report = ew.check(manifest, root=str(host))
    assert rules(report) == [
        ("NEW_OUTBOUND_PORT", "/usr/bin/ssh", 2222),
        ("NEW_OUTBOUND_PROGRAM", "/opt/vendor/agent", 8443),
        ("NEW_OUTBOUND_PROGRAM", "/tmp/.x/kworker", 4444),
        ("NEW_OUTBOUND_PROGRAM", "/usr/bin/python3.12 /home/u/.cache/sync.py", 443),
        ("OUTBOUND_FROM_TEMPORARY", "/tmp/.x/kworker", 4444)]
    temporary = next(f for f in report["findings"] if f["rule_id"] == "OUTBOUND_FROM_TEMPORARY")
    assert temporary["severity"] == "HIGH" and temporary["evidence"]["processes"] == [
        {"program": "/tmp/.x/kworker", "pid": 201, "start": 9000}]


def test_a_script_is_its_own_program_and_temporary_programs_are_never_learned(host, tmp_path):
    manifest = tmp_path / "egress.json"
    add_connection(host, 811, ("93.184.216.7", 443), 210, "/usr/bin/python3.12",
                   b"/usr/bin/python3.12\0/opt/app/backup.py\0")
    add_connection(host, 812, ("93.184.215.9", 443), 211, "/dev/shm/x", b"x\0")
    ew.learn(manifest, root=str(host))
    learned = ew.read(manifest)["programs"]
    assert "/usr/bin/python3.12 /opt/app/backup.py" in learned and "/dev/shm/x" not in learned
    add_connection(host, 813, ("93.184.216.7", 443), 212, "/usr/bin/python3.12",
                   b"/usr/bin/python3.12\0/tmp/stage2.py\0")
    assert rules(ew.check(manifest, root=str(host))) == [
        ("NEW_OUTBOUND_PROGRAM", "/dev/shm/x", 443),
        ("NEW_OUTBOUND_PROGRAM", "/usr/bin/python3.12 /tmp/stage2.py", 443),
        ("OUTBOUND_FROM_TEMPORARY", "/dev/shm/x", 443)]


def test_allow_and_a_watch_that_reloads_the_baseline(host, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(host))
    add_connection(host, 821, ("93.184.215.70", 8443), 220, "/opt/vendor/agent", b"agent\0")
    found = []
    watcher = ew.Watcher(manifest, found.append, root=str(host))
    watcher.poll()
    watcher.poll()
    assert [f["rule_id"] for f in found] == ["NEW_OUTBOUND_PROGRAM"], "reported once, not every poll"
    ew.allow(manifest, "/opt/vendor/agent", "tcp/8443")
    found.clear()
    watcher.last.clear()
    watcher.poll()
    assert found == [], "the watch picked up the allowed program without a restart"
    with pytest.raises(ew.EgressError, match="tcp/443"):
        ew.allow(manifest, "/opt/vendor/agent", "443")
    os.chmod(manifest, 0o644)
    with pytest.raises(ew.EgressError, match="mode-600"):
        ew.check(manifest, root=str(host))


def test_private_destinations_only_when_asked(host, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(host), include_private=True)
    assert "tcp/53" in ew.read(manifest)["programs"]["/usr/bin/ssh"]["ports"]
    add_connection(host, 831, ("192.168.1.40", 445), 230, "/usr/bin/smbclient", b"smbclient\0")
    found = ew.check(manifest, root=str(host))["findings"]
    assert [(f["rule_id"], f["severity"]) for f in found] == [("NEW_OUTBOUND_PROGRAM", "MEDIUM")]


@linux
def test_a_real_connection_is_matched_to_its_program(tmp_path, monkeypatch):
    # Loopback stands in for the internet here; the socket tables and descriptors are real.
    monkeypatch.setattr(ew, "_scope", lambda address: "public")
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        port = server.getsockname()[1]
        manifest = tmp_path / "egress.json"
        ew.learn(manifest)
        script = tmp_path / "phone_home.py"
        script.write_text("import socket, sys, time\n"
                          f"s = socket.create_connection(('127.0.0.1', {port}))\n"
                          "print('up', flush=True)\ntime.sleep(5)\n")
        child = subprocess.Popen([sys.executable, str(script)], stdout=subprocess.PIPE, text=True)
        try:
            assert child.stdout.readline().strip() == "up"
            accepted, _ = server.accept()
            report = ew.check(manifest)
        finally:
            child.kill()
            child.wait()
        accepted.close()
    mine = [f for f in report["findings"] if f["evidence"]["processes"][0]["pid"] == child.pid]
    assert [(f["rule_id"], f["port"]) for f in mine] == [("NEW_OUTBOUND_PROGRAM", port)]
    assert mine[0]["program"] == f"{os.path.realpath(sys.executable)} {script}" or \
        mine[0]["program"].endswith(str(script))


def test_findings_reach_the_response_engine(host, tmp_path):
    manifest = tmp_path / "egress.json"
    ew.learn(manifest, root=str(host))
    add_connection(host, 841, ("93.184.215.51", 4444), 240, "/tmp/.x/kworker", b"kworker\0", start=424242)
    signals = re_.egress_signals(ew.check(manifest, root=str(host)))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert {d["playbook"] for d in decisions} == {"dropped-tool-phoning-home", "new-outbound-program"}
    planned = {(a["action"], a["target"], a["status"]) for d in decisions for a in d["actions"]}
    assert ("suspend_process", "240@424242:/tmp/.x/kworker", "would_apply") in planned
    assert any(a == "block_address" and t == "93.184.215.51" for a, t, _ in planned)


def test_cli(host, tmp_path, capsys, monkeypatch):
    from megalodon.cli import main
    real = ew.observe
    monkeypatch.setattr(ew, "observe", lambda root="/", **kw: real(str(host), **kw))
    manifest = tmp_path / "egress.json"

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("egress", "learn", "--manifest", str(manifest)) == 0
    assert code("egress", "check", "--manifest", str(manifest)) == 0
    add_connection(host, 851, ("93.184.215.9", 443), 250, "/opt/new", b"new\0")
    capsys.readouterr()
    assert code("egress", "check", "--manifest", str(manifest)) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "NEW_OUTBOUND_PROGRAM"
    assert code("egress", "allow", "--manifest", str(manifest), "/opt/new") == 0
    assert code("egress", "check", "--manifest", str(manifest)) == 0
    assert code("egress", "check", "--manifest", str(tmp_path / "none.json")) == 2
