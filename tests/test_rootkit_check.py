"""Rootkit cross-checks: one view hides something, the other still sees it."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import pytest

from megalodon import response_engine as re_
from megalodon import rootkit_check as rk

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")


@linux
def test_a_process_hidden_from_the_proc_listing_is_found():
    child = subprocess.Popen(["sleep", "30"])
    try:
        time.sleep(0.1)
        # The listing is what a rootkit hooks; the probe and direct lookup still reach the process.
        hiding = lambda proc: rk._listed_pids(proc) - {child.pid}
        found = rk.hidden_processes(max_pid=max(child.pid + 10, 32768), listed=hiding)
        assert [(f["rule_id"], f["pid"]) for f in found] == [("HIDDEN_PROCESS", child.pid)]
        assert found[0]["severity"] == "CRITICAL" and "opens directly in /proc" in found[0]["detail"]
        # Threads are not listed in /proc by design and are never reported.
        assert rk.hidden_processes(max_pid=max(child.pid + 10, 32768)) == []
    finally:
        child.kill()
        child.wait()


@linux
def test_a_port_missing_from_the_socket_tables_is_found():
    with socket.socket() as backdoor, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as quiet:
        backdoor.bind(("0.0.0.0", 0))
        backdoor.listen(1)
        port = backdoor.getsockname()[1]
        quiet.bind(("127.0.0.1", 0))
        udp = quiet.getsockname()[1]

        def hiding(root):
            ports, gaps = rk.table_ports(root)
            return {"tcp": ports["tcp"] - {port}, "udp": ports["udp"] - {udp}}, gaps
        found, _ = rk.hidden_ports(tables=hiding, first_port=1024)
        assert {(f["protocol"], f["port"]) for f in found} == {("tcp", port), ("udp", udp)}
        clean, _ = rk.hidden_ports(first_port=1024)
        assert not [f for f in clean if f["port"] in (port, udp)], "a listed socket is not hidden"


def test_kernel_module_lists_that_disagree(tmp_path):
    for name, live in (("ext4", True), ("hidden_lkm", True), ("builtin_thing", False)):
        (tmp_path / "sys/module" / name).mkdir(parents=True)
        if live:
            (tmp_path / "sys/module" / name / "initstate").write_text("live\n")
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/modules").write_text("ext4 1000 1 - Live 0x0\nunlinked_kobj 10 0 - Live 0x0\n")
    found, gaps = rk.module_findings(str(tmp_path))
    assert gaps == [] and [f["subject"] for f in found] == ["hidden_lkm", "unlinked_kobj"]
    (tmp_path / "proc/modules").unlink()
    assert rk.module_findings(str(tmp_path))[1] == [
        "the kernel has no loadable modules (/proc/modules is absent); nothing to compare"]


def test_forced_module_taint_is_reported_and_others_noted(tmp_path):
    (tmp_path / "proc/sys/kernel").mkdir(parents=True)
    (tmp_path / "proc/sys/kernel/tainted").write_text(str((1 << 1) | (1 << 12)))
    kernel, found = rk.taint(str(tmp_path))
    assert kernel["flags"] == ["F (a module was loaded by force)", "O (out-of-tree module)"]
    assert [f["rule_id"] for f in found] == ["KERNEL_FORCED_MODULE"]


def test_a_folder_hidden_from_its_listing_is_found(tmp_path, monkeypatch):
    for name in ("a", "b", ".x-rootkit"):
        (tmp_path / "etc" / name).mkdir(parents=True)
    monkeypatch.setattr(rk, "_filesystems", lambda root: {"/": "ext4"})
    assert rk.hidden_directories(str(tmp_path), directories=("/etc",)) == ([], [])
    real = os.scandir

    class Hiding:
        def __init__(self, path):
            self.inner = real(path)

        def __enter__(self):
            return (e for e in self.inner if e.name != ".x-rootkit")

        def __exit__(self, *exc):
            self.inner.close()
    monkeypatch.setattr(rk.os, "scandir", Hiding)
    found, _ = rk.hidden_directories(str(tmp_path), directories=("/etc",))
    assert [(f["rule_id"], f["expected"], f["listed"]) for f in found] == [("HIDDEN_DIRECTORY", 3, 2)]
    monkeypatch.setattr(rk, "_filesystems", lambda root: {"/": "btrfs"})
    assert rk.hidden_directories(str(tmp_path), directories=("/etc",))[0] == [], "btrfs does not count"


def test_preloaded_and_hidden_libraries(tmp_path, monkeypatch):
    (tmp_path / "etc").mkdir()
    assert rk.preload_findings(str(tmp_path)) == ([], [])
    (tmp_path / "usr/lib").mkdir(parents=True)
    (tmp_path / "usr/lib/libhide.so").write_bytes(b"\x7fELF")
    (tmp_path / "etc/ld.so.preload").write_text("# comment\n/usr/lib/libhide.so\n")
    found, _ = rk.preload_findings(str(tmp_path))
    assert [f["rule_id"] for f in found] == ["PRELOAD_LIBRARY"]
    real = os.scandir

    class Hiding:
        def __init__(self, path):
            self.inner = real(path)

        def __enter__(self):
            return (e for e in self.inner if e.name != "libhide.so")

        def __exit__(self, *exc):
            self.inner.close()
    monkeypatch.setattr(rk.os, "scandir", Hiding)
    found, _ = rk.preload_findings(str(tmp_path))
    assert [f["rule_id"] for f in found] == ["PRELOAD_LIBRARY", "HIDDEN_FILE"]


@linux
def test_this_machine_is_clean_and_findings_reach_the_response_engine(tmp_path):
    report = rk.check(max_pid=65536)
    assert report["findings"] == [] and report["schema"] == rk.SCHEMA
    report["findings"] = [rk._finding("HIDDEN_PROCESS", "4242", "process 4242 ...", pid=4242, program="/tmp/.x"),
                          rk._finding("HIDDEN_PORT", "tcp:31337", "...", protocol="tcp", port=31337)]
    signals = re_.rootkit_signals(report)
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert {d["playbook"] for d in decisions} == {"rootkit"}
    assert all({a["action"] for a in d["actions"]} == {"collect_evidence", "notify"} for d in decisions)


def test_cli(capsys, monkeypatch):
    from megalodon.cli import main
    monkeypatch.setattr(rk, "check", lambda **kw: dict(schema=rk.SCHEMA, findings=[], gaps=[], kw=sorted(kw)))
    with pytest.raises(SystemExit) as exit_:
        main(["rootkit", "check", "--skip-ports", "--max-pid", "1000"])
    assert exit_.value.code == 0
    assert json.loads(capsys.readouterr().out)["kw"] == ["max_pid", "ports"]
