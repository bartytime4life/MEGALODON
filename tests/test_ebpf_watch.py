"""eBPF check: new, changed, hidden and dropped-tool programs, with a stand-in kernel and a live socket filter."""
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

from megalodon import ebpf_watch as ew
from megalodon import response_engine as re_


class FakeBpf:
    def __init__(self, programs):
        self.programs = {p["id"]: p for p in programs}

    def ids(self):
        return sorted(self.programs)[:ew.MAX_PROGRAMS]          # the real listing stops at the limit too

    def info(self, prog_id):
        return dict(self.programs[prog_id]) if prog_id in self.programs else None


def program(prog_id, kind, name, tag, uid=0):
    return dict(id=prog_id, type=kind, name=name, tag=tag, uid=uid, load_time_ns=1)


def holder(root, pid, exe, prog_id, argv=None, start=5000, kind="bpf-prog"):
    base = root / "proc" / str(pid)
    (base / "fd").mkdir(parents=True)
    (base / "fdinfo").mkdir()
    os.symlink(exe, base / "exe")
    os.symlink(f"anon_inode:{kind}", base / "fd/7")
    (base / "fdinfo/7").write_text(f"pos:\t0\nprog_type:\t2\nprog_id:\t{prog_id}\n")
    (base / "cmdline").write_bytes(b"\0".join(a.encode() for a in (argv or [exe])) + b"\0")
    (base / "stat").write_text(f"{pid} (x) S 1 " + " ".join(["0"] * 17) + f" {start} 0 0\n")


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "root"
    (base / "proc/sys/kernel").mkdir(parents=True)
    (base / "proc/sys/kernel/unprivileged_bpf_disabled").write_text("2\n")
    (base / "sys/fs/bpf").mkdir(parents=True)
    return base


SYSTEMD = program(10, "cgroup_device", "sd_devices", "aa" * 8)


def rules(report):
    return sorted((f["rule_id"], f["subject"].split(":")[1]) for f in report["findings"])


def test_new_changed_and_dropped_tool_programs(root, tmp_path):
    manifest = tmp_path / "ebpf.json"
    kernel = FakeBpf([SYSTEMD, program(11, "kprobe", "trace_open", "bb" * 8)])
    result = ew.baseline(manifest, root=str(root), bpf=kernel)
    assert result["programs"] == 2 and result["findings"] == [] and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert ew.check(manifest, root=str(root), bpf=kernel)["findings"] == []
    kernel = FakeBpf([SYSTEMD, program(12, "kprobe", "trace_open", "cc" * 8),         # same program, new code
                      program(13, "tracing", "hide_pid", "dd" * 8), program(14, "socket_filter", "dns", "ee" * 8)])
    holder(root, 300, "/dev/shm/.loader", 13, start=777)
    report = ew.check(manifest, root=str(root), bpf=kernel)
    assert rules(report) == [("EBPF_LOADED_BY_DROPPED_TOOL", "tracing"), ("EBPF_NEW_FILTER", "socket_filter"),
                             ("EBPF_NEW_PROGRAM", "tracing"), ("EBPF_PROGRAM_CHANGED", "kprobe")]
    dropped = report["findings"][0]
    assert dropped["severity"] == "CRITICAL" and dropped["evidence"]["processes"] == [
        {"program": "/dev/shm/.loader", "pid": 300, "start": 777}]
    assert "/dev/shm/.loader (pid 300)" in next(f for f in report["findings"]
                                                if f["rule_id"] == "EBPF_NEW_PROGRAM")["detail"]
    assert report["removed"] == ["kprobe:trace_open:" + "bb" * 8]
    ew.accept(manifest, root=str(root), bpf=kernel)
    remaining = ew.check(manifest, root=str(root), bpf=kernel)["findings"]
    assert [f["rule_id"] for f in remaining] == ["EBPF_LOADED_BY_DROPPED_TOOL"], "a dropped holder is never accepted"


def test_a_program_hidden_from_the_kernel_list_is_found(root, tmp_path):
    manifest = tmp_path / "ebpf.json"
    ew.baseline(manifest, root=str(root), bpf=FakeBpf([SYSTEMD]))
    holder(root, 400, "/usr/sbin/cron", 99)              # held, but bpf() no longer lists program 99
    report = ew.check(manifest, root=str(root), bpf=FakeBpf([SYSTEMD]))
    assert rules(report) == [("EBPF_HIDDEN_PROGRAM", "hidden")]
    assert report["findings"][0]["severity"] == "CRITICAL" and "/usr/sbin/cron (pid 400)" in \
        report["findings"][0]["detail"]
    # The exact process, with its start time, so a response targets it and not every cron.
    assert report["findings"][0]["processes"] == [dict(pid=400, program="/usr/sbin/cron", start=5000)]
    assert re_.ebpf_signals(report)[0].entities["process_id"] == {"400@5000:/usr/sbin/cron"}


def test_a_link_reopened_by_id_is_a_holder(root, tmp_path):
    manifest = tmp_path / "ebpf.json"
    ew.baseline(manifest, root=str(root), bpf=FakeBpf([SYSTEMD]))
    holder(root, 410, "/tmp/.l", 98, kind="bpf-link")              # links reopened by ID are spelled bpf-link
    assert rules(ew.check(manifest, root=str(root), bpf=FakeBpf([SYSTEMD]))) == [("EBPF_HIDDEN_PROGRAM", "hidden")]


def test_a_list_cut_short_at_the_limit_is_a_gap_not_hidden_programs(root, tmp_path, monkeypatch):
    manifest = tmp_path / "ebpf.json"
    kernel = FakeBpf([SYSTEMD, program(11, "kprobe", "a", "bb" * 8), program(12, "kprobe", "b", "cc" * 8)])
    ew.baseline(manifest, root=str(root), bpf=kernel)
    monkeypatch.setattr(ew, "MAX_PROGRAMS", 2)
    holder(root, 420, "/usr/sbin/agent", 12)                       # listed by the kernel, past the limit
    report = ew.check(manifest, root=str(root), bpf=kernel)
    assert [f["rule_id"] for f in report["findings"]] == []
    assert any("more than 2 eBPF programs" in gap for gap in report["gaps"])


def test_pins_and_the_unprivileged_setting(root, tmp_path):
    manifest = tmp_path / "ebpf.json"
    ew.baseline(manifest, root=str(root), bpf=FakeBpf([SYSTEMD]))
    (root / "sys/fs/bpf/tc").mkdir()
    (root / "sys/fs/bpf/tc/backdoor").write_text("")
    (root / "proc/sys/kernel/unprivileged_bpf_disabled").write_text("0\n")
    found = rules(ew.check(manifest, root=str(root), bpf=FakeBpf([SYSTEMD])))
    assert found == [("EBPF_PINNED_ADDED", "/sys/fs/bpf/tc/backdoor"), ("EBPF_UNPRIVILEGED_ENABLED",
                                                                        "unprivileged_bpf_disabled")]


def test_without_root_listing_is_a_gap(root, tmp_path):
    class Refused(FakeBpf):
        def ids(self):
            raise PermissionError(1, "Operation not permitted")
    with pytest.raises(ew.EbpfError, match="needs root"):
        ew.baseline(tmp_path / "ebpf.json", root=str(root), bpf=Refused([]))


def _can_load():
    try:
        kernel = ew.Bpf()
        kernel.ids()
        return True
    except (OSError, ew.EbpfError):
        return False


@pytest.mark.skipif(not sys.platform.startswith("linux") or not _can_load(), reason="needs root and bpf()")
def test_a_real_program_loaded_by_a_dropped_script_is_reported(tmp_path):
    manifest = tmp_path / "ebpf.json"
    ew.baseline(manifest)
    loader = tmp_path / "loader.py"           # under a temporary folder: a dropped tool
    number = ew._SYSCALL[__import__("platform").machine()]
    loader.write_text(
        "import ctypes, struct, time\n"
        "libc = ctypes.CDLL(None, use_errno=True)\n"
        "code = struct.pack('=BBhi', 0xb7, 0, 0, 0) + struct.pack('=BBhi', 0x95, 0, 0, 0)\n"
        "insns = ctypes.create_string_buffer(code); lic = ctypes.create_string_buffer(b'GPL')\n"
        "attr = struct.pack('=IIQQIIQII', 1, 2, ctypes.addressof(insns), ctypes.addressof(lic), 0, 0, 0, 0, 0)"
        " + b'megalodon_test'.ljust(16, b'\\0')\n"
        "buf = ctypes.create_string_buffer(attr, 128)\n"
        f"print(libc.syscall({number}, 5, buf, 128), flush=True)\n"
        "time.sleep(5)\n")
    child = subprocess.Popen([sys.executable, str(loader)], stdout=subprocess.PIPE, text=True)
    try:
        assert int(child.stdout.readline()) >= 0, "the kernel refused the test filter"
        report = ew.check(manifest)
    finally:
        child.kill()
        child.wait()
    mine = [f for f in report["findings"] if "megalodon_test" in f["detail"]]
    assert {f["rule_id"] for f in mine} == {"EBPF_NEW_FILTER", "EBPF_LOADED_BY_DROPPED_TOOL"}


def test_findings_become_shadow_decisions_and_the_cli(root, tmp_path, capsys, monkeypatch):
    manifest = tmp_path / "ebpf.json"
    ew.baseline(manifest, root=str(root), bpf=FakeBpf([SYSTEMD]))
    holder(root, 500, "/tmp/.x/ld", 15, start=888)
    kernel = FakeBpf([SYSTEMD, program(15, "lsm", "hook", "ff" * 8)])
    signals = re_.ebpf_signals(ew.check(manifest, root=str(root), bpf=kernel))
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decisions = [json.loads(line) for line in (tmp_path / "ledger.jsonl").read_text().splitlines()]
    assert {d["playbook"] for d in decisions} == {"ebpf-rootkit", "ebpf-change"}
    assert any(a["action"] == "suspend_process" and a["target"] == "500@888:/tmp/.x/ld" and a["status"] ==
               "would_apply" for d in decisions for a in d["actions"])
    from megalodon.cli import main
    monkeypatch.setattr(ew, "Bpf", lambda: kernel)
    real = ew.snapshot
    monkeypatch.setattr(ew, "snapshot", lambda root="/", bpf=None: real(root=str(tmp_path / "root"), bpf=bpf))
    with pytest.raises(SystemExit) as exit_:
        main(["ebpf", "check", "--manifest", str(manifest)])
    assert exit_.value.code == 1
    assert {f["rule_id"] for f in json.loads(capsys.readouterr().out)["findings"]} == {
        "EBPF_NEW_PROGRAM", "EBPF_LOADED_BY_DROPPED_TOOL"}
