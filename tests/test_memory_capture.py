"""Process memory: flagged regions, a sweep, sealed captures that `evidence verify` checks, and a live child process."""
from __future__ import annotations

import json
import mmap
import os
from pathlib import Path
import subprocess
import sys

import pytest

from megalodon import evidence
from megalodon import memory_capture as mc
from megalodon import response_engine as re_

ELF = b"\x7fELF\x02\x01\x01" + b"\0" * 57


def region(perms, path="", inode=0, start=0x1000, end=0x2000):
    return dict(start=start, end=end, perms=perms, offset=0, inode=inode, path=path)


def test_which_regions_are_suspicious():
    assert mc.flags(region("r-xp", "/usr/lib/libc.so.6", 5)) == []
    assert mc.flags(region("rw-p")) == [], "data, not code"
    assert mc.flags(region("r-xp", "[vdso]")) == []
    assert mc.flags(region("r-xp"), b"\x90\x90\x90\x90") == ["anonymous_executable"]
    assert mc.flags(region("rwxp"), ELF[:4]) == ["anonymous_executable", "elf_in_anonymous", "writable_executable"]
    assert mc.flags(region("rwxs", "/dev/zero (deleted)", 7), ELF[:4]) == [
        "anonymous_executable", "elf_in_anonymous", "writable_executable"], "shared anonymous memory"
    assert mc.flags(region("r-xs", "/memfd:stage2 (deleted)", 9)) == ["memfd"]
    assert mc.flags(region("r-xp", "/tmp/.x/libhook.so", 9)) == ["temporary"]
    assert mc.flags(region("r-xp", "/opt/app/lib.so (deleted)", 9)) == ["deleted"]


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "root"
    proc = base / "proc/300"
    proc.mkdir(parents=True)
    os.symlink("/usr/bin/agent", proc / "exe")
    (proc / "stat").write_text("300 (agent) S 1 " + " ".join(["0"] * 17) + " 777 0 0\n")
    (proc / "status").write_text("Name:\tagent\n")
    (proc / "cmdline").write_bytes(b"agent\0--token\0secret\0")
    (proc / "maps").write_text(
        "00001000-00002000 r-xp 00000000 00:00 0 \n"                                     # an ELF image, loaded from nowhere
        "00002000-00003000 r-xs 00000000 00:01 9 /memfd:stage2 (deleted)\n"
        "00003000-00004000 r-xp 00000000 08:01 12 /usr/lib/x86_64-linux-gnu/libc.so.6 (deleted)\n"   # an update
        "00004000-00005000 rw-p 00000000 00:00 0 \n"
        "00005000-00006000 r-xp 00000000 08:01 13 /tmp/.x/libhook.so\n"
        "7ffe0000-7ffe1000 r-xp 00000000 00:00 0 [vdso]\n")
    memory = bytearray(0x6000)
    memory[0x1000:0x1000 + len(ELF)] = ELF
    memory[0x2000:0x2010] = b"\x90" * 16
    memory[0x4000:0x4010] = b"heap data......."
    (proc / "mem").write_bytes(bytes(memory))
    return base


def rules(report):
    return [(f["rule_id"], f["region"]) for f in report["findings"]]


def test_inspect_flags_fileless_code(root):
    report = mc.inspect(300, root=str(root))
    assert rules(report) == [("MEMORY_ELF_IN_ANONYMOUS", "1000-2000 r-xp"),
                             ("MEMORY_EXECUTABLE_MEMFD", "2000-3000 r-xs"),
                             ("MEMORY_EXECUTABLE_TEMPORARY", "5000-6000 r-xp")]
    assert report["findings"][0]["severity"] == "CRITICAL"
    assert report["findings"][0]["evidence"]["processes"] == [dict(pid=300, start=777, program="/usr/bin/agent")]
    assert [r["address"] for r in report["regions"]] == ["1000-2000", "2000-3000", "3000-4000", "5000-6000"]
    with pytest.raises(mc.MemoryCaptureError, match="does not exist"):
        mc.inspect(301, root=str(root))


def test_capture_seals_the_suspicious_regions(root, tmp_path):
    bundle = tmp_path / "bundle"
    result = mc.capture(300, start=777, output=bundle, root=str(root))
    assert result["regions"] == 4 and result["bytes"] == 4 * 0x1000
    saved = json.loads((bundle / "regions.json").read_text())
    assert [r["address"] for r in saved] == ["1000-2000", "2000-3000", "3000-4000", "5000-6000"]
    assert (bundle / "regions/0000000000001000-0000000000002000.bin").read_bytes()[:len(ELF)] == ELF
    assert "command_line" not in json.loads((bundle / "process.json").read_text()), "only when asked"
    checked = evidence.verify(bundle, expected=result["manifest_sha256"])
    assert checked["intact"] and oct(bundle.stat().st_mode & 0o777) == "0o500"
    everything = mc.capture(300, output=tmp_path / "all", everything=True, command_line=True, root=str(root))
    assert everything["regions"] == 5, "every readable region but the kernel's"
    assert json.loads((tmp_path / "all/process.json").read_text())["command_line"] == "agent --token secret"
    with pytest.raises(mc.MemoryCaptureError, match="different process"):
        mc.capture(300, start=778, output=tmp_path / "other", root=str(root))
    with pytest.raises(mc.MemoryCaptureError, match="never overwritten"):
        mc.capture(300, output=bundle, root=str(root))
    small = mc.capture(300, output=tmp_path / "small", limit=0x1800, root=str(root))
    assert small["regions"] == 1 and any("capture limit" in gap for gap in small["gaps"])


def test_findings_become_shadow_decisions_and_the_cli(root, tmp_path, capsys, monkeypatch):
    report = mc.sweep(root=str(root))
    assert report["processes"] == 1 and [f["rule_id"] for f in report["findings"]][0] == "MEMORY_ELF_IN_ANONYMOUS"
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=re_.memory_signals(report), protected=set())
    decisions = {json.loads(line)["playbook"]: json.loads(line)
                 for line in (tmp_path / "ledger.jsonl").read_text().splitlines()}
    assert set(decisions) == {"code-loaded-into-memory", "code-run-from-memory"}
    assert any(a["action"] == "suspend_process" and a["target"] == "300@777:/usr/bin/agent"
               for a in decisions["code-loaded-into-memory"]["actions"])
    from megalodon.cli import main
    monkeypatch.setattr(mc, "inspect", lambda pid, root="/", real=mc.inspect: real(300, root=str(tmp_path / "root")))
    with pytest.raises(SystemExit) as exit_:
        main(["memory", "inspect", "300"])
    assert exit_.value.code == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "MEMORY_ELF_IN_ANONYMOUS"


CHILD = """
import mmap, os, sys, time
image = mmap.mmap(-1, 8192, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                  prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
image.write(b'\\x7fELF' + b'\\x02\\x01\\x01' + b'\\0' * 57)
print(hex(__import__('ctypes').addressof(__import__('ctypes').c_char.from_buffer(image))), flush=True)
time.sleep(30)
"""


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
def test_a_live_process_with_an_elf_image_in_anonymous_memory(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", CHILD], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = child.stdout.readline().strip()
        if not line:
            pytest.skip("this kernel refuses writable executable memory: " + child.stderr.read()[:200])
        address = int(line, 16)
        report = mc.inspect(child.pid)
        if report["gaps"]:
            pytest.skip("the child's memory cannot be read here: " + report["gaps"][0])
        hit = [f for f in report["findings"] if f["rule_id"] == "MEMORY_ELF_IN_ANONYMOUS"]
        assert hit and hit[0]["region"].startswith(f"{address:x}-")
        result = mc.capture(child.pid, output=tmp_path / "bundle")
        saved = json.loads((tmp_path / "bundle/regions.json").read_text())
        image = next(r for r in saved if r["address"].startswith(f"{address:x}-"))
        assert (tmp_path / "bundle" / image["file"]).read_bytes()[:4] == b"\x7fELF"
        assert evidence.verify(tmp_path / "bundle", expected=result["manifest_sha256"])["intact"]
    finally:
        child.kill()
        child.wait()
