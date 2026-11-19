"""Evidence collection: a sealed, hashed, read-only snapshot; deleted programs recovered; tampering detected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time

import pytest

from megalodon import evidence as ev

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")


def unseal(path):
    for item in [Path(path), *Path(path).rglob("*")]:
        os.chmod(item, 0o700)


@pytest.fixture
def bundle_dir(tmp_path):
    target = tmp_path / "bundle"
    yield target
    if target.exists():
        unseal(target)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture
def no_reports(monkeypatch):
    monkeypatch.setattr(ev, "reports", lambda root="/", verify_programs=True: ({"stub": {"ok": True}}, []))


# ------------------------------------------------------------------ a real collection

@linux
def test_a_deleted_running_program_is_recovered_and_the_bundle_is_sealed(tmp_path, bundle_dir, no_reports):
    program = tmp_path / "dropped-tool"
    shutil.copy("/bin/sleep", program)
    original = sha256(program)
    child = subprocess.Popen([str(program), "30"])
    try:
        time.sleep(0.2)
        program.unlink()
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            result = ev.collect(output=bundle_dir, hours=1, verify_programs=False)
    finally:
        child.kill()
        child.wait()
    assert result["counts"]["programs_copied"] >= 1
    processes = json.loads((bundle_dir / "processes.json").read_text())
    mine = next(p for p in processes if p["pid"] == child.pid)
    assert {"deleted", "temporary"} <= set(mine["flags"]) and mine["sha256"] == original
    assert "command_line" not in mine, "command lines are off by default"
    copied = next(c for c in json.loads((bundle_dir / "programs.json").read_text()) if c["pid"] == child.pid)
    assert copied["copied"] is True and sha256(bundle_dir / copied["file"]) == original
    assert stat.S_IMODE((bundle_dir / copied["file"]).stat().st_mode) == 0o400, "never executable"
    sockets = json.loads((bundle_dir / "network.json").read_text())
    assert any(s["local"] == f"127.0.0.1:{port}" and s["state"] == "listen" and os.getpid() in s["pids"]
               for s in sockets)
    manifest = json.loads((bundle_dir / "manifest.json").read_text())
    assert result["manifest_sha256"] == sha256(bundle_dir / "manifest.json")
    assert {f["file"] for f in manifest["files"]} >= {"processes.json", "network.json", "report_stub.json",
                                                      copied["file"]}
    assert stat.S_IMODE(bundle_dir.stat().st_mode) == 0o500
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o400 for p in bundle_dir.rglob("*") if p.is_file())
    assert ev.verify(bundle_dir, expected=result["manifest_sha256"])["intact"] is True


@linux
def test_command_lines_only_when_asked(bundle_dir, no_reports):
    ev.collect(output=bundle_dir, hours=1, verify_programs=False, command_lines=True, copy_suspicious=False)
    me = next(p for p in json.loads((bundle_dir / "processes.json").read_text()) if p["pid"] == os.getpid())
    assert me["command_line"] and not (bundle_dir / "programs").exists()


def test_tampering_is_detected(tmp_path, bundle_dir, no_reports):
    result = ev.collect(output=bundle_dir, hours=1, verify_programs=False, copy_suspicious=False)
    with pytest.raises(ev.EvidenceError, match="never overwritten"):
        ev.collect(output=bundle_dir, hours=1, verify_programs=False)
    assert ev.verify(bundle_dir, expected="0" * 64)["problems"] == [
        {"file": "manifest.json", "problem": "differs from the expected digest"}]
    unseal(bundle_dir)
    with open(bundle_dir / "sessions.json", "a") as out:
        out.write(" ")
    (bundle_dir / "extra.txt").write_text("planted")
    (bundle_dir / "network.json").unlink()
    report = ev.verify(bundle_dir, expected=result["manifest_sha256"])
    assert report["intact"] is False and sorted(map(tuple, (p.values() for p in report["problems"]))) == [
        ("extra.txt", "not in the manifest"), ("network.json", "missing"), ("sessions.json", "changed")]
    with pytest.raises(ev.EvidenceError, match="cannot be read"):
        ev.verify(tmp_path / "nothing")


# ------------------------------------------------------------------ parts, on a constructed root

def test_recent_files_in_sensitive_folders(tmp_path):
    root = tmp_path / "root"
    now = datetime(2026, 11, 18, 23, 0, tzinfo=timezone.utc)
    for path, age in (("tmp/new.sh", 1), ("etc/cron.d/new", 2), ("etc/old.conf", 72), ("var/lib/other", 1)):
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(path)
        stamp = (now - timedelta(hours=age)).timestamp()
        os.utime(target, (stamp, stamp))
    os.symlink("/tmp/new.sh", root / "tmp/link")
    found, gaps = ev.recent_files(str(root), hours=24, now=now)
    paths = {f["path"]: f for f in found}
    # ctime cannot be set back, so the old file is excluded only by a window narrower than its ctime age.
    assert {"/tmp/new.sh", "/etc/cron.d/new", "/tmp/link"} <= set(paths) and "/var/lib/other" not in paths
    assert paths["/tmp/new.sh"]["sha256"] == hashlib.sha256(b"tmp/new.sh").hexdigest()
    assert paths["/tmp/link"]["link"] == "/tmp/new.sh" and gaps == []


def test_sessions_are_read_from_utmp(tmp_path):
    (tmp_path / "run").mkdir()
    record = struct.pack(ev.UTMP_FORMAT, 7, 4242, b"pts/0", b"ts/0", b"alice", b"198.51.100.7", 0, 0, 0,
                         1795561200, 0, b"\0" * 16)
    dead = struct.pack(ev.UTMP_FORMAT, 8, 1, b"pts/1", b"", b"", b"", 0, 0, 0, 0, 0, b"\0" * 16)
    (tmp_path / "run/utmp").write_bytes(record + dead)
    found, gaps = ev.sessions(str(tmp_path))
    assert gaps == [] and found == [{"type": "user", "pid": 4242, "user": "alice", "line": "pts/0",
                                     "host": "198.51.100.7", "since": "2026-11-24T23:00:00Z"}]
    assert ev.sessions(str(tmp_path / "none")) == ([], ["no utmp session record found"])


def test_the_collector_changes_nothing_on_the_machine():
    source = inspect.getsource(ev)
    for forbidden in ("subprocess", "os.kill", "killpg", "os.system", "popen", "unlink", "os.remove", "rmtree",
                      "os.rename", "os.replace", "shutil"):
        assert forbidden not in source, forbidden


def test_cli(tmp_path, bundle_dir, no_reports, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("evidence", "collect", "--output", str(bundle_dir), "--hours", "1", "--skip-program-verification",
                "--no-program-copies") == 0
    digest = json.loads(capsys.readouterr().out)["manifest_sha256"]
    assert code("evidence", "verify", str(bundle_dir), "--expected", digest) == 0
    assert code("evidence", "verify", str(bundle_dir), "--expected", "0" * 64) == 1
    assert code("evidence", "collect", "--output", str(bundle_dir)) == 2


# ------------------------------------------------------------------ limits hold while reading

def _claims(size):
    """An fstat that reports a smaller size than the file really has, as for a file still growing."""
    real = os.fstat

    def fstat(fd):
        info = real(fd)
        return os.stat_result((info.st_mode, info.st_ino, info.st_dev, info.st_nlink, info.st_uid, info.st_gid,
                               size, int(info.st_atime), int(info.st_mtime), int(info.st_ctime)))
    return fstat


def test_a_file_growing_past_the_hashing_limits_is_skipped(tmp_path, monkeypatch):
    target = tmp_path / "growing.log"
    target.write_bytes(b"x" * 300)
    monkeypatch.setattr(ev.os, "fstat", _claims(5))
    for size_limit, total, reason in ((50, 1000, "too large"), (1000, 40, "hashing budget reached")):
        budget = ev._Budget(total)
        fd = os.open(target, os.O_RDONLY)
        try:
            assert ev._sha256_fd(fd, size_limit, budget) == (None, reason)
            assert os.lseek(fd, 0, os.SEEK_CUR) <= min(size_limit, total) + 1, "read stops at the allowance"
        finally:
            os.close(fd)
        assert 0 <= budget.left < total


def test_a_program_growing_past_the_copy_limit_is_not_copied_whole(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "proc/4242").mkdir(parents=True)
    (root / "proc/4242/exe").write_bytes(b"y" * 300)
    (tmp_path / "programs").mkdir()
    monkeypatch.setattr(ev, "MAX_COPY_FILE", 64)
    saved = ev.copy_programs([{"pid": 4242, "sha256": "a" * 64, "size": 10}], tmp_path / "programs", root=str(root))
    assert saved[0]["copied"] is False and "grew past" in saved[0]["reason"]
    assert (tmp_path / "programs" / f"{'a' * 64}.bin").stat().st_size <= 64


def test_recent_file_limits_hold_inside_one_flat_folder(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "tmp").mkdir(parents=True)
    for number in range(20):
        (root / f"tmp/drop-{number}").write_text("new")
    monkeypatch.setattr(ev, "MAX_RECENT_FILES", 3)
    found, gaps = ev.recent_files(str(root), hours=24)
    assert len(found) == 3 and gaps
    monkeypatch.setattr(ev, "MAX_RECENT_FILES", 5000)
    monkeypatch.setattr(ev, "MAX_WALK_ENTRIES", 7)
    found, gaps = ev.recent_files(str(root), hours=24)
    assert len(found) == 7 and gaps


def test_an_explicitly_requested_digest_is_sent_below_the_alert_minimum(tmp_path, bundle_dir, no_reports, monkeypatch,
                                                                         capsys):
    from megalodon import alerts
    from megalodon.cli import main
    sent, made = [], []

    def dispatcher_for(settings):
        if not settings.enabled:
            return None
        made.append(alerts.AlertDispatcher(settings, transport=sent.append))
        return made[-1]
    monkeypatch.setattr(alerts, "dispatcher_for", dispatcher_for)
    config = tmp_path / "settings.toml"
    config.write_text('[alerts]\nenabled = true\nmin_severity = "HIGH"\n[[alerts.destination]]\nname = "siem"\n'
                      'kind = "syslog"\nhost = "127.0.0.1"\n', encoding="utf-8")
    with pytest.raises(SystemExit) as exit_:
        main(["evidence", "collect", "--output", str(bundle_dir), "--hours", "1", "--skip-program-verification",
              "--no-program-copies", "--alert", "--config", str(config)])
    assert exit_.value.code == 0
    made[0].close(timeout=5)
    digest = json.loads(capsys.readouterr().out)["manifest_sha256"]
    assert [item["rule_id"] for item in sent] == ["EVIDENCE_COLLECTED"] and sent[0]["digest"] == digest
    # What each transport actually sends at the default detail level carries the digest.
    destination = made[0].settings.destinations[0]
    assert digest in alerts.syslog_message(destination, sent[0]).decode()
    for kind in alerts.FORMATS:
        hook = alerts.AlertDestination(name="hook", kind="webhook", url_file="/unused", format=kind)
        assert digest in alerts.webhook_request(hook, "https://example.invalid", "", sent[0])[0].decode()
    config.write_text("[alerts]\nenabled = false\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exit_:
        main(["evidence", "collect", "--output", str(tmp_path / "second"), "--hours", "1",
              "--skip-program-verification", "--no-program-copies", "--alert", "--config", str(config)])
    assert exit_.value.code == 1 and "digest was not sent" in capsys.readouterr().err
    unseal(tmp_path / "second")


def test_a_folder_failing_mid_listing_is_a_gap_not_a_failed_collection(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "tmp").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "etc/new.conf").write_text("new")
    for number in range(3):
        (root / f"tmp/drop-{number}").write_text("new")
    real = os.scandir

    class Failing:
        def __init__(self, path):
            self.inner = real(path)
            self.given = 0

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.inner.close()

        def __iter__(self):
            return self

        def __next__(self):
            if self.given == 1:
                raise OSError(5, "Input/output error")
            self.given += 1
            return next(self.inner)

    monkeypatch.setattr(ev.os, "scandir", lambda path: Failing(path) if str(path).endswith("/tmp") else real(path))
    found, gaps = ev.recent_files(str(root), hours=24)
    paths = {f["path"] for f in found}
    assert "/etc/new.conf" in paths and len(paths & {f"/tmp/drop-{n}" for n in range(3)}) == 1
    assert gaps == ["/tmp could not be read whole"]
