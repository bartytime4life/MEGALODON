"""Log integrity: rotation stays quiet; deletion, truncation, rewriting, replacement and permissions are found."""
from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
import shutil

import pytest

from megalodon import log_integrity as li

LINES = "".join(f"Nov 18 08:{i // 60:02d}:{i % 60:02d} host service[1]: entry {i}\n" for i in range(200))


@pytest.fixture
def logs(tmp_path):
    root = tmp_path / "root"
    folder = root / "var/log"
    folder.mkdir(parents=True)
    for name in ("auth.log", "syslog"):
        (folder / name).write_text(LINES, encoding="utf-8")
    (folder / "wtmp").write_bytes(b"\x07\x00\x00\x00" + b"\x01" * 380)
    (folder / "lastlog").write_bytes(b"\x00" * 584)
    options = dict(root=str(root))
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, **options)
    return folder, options, manifest


def rules(manifest, options):
    report = li.check(manifest, **options)
    return {(f["rule_id"], f["log"]) for f in report["findings"]}, report


def test_unchanged_and_appended_logs_are_quiet(logs):
    folder, options, manifest = logs
    with open(folder / "auth.log", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    with open(folder / "wtmp", "ab") as out:
        out.write(b"\x08\x00\x00\x00" + b"\x02" * 380)
    (folder / "lastlog").write_bytes(b"\x01" * 584)  # Updated in place by design.
    found, report = rules(manifest, options)
    assert found == set() and report["rotated"] == []


@pytest.mark.parametrize("style", ["rename", "copytruncate", "gzip", "dateext"])
def test_normal_rotation_is_recognized(logs, style):
    folder, options, manifest = logs
    log = folder / "auth.log"
    if style == "rename":
        log.rename(folder / "auth.log.1")
        log.write_text("Nov 18 09:00:00 host service[1]: new file\n", encoding="utf-8")
    elif style == "copytruncate":
        shutil.copy(log, folder / "auth.log.1")
        os.truncate(log, 0)
    elif style == "gzip":
        with open(log, "rb") as source, gzip.open(folder / "auth.log.1.gz", "wb") as target:
            shutil.copyfileobj(source, target)
        log.unlink()
    else:
        log.rename(folder / "auth.log-20261118")
    found, report = rules(manifest, options)
    assert found == set()
    assert [item["log"] for item in report["rotated"]] == ["/var/log/auth.log"]


def test_wiping_logs_is_found(logs):
    folder, options, manifest = logs
    os.truncate(folder / "auth.log", 100)
    (folder / "syslog").unlink()
    os.truncate(folder / "wtmp", 0)
    found, _ = rules(manifest, options)
    assert found == {("LOG_TRUNCATED", "/var/log/auth.log"), ("LOG_DELETED", "/var/log/syslog"),
                     ("LOG_TRUNCATED", "/var/log/wtmp")}


def test_rewriting_or_replacing_a_log_is_found(logs):
    folder, options, manifest = logs
    data = bytearray((folder / "auth.log").read_bytes())
    data[16:22] = b"XXXXXX"  # Same size, different beginning.
    (folder / "auth.log").write_bytes(bytes(data))
    (folder / "syslog").unlink()
    (folder / "syslog").write_text("Nov 18 09:00:00 host service[1]: unrelated\n" * 300, encoding="utf-8")
    found, _ = rules(manifest, options)
    assert ("LOG_REWRITTEN", "/var/log/auth.log") in found
    # A recreated file can reuse the old inode number; it is then reported as rewritten instead.
    assert found & {("LOG_REPLACED", "/var/log/syslog"), ("LOG_REWRITTEN", "/var/log/syslog")}
    assert len(found) == 2


def test_permission_and_owner_changes_are_found(logs):
    folder, options, manifest = logs
    (folder / "auth.log").chmod(0o666)
    found, report = rules(manifest, options)
    assert found == {("LOG_PERMISSIONS", "/var/log/auth.log")}
    assert report["findings"][0]["detail"]["mode"][1] == "0o666"


def test_accept_and_baseline_safety(logs, tmp_path):
    folder, options, manifest = logs
    os.truncate(folder / "auth.log", 0)
    assert rules(manifest, options)[0]
    li.accept(manifest, **options)
    assert rules(manifest, options)[0] == set()
    with pytest.raises(li.LogIntegrityError, match="exists"):
        li.baseline(manifest, **options)
    manifest.chmod(0o644)
    with pytest.raises(li.LogIntegrityError, match="mode-600"):
        li.check(manifest, **options)
    with pytest.raises(li.LogIntegrityError, match="no log baseline"):
        li.check(tmp_path / "missing.json", **options)


def test_cli_exit_codes(logs, monkeypatch, capsys):
    folder, options, manifest = logs
    real = li.snapshot
    monkeypatch.setattr(li, "snapshot", lambda **kw: real(**options))
    real_check = li.check
    monkeypatch.setattr(li, "check", lambda m, **kw: real_check(m, **options))
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("logwatch", "check", "--manifest", str(manifest)) == 0
    os.truncate(folder / "syslog", 10)
    capsys.readouterr()
    assert code("logwatch", "check", "--manifest", str(manifest)) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "LOG_TRUNCATED"
    assert code("logwatch", "check", "--manifest", str(Path(manifest).with_name("none.json"))) == 2


@pytest.mark.parametrize("replacement", [True, False])
def test_a_rotated_copy_that_was_emptied_is_truncation(logs, replacement):
    folder, options, manifest = logs
    log = folder / "auth.log"
    log.rename(folder / "auth.log.1")
    if replacement:
        log.write_text("", encoding="utf-8")
    os.truncate(folder / "auth.log.1", 0)
    found, report = rules(manifest, options)
    assert found == {("LOG_TRUNCATED", "/var/log/auth.log")} and report["rotated"] == []
    detail = report["findings"][0]["detail"]
    assert detail["rotated_to"] == "auth.log.1" and detail["size"] == 0


def test_copytruncate_then_regrowth_past_the_recorded_size_is_rotation(logs):
    folder, options, manifest = logs
    log = folder / "auth.log"
    shutil.copy(log, folder / "auth.log.1")
    os.truncate(log, 0)
    later = "".join(f"Nov 18 10:{i // 60:02d}:{i % 60:02d} host service[1]: later entry {i}\n" for i in range(300))
    with open(log, "a", encoding="utf-8") as out:
        out.write(later)
    assert log.stat().st_size > len(LINES)
    found, report = rules(manifest, options)
    assert found == set() and report["rotated"] == [dict(log="/var/log/auth.log", rotated_to="auth.log.1")]
    os.truncate(folder / "auth.log.1", 1000)
    found, _ = rules(manifest, options)
    assert found == {("LOG_REWRITTEN", "/var/log/auth.log")}, "a cut-down copy no longer explains the change"
