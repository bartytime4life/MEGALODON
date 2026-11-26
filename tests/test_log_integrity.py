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


def big_log(folder, lines=60000):
    """A log of several 1 MiB pieces, recorded as the baseline's only log."""
    text = "".join(f"Nov 18 08:{i // 3600 % 60:02d}:{i % 60:02d} host sshd[{i}]: session entry {i:06d}\n"
                   for i in range(lines))
    (folder / "auth.log").write_text(text, encoding="utf-8")
    return text


def test_one_line_removed_from_the_middle_of_a_growing_log_is_found(logs):
    folder, options, manifest = logs
    text = big_log(folder)
    li.accept(manifest, **options)
    record = json.loads(manifest.read_text())["logs"]["/var/log/auth.log"]
    assert record["piece_bytes"] == 1 << 20 and len(record["pieces"]) == 4
    removed = "host sshd[50000]: session entry 050000\n"
    at = text.index(removed)
    assert 3 << 20 > at > 2 << 20
    start = text.rindex("\n", 0, at) + 1
    edited = text[:start] + text[at + len(removed):]  # The whole line, timestamp and all.
    assert len(edited) < len(text)
    with open(folder / "auth.log", "w", encoding="utf-8") as out:
        out.write(edited + "Nov 18 09:00:00 host sshd[1]: later entry\n" * 2000)  # It kept growing.
    assert (folder / "auth.log").stat().st_size > len(text)
    found, report = rules(manifest, options)
    assert found == {("LOG_REWRITTEN", "/var/log/auth.log")}
    assert report["findings"][0]["detail"]["changed_from_byte"] == 2 << 20, "the piece that changed is named"


@pytest.mark.parametrize("style", ["rename", "gzip"])
def test_a_log_edited_and_then_rotated_is_not_a_rotation(logs, style):
    folder, options, manifest = logs
    log = folder / "auth.log"
    log.write_text(LINES.replace("entry 120\n", "entry 121\n"), encoding="utf-8")  # Same size, one record changed.
    if style == "rename":
        log.rename(folder / "auth.log.1")
        log.write_text("Nov 18 09:00:00 host service[1]: new file\n", encoding="utf-8")
    else:
        with open(log, "rb") as source, gzip.open(folder / "auth.log.1.gz", "wb") as target:
            shutil.copyfileobj(source, target)
        log.unlink()
    found, report = rules(manifest, options)
    assert report["rotated"] == []
    if style == "rename":
        assert found == {("LOG_REWRITTEN", "/var/log/auth.log")}
        assert report["findings"][0]["detail"]["rotated_to"] == "auth.log.1"
    else:
        assert found == {("LOG_DELETED", "/var/log/auth.log")}


def test_advance_follows_rotation_and_covers_what_was_written_since(logs):
    folder, options, manifest = logs
    log = folder / "auth.log"
    log.rename(folder / "auth.log.1")
    log.write_text("Nov 18 09:00:00 host service[1]: new file\n" * 50, encoding="utf-8")
    report = li.check(manifest, advance=True, **options)
    assert report["findings"] == [] and report["rotated"][0]["rotated_to"] == "auth.log.1"
    assert "/var/log/auth.log" in report["advanced"]
    (folder / "auth.log.1").unlink()  # logrotate deletes its oldest copy.
    assert rules(manifest, options)[0] == set(), "the deleted copy was already let go"
    with open(log, "a", encoding="utf-8") as out:
        out.write("Nov 18 09:05:00 host sshd[2]: written after the baseline\n")
    li.check(manifest, advance=True, **options)
    log.write_text("Nov 18 09:00:00 host service[1]: new file\n" * 50
                   + "Nov 18 09:06:00 host sshd[3]: an unrelated, later and longer entry\n", encoding="utf-8")
    found, _ = rules(manifest, options)
    assert found == {("LOG_REWRITTEN", "/var/log/auth.log")}, "a line written after the baseline was removed"


def test_advance_keeps_the_record_of_a_log_with_a_finding(logs):
    folder, options, manifest = logs
    os.truncate(folder / "auth.log", 100)
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    first = li.check(manifest, advance=True, **options)
    assert {f["rule_id"] for f in first["findings"]} == {"LOG_TRUNCATED"}
    assert "/var/log/auth.log" not in first["advanced"] and "/var/log/syslog" in first["advanced"]
    stored = json.loads(li.progress_path(manifest).read_text())["logs"]
    assert stored["/var/log/auth.log"]["size"] == len(LINES)
    assert stored["/var/log/syslog"]["size"] > len(LINES)
    again = li.check(manifest, advance=True, **options)
    assert {(f["rule_id"], f["log"]) for f in again["findings"]} == {("LOG_TRUNCATED", "/var/log/auth.log")}
    assert len(again["findings"]) == 1, "found against the progress and the baseline, reported once"
    assert li.progress_path(manifest).stat().st_mode & 0o777 == 0o600


def test_without_advance_check_writes_nothing(logs):
    folder, options, manifest = logs
    before = manifest.read_bytes()
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    assert "advanced" not in li.check(manifest, **options)
    assert manifest.read_bytes() == before and not li.progress_path(manifest).exists()


def test_an_unreadable_log_is_reported_and_keeps_its_record_when_advancing(logs, monkeypatch):
    folder, options, manifest = logs
    real = li._identity
    monkeypatch.setattr(li, "_identity", lambda path, tries=3: "unreadable" if path.endswith("syslog")
                        else real(path, tries))
    report = li.check(manifest, advance=True, **options)
    monkeypatch.setattr(li, "_identity", real)
    assert "/var/log/syslog" in report["gaps"] and "/var/log/syslog" not in report["advanced"]
    assert "/var/log/syslog" in json.loads(li.progress_path(manifest).read_text())["logs"]


def test_a_baseline_from_before_whole_content_digests_still_works(logs):
    folder, options, manifest = logs
    old = json.loads(manifest.read_text())
    for record in old["logs"].values():
        record.pop("pieces", None), record.pop("piece_bytes", None)
    manifest.write_text(json.dumps(old))
    log = folder / "auth.log"
    log.write_text(LINES.replace("entry 120\n", "entry 121\n"), encoding="utf-8")
    assert rules(manifest, options)[0] == set(), "only the first bytes were recorded"
    data = bytearray(log.read_bytes())
    data[16:22] = b"XXXXXX"
    log.write_bytes(bytes(data))
    found, report = rules(manifest, options)
    assert found == {("LOG_REWRITTEN", "/var/log/auth.log")}
    assert report["findings"][0]["detail"]["changed_from_byte"] == 0


def test_pieces_grow_so_a_large_log_keeps_a_small_record():
    assert li._piece_size(0) == li._piece_size(5) == 1 << 20
    assert li._piece_size(128 << 20) == 1 << 20
    assert li._piece_size((128 << 20) + 1) == 2 << 20
    for size in (1, 200 << 20, 5 << 30):
        assert -(-size // li._piece_size(size)) <= li.MAX_PIECES


def test_in_place_logs_get_no_content_digests(logs):
    _, _, manifest = logs
    stored = json.loads(manifest.read_text())["logs"]
    assert "pieces" not in stored["/var/log/lastlog"] and "pieces" in stored["/var/log/wtmp"]


def test_a_log_cut_short_while_it_is_read_is_read_again(logs, monkeypatch):
    folder, _, _ = logs
    real, calls = li._pieces, []

    def short_once(stream, size, piece):
        calls.append(size)
        return None if len(calls) == 1 else real(stream, size, piece)
    monkeypatch.setattr(li, "_pieces", short_once)
    found = li._identity(str(folder / "auth.log"))
    assert len(calls) == 2 and found["pieces"] == real(open(folder / "auth.log", "rb"), len(LINES), 1 << 20)
    monkeypatch.setattr(li, "_pieces", lambda *a: None)
    assert li._identity(str(folder / "auth.log")) == "unreadable"


def test_cli_advance_and_the_schedule_uses_it(logs, monkeypatch, capsys):
    folder, options, manifest = logs
    real_check = li.check
    monkeypatch.setattr(li, "check", lambda m, **kw: real_check(m, **{**kw, **options}))
    from megalodon.cli import main
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    with pytest.raises(SystemExit) as exit_:
        main(["logwatch", "check", "--advance", "--manifest", str(manifest)])
    assert exit_.value.code == 0 and "/var/log/syslog" in json.loads(capsys.readouterr().out)["advanced"]
    assert json.loads(li.progress_path(manifest).read_text())["logs"]["/var/log/syslog"]["size"] > len(LINES)
    from megalodon import schedule
    job = next(job for job in schedule.JOBS if job.name == "logwatch")
    assert job.command == ("logwatch", "check", "--alert", "--advance")


@pytest.mark.parametrize("damage", [dict(piece_bytes=0), dict(piece_bytes="1"), dict(pieces=[]), dict(pieces="x"),
                                    dict(size=-1)])
def test_a_damaged_record_is_reported_not_looped_on(logs, damage):
    folder, options, manifest = logs
    stored = json.loads(manifest.read_text())
    stored["logs"]["/var/log/auth.log"].update(damage)
    manifest.write_text(json.dumps(stored))
    found, report = rules(manifest, options)
    assert ("LOG_REWRITTEN", "/var/log/auth.log") in found or ("LOG_TRUNCATED", "/var/log/auth.log") in found


def test_an_unreadable_log_explained_by_a_rotated_copy_keeps_its_record(logs, monkeypatch):
    folder, options, manifest = logs
    shutil.copy(folder / "auth.log", folder / "auth.log.1")  # A copy that holds the recorded content.
    real = li._identity
    monkeypatch.setattr(li, "_identity", lambda path, tries=3: "unreadable" if path.endswith("/auth.log")
                        else real(path, tries))
    report = li.check(manifest, advance=True, **options)
    assert report["findings"] == [] and "/var/log/auth.log" in report["gaps"]
    assert "/var/log/auth.log" not in report["advanced"]
    monkeypatch.setattr(li, "_identity", real)
    assert "/var/log/auth.log" in json.loads(manifest.read_text())["logs"], "the record is kept to compare later"
    (folder / "auth.log").write_text(LINES.replace("entry 120\n", "entry 121\n"), encoding="utf-8")
    (folder / "auth.log.1").unlink()
    found, _ = rules(manifest, options)
    assert found == {("LOG_REWRITTEN", "/var/log/auth.log")}, "an edit made while it was unreadable is found"


def test_advance_leaves_the_reviewed_baseline_alone(logs):
    # The scheduled check advances every 15 minutes; the tamper check watches the baseline, which changes only at
    # baseline and accept.
    folder, options, manifest = logs
    before = manifest.read_bytes()
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    report = li.check(manifest, advance=True, **options)
    assert "/var/log/syslog" in report["advanced"] and manifest.read_bytes() == before
    assert report["compared_with"] == str(manifest)
    progress = li.progress_path(manifest)
    assert progress.name == "logs-progress.json" and progress.stat().st_mode & 0o777 == 0o600
    assert li.progress_path(li.DEFAULT_MANIFEST).name == "log-integrity-progress.json"
    # The next check compares with what the last one recorded: an appended line is not compared again.
    again = li.check(manifest, **options)
    assert again["compared_with"] == str(progress) and again["findings"] == []


@pytest.mark.parametrize("step", ["accept", "baseline"])
def test_accept_and_a_new_baseline_record_the_logs_and_start_again(logs, step):
    folder, options, manifest = logs
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    li.check(manifest, advance=True, **options)
    if step == "accept":
        li.accept(manifest, **options)
    else:
        li.baseline(manifest, replace=True, **options)
    assert not li.progress_path(manifest).exists()
    assert json.loads(manifest.read_text())["logs"]["/var/log/syslog"]["size"] > len(LINES)


def test_a_progress_file_must_be_private_too(logs):
    folder, options, manifest = logs
    li.check(manifest, advance=True, **options)
    os.chmod(li.progress_path(manifest), 0o644)
    with pytest.raises(li.LogIntegrityError, match="mode-600"):
        li.check(manifest, **options)


def test_the_tamper_check_stays_quiet_while_the_log_check_advances(logs, tmp_path):
    from megalodon import tamper
    folder, options, _ = logs
    config = tmp_path / "config"
    manifest = config / "log-integrity.json"          # the name the tamper check watches
    li.baseline(manifest, **options)
    units, recorded = tmp_path / "units", tmp_path / "tamper.json"
    units.mkdir()
    tamper.baseline(recorded, config_dir=config, unit_dir=units, system=False)
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    li.check(manifest, advance=True, **options)
    li.check(manifest, advance=True, **options)
    assert tamper.check(recorded, runner=lambda *a: None)["findings"] == []
    li.accept(manifest, **options)                       # a reviewed change to the baseline is still seen
    assert [f["rule_id"] for f in tamper.check(recorded, runner=lambda *a: None)["findings"]] == ["BASELINE_CHANGED"]


def _forge_progress(manifest, options):
    """What an intruder able to write the sensor's files could do: record the logs as they are now as progress."""
    li._write(li.progress_path(manifest), dict(schema=li.SCHEMA, recorded_at="2026-11-26T00:00:00Z",
                                                **li.snapshot(**options)))


@pytest.mark.parametrize("damage", ["truncate", "empty", "rewrite"])
def test_progress_cannot_hide_damage_to_a_log_the_reviewed_baseline_recorded(logs, damage):
    # The tamper check watches the reviewed baseline, not the progress file, so the baseline is the floor: a log
    # that is still the same file as at the baseline can only have grown since, whatever the progress says.
    folder, options, manifest = logs
    li.check(manifest, advance=True, **options)
    log = folder / "auth.log"
    if damage == "truncate":
        os.truncate(log, 100)
    elif damage == "empty":
        os.truncate(log, 0)
    else:
        with open(log, "r+", encoding="utf-8") as out:
            out.seek(200)
            out.write("X" * 40)
    _forge_progress(manifest, options)
    report = li.check(manifest, advance=True, **options)
    found = {(f["rule_id"], f["log"]) for f in report["findings"]}
    assert found == {("LOG_REWRITTEN" if damage == "rewrite" else "LOG_TRUNCATED", "/var/log/auth.log")}
    assert report["findings"][0]["detail"]["compared_with"] == "the reviewed baseline"
    again = li.check(manifest, advance=True, **options)
    assert {(f["rule_id"], f["log"]) for f in again["findings"]} == found, "reported until accept"


def test_the_floor_is_quiet_for_normal_growth_and_rotation(logs):
    folder, options, manifest = logs
    with open(folder / "syslog", "a", encoding="utf-8") as out:
        out.write("Nov 18 09:00:00 host service[1]: later entry\n")
    log = folder / "auth.log"
    log.rename(folder / "auth.log.1")
    log.write_text("Nov 18 09:00:00 host service[1]: new file\n" * 50, encoding="utf-8")
    assert li.check(manifest, advance=True, **options)["findings"] == []
    (folder / "auth.log.1").unlink()
    with open(log, "a", encoding="utf-8") as out:
        out.write("Nov 18 09:05:00 host sshd[2]: later\n")
    assert li.check(manifest, advance=True, **options)["findings"] == []
    assert li.check(manifest, advance=True, **options)["findings"] == []


def test_a_copytruncate_log_is_reported_once_no_copy_holds_the_reviewed_content(logs):
    # Copied and emptied in place, the log stays the same file, so the reviewed baseline still speaks for it: once
    # the rotated copies holding what it recorded are gone, the change is reported until accept.
    folder, options, manifest = logs
    log = folder / "auth.log"
    shutil.copy(log, folder / "auth.log.1")
    os.truncate(log, 0)
    log.write_text("Nov 18 09:00:00 host service[1]: after rotation\n", encoding="utf-8")
    assert li.check(manifest, advance=True, **options)["findings"] == []
    (folder / "auth.log.1").unlink()
    report = li.check(manifest, advance=True, **options)
    assert {(f["rule_id"], f["log"]) for f in report["findings"]} == {("LOG_TRUNCATED", "/var/log/auth.log")}
    assert "copytruncate" in report["findings"][0]["detail"]["note"], "the finding says what to do"
    li.accept(manifest, **options)
    assert li.check(manifest, advance=True, **options)["findings"] == []
