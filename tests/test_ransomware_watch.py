"""Ransomware watch: classification, detection logic, real inotify, suspects and CLI."""
from __future__ import annotations

from datetime import datetime, timezone
import gzip
import json
import os
from pathlib import Path
import sys
from threading import Event, Thread
import time

import pytest

from megalodon import alerts
from megalodon import ransomware_watch as rw
from megalodon.ransomware_watch import RansomwareDetector, classify, classify_bytes, entropy

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify is Linux-only")
TEXT = b"Quarterly report and meeting notes.\n" * 200


def write(path, data):
    Path(path).write_bytes(data)
    return str(path)


# ------------------------------------------------------------- classification

def test_formats_text_and_encrypted_bytes_are_told_apart():
    random = os.urandom(65536)
    assert entropy(random) > 7.9 and entropy(TEXT) < 5
    for header in (b"%PDF-1.7", b"PK\x03\x04", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff\xe0", b"\x1f\x8b\x08",
                   b"SQLite format 3\x00", b"7z\xbc\xaf\x27\x1c", b"\x7fELF"):
        assert classify_bytes(header + random[:8000]) == "known", header
    assert classify_bytes(b"\x00" * 100 + random[:8000][100:]) == "encrypted"
    assert classify_bytes(TEXT) == "text" and classify_bytes("Grüße, 日本語 notes\n".encode() * 200) == "text"
    assert classify_bytes(random[:500]) == "small"
    assert classify_bytes(bytes(range(256)) * 4 + b"\x00\x01" * 2000) == "opaque"


def test_classify_never_follows_links_or_blocks_on_fifos(tmp_path):
    target = write(tmp_path / "doc.pdf", b"%PDF-1.7" + os.urandom(4000))
    os.symlink(target, tmp_path / "link.pdf")
    os.mkfifo(tmp_path / "pipe")
    started = time.monotonic()
    assert classify(tmp_path / "link.pdf") is None and classify(tmp_path / "pipe") is None
    assert time.monotonic() - started < 2 and classify(target) == "known"


def test_ransom_note_names():
    for name in ("_readme.txt", "HOW_TO_DECRYPT.txt", "!!!READ_ME_TO_DECRYPT!!!.txt", "How-To-Restore-Files.html",
                 "DECRYPT-FILES.html", "YOUR_FILES_ARE_ENCRYPTED.txt", "restore_my_files.hta"):
        assert rw._NOTE.match(name), name
    for name in ("README.txt", "readme.md", "README_FIRST.txt", "notes.txt", "restore.sh", "recovery-plan.txt",
                 "howto-install.txt", "restore_notes.txt"):
        assert not rw._NOTE.match(name), name


# ------------------------------------------------------------- detection logic

class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def detector(**kwargs):
    clock = Clock()
    return RansomwareDetector(clock=clock, wallclock=lambda: datetime(2026, 11, 18, tzinfo=timezone.utc),
                              **{"min_files": 5, **kwargs}), clock


def test_in_place_encryption_of_recognized_files_is_critical(tmp_path):
    d, clock = detector()
    paths = [write(tmp_path / f"f{i}.docx", b"PK\x03\x04" + os.urandom(8000)) for i in range(6)]
    d.seed([tmp_path])
    found = []
    for path in paths:
        write(path, os.urandom(8000))
        found += d.written(path)
        clock.now += 1
    assert [f.rule_id for f in found] == ["RANSOMWARE_ENCRYPTION"]
    assert found[0].severity == "CRITICAL" and found[0].evidence["files"] == 5
    assert found[0].to_dict()["attack"] == ["T1486"]
    write(paths[0], os.urandom(8000))
    assert d.written(paths[0]) == [], "one finding per cooldown"


def test_encrypted_copy_next_to_a_deleted_original_counts(tmp_path):
    d, clock = detector()
    found = []
    for i in range(5):
        original = write(tmp_path / f"photo{i}.jpg", b"\xff\xd8\xff\xe0" + os.urandom(8000))
        d.seed([tmp_path])
        os.unlink(original)
        d.deleted(original)
        # Renamed extensions, swapped extensions and the same name all count as replacing the original.
        name = (f"photo{i}.jpg.id-1234", f"photo{i}.crypted", f"photo{i}.jpg")[i % 3]
        found += d.written(write(tmp_path / name, os.urandom(8000)))
    assert [f.rule_id for f in found] == ["RANSOMWARE_ENCRYPTION"]


def test_everyday_activity_stays_quiet(tmp_path):
    d, clock = detector(min_files=3)
    d.seed([tmp_path])
    found = []
    for i in range(30):
        found += d.written(write(tmp_path / f"backup{i}.gz", gzip.compress(TEXT * (i + 1))))
        found += d.written(write(tmp_path / f"photo{i}.png", b"\x89PNG\r\n\x1a\n" + os.urandom(8000)))
        found += d.written(write(tmp_path / f"notes{i}.txt", TEXT))
        found += d.written(write(tmp_path / f"README{i}.txt", TEXT))
    assert found == []


def test_unrelated_encrypted_files_only_raise_the_milder_mass_write(tmp_path):
    d, clock = detector(min_files=3)
    found = []
    for i in range(9):
        found += d.written(write(tmp_path / f"blob{i}.bin", os.urandom(8000)))
    assert [f.rule_id for f in found] == ["RANSOMWARE_MASS_WRITE"] and found[0].severity == "HIGH"


def test_the_window_forgets_old_rewrites(tmp_path):
    d, clock = detector(window_seconds=10)
    paths = [write(tmp_path / f"f{i}.pdf", b"%PDF-1.7" + os.urandom(8000)) for i in range(6)]
    d.seed([tmp_path])
    found = []
    for path in paths:
        write(path, os.urandom(8000))
        found += d.written(path)
        clock.now += 11
    assert found == []


def test_a_ransom_note_is_flagged_once_per_name(tmp_path):
    d, _ = detector()
    first = d.written(write(tmp_path / "HOW_TO_DECRYPT.txt", b"pay"))
    second = d.written(write(tmp_path / "HOW_TO_DECRYPT.txt", b"pay"))
    assert [f.rule_id for f in first] == ["RANSOM_NOTE"] and second == []


def test_bounds_are_validated():
    for bad in (dict(min_files=1), dict(window_seconds=4), dict(window_seconds=7200)):
        with pytest.raises(ValueError):
            RansomwareDetector(**bad)
    d = RansomwareDetector(max_baseline=3)
    for i in range(10):
        d.remember(f"/x/{i}", "known")
    assert list(d.baseline) == ["/x/7", "/x/8", "/x/9"]


# ------------------------------------------------------------- real inotify

@linux
def test_real_watch_catches_encryption_in_new_and_existing_folders(tmp_path):
    (tmp_path / "old").mkdir()
    for i in range(3):
        write(tmp_path / "old" / f"a{i}.txt", TEXT)
    d = RansomwareDetector(min_files=5, window_seconds=60)
    d.seed([tmp_path])
    found = []
    watcher = rw.Watcher([tmp_path], d, found.append, suspects_fn=lambda roots: [{"pid": 1}])
    stop = Event()
    thread = Thread(target=watcher.run, args=(stop,), kwargs=dict(poll=0.05), daemon=True)
    thread.start()
    try:
        (tmp_path / "new").mkdir()
        time.sleep(0.3)  # The watcher adds the new folder.
        for i in range(3):
            path = tmp_path / "old" / f"a{i}.txt"
            write(str(path) + ".locked", os.urandom(8000))
            path.unlink()
        for i in range(3):
            original = write(tmp_path / "new" / f"b{i}.pdf", b"%PDF-1.7" + os.urandom(8000))
            time.sleep(0.05)
            os.rename(original, original + ".enc")
            write(original + ".enc", os.urandom(8000))
        deadline = time.monotonic() + 5
        while not found and time.monotonic() < deadline:
            time.sleep(0.05)
    finally:
        stop.set()
        thread.join(2)
        watcher.close()
    assert [f.rule_id for f in found] == ["RANSOMWARE_ENCRYPTION"]
    assert found[0].evidence["processes"] == [{"pid": 1}]


@linux
def test_selftest_and_cli(tmp_path, capsys):
    rules = {f.rule_id for f in rw.selftest(str(tmp_path / "s"))}
    assert rules == {"RANSOMWARE_ENCRYPTION", "RANSOM_NOTE"}
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("ransomware", "selftest") == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert code("ransomware", "watch", "--dir", str(tmp_path / "missing"), "--config",
                str(tmp_path / "none.toml")) == 2


def test_suspects_names_a_process_holding_watched_files(tmp_path):
    held = open(write(tmp_path / "victim.docx", b"x" * 10), "rb")
    try:
        found = rw.suspects([tmp_path])
    finally:
        held.close()
    mine = [item for item in found if item["pid"] == os.getpid()]
    assert mine and mine[0]["open_files"] >= 1 and mine[0]["program"]
    (tmp_path / "quiet").mkdir()
    assert all(item["pid"] != os.getpid() for item in rw.suspects([tmp_path / "quiet"]))


# ------------------------------------------------------------- alerts

def test_host_findings_reach_alerts_without_addresses():
    sent = []
    settings = alerts.AlertSettings(enabled=True, min_severity="HIGH", destinations=(
        alerts.AlertDestination(name="siem", kind="syslog", host="127.0.0.1"),))
    dispatcher = alerts.AlertDispatcher(settings, transport=sent.append)
    dispatcher.submit([alerts.HostNotice("RANSOMWARE_ENCRYPTION", "CRITICAL", datetime(2026, 11, 18, tzinfo=timezone.utc),
                                         "12 files encrypted", ("T1486",), "Files are being encrypted.")])
    dispatcher.close(timeout=5)
    assert sent and sent[0]["rule_id"] == "RANSOMWARE_ENCRYPTION" and sent[0]["attack"] == ["T1486"]
    assert "src_ip" not in sent[0]
    message = alerts.syslog_message(settings.destinations[0], sent[0]).decode()
    assert "RANSOMWARE_ENCRYPTION" in message and "src_ip" not in message and message.startswith("<130>1 ")
