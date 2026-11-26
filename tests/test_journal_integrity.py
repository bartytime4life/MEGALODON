"""Journal integrity: rotation, vacuuming and boot stay quiet; deleted, cut back and edited journal files are found."""
from __future__ import annotations

import json
import os
import struct
import uuid

import pytest

from megalodon import journal_integrity as ji
from megalodon import log_integrity as li

MACHINE = "02c0ff32d11f4f6ea20de4b2a2924cdc"
SEQUENCE = uuid.UUID(int=7).bytes
HEADER = 272


def journal(path, *, head, tail, entries=None, state=ji.STATE_OFFLINE, sequence=SEQUENCE, file_id=None,
            arena=4096, body=b"", sealed=False, since=1_700_000_000_000_000):
    """A journal file laid out as https://systemd.io/JOURNAL_FILE_FORMAT/ describes its header."""
    data = bytearray(HEADER)
    data[0:8] = b"LPKSHHRH"
    struct.pack_into("<II", data, 8, 1 if sealed else 0, 0)
    data[16] = state
    file_id = file_id or uuid.uuid4().bytes
    data[24:40] = file_id
    data[40:56] = bytes.fromhex(MACHINE)
    data[72:88] = sequence
    struct.pack_into("<QQ", data, 88, HEADER, arena)
    entries = tail - head + 1 if entries is None else entries
    struct.pack_into("<QQQ", data, 152, entries, tail, head)
    struct.pack_into("<QQ", data, 184, since + head, since + tail)  # Entry times, in microseconds.
    content = bytes(data) + (body or os.urandom(64)).ljust(arena, b"\0")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return file_id


def archive(folder, head, tail, sequence=SEQUENCE, since=1_700_000_000_000_000):
    """An archived file, named as journald names one at rotation."""
    name = f"system@{sequence.hex()}-{head:016x}-{since + head:016x}.journal"
    return journal(folder / name, head=head, tail=tail, state=ji.STATE_ARCHIVED, sequence=sequence, since=since)


@pytest.fixture
def machine(tmp_path):
    root = tmp_path / "root"
    folder = root / "var/log/journal" / MACHINE
    archive(folder, 1, 100)
    archive(folder, 101, 200)
    journal(folder / "system.journal", head=201, tail=250)
    journal(folder / "user-1000.journal", head=205, tail=240, entries=10)  # Shares the sequence, interleaved.
    boot = root / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True)
    boot.write_text("boot-one\n")
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, root=str(root))
    return root, folder, manifest


def check(manifest, root, **kw):
    report = li.check(manifest, root=str(root), **kw)
    return {(f["rule_id"], f["log"].rsplit("/", 1)[1]) for f in report["findings"]}, report


def grow(path, tail, entries=None):
    data = bytearray(path.read_bytes())
    old_entries, old_tail, head = struct.unpack_from("<QQQ", data, 152)
    struct.pack_into("<QQ", data, 152, entries if entries is not None else old_entries + tail - old_tail, tail)
    path.write_bytes(bytes(data))


def test_the_header_is_read_as_the_format_lays_it_out(machine):
    root, folder, manifest = machine
    stored = json.loads(manifest.read_text())["journals"]["files"]
    active = next(r for r in stored.values() if r["path"].endswith("/system.journal"))
    assert (active["head"], active["tail"], active["n_entries"]) == (201, 250, 50)
    assert active["seqnum_id"] == SEQUENCE.hex() and active["state"] == ji.STATE_OFFLINE
    assert active["used"] == HEADER + 4096 and "sha256" not in active, "the file being written is not hashed"
    archived = [r for r in stored.values() if r["state"] == ji.STATE_ARCHIVED]
    assert len(archived) == 2 and all(len(r["sha256"]) == 64 for r in archived)
    real = (folder / "system.journal").read_bytes()[:ji.HEADER_READ]
    assert ji.header(real)["head"] == 201
    assert ji.header(b"NOTAJRNL" + real[8:]) is None, "the signature is checked"
    assert ji.header(real[:100]) is None, "a short header is not read"


def test_writing_rotation_vacuuming_and_flushing_stay_quiet(machine):
    root, folder, manifest = machine
    grow(folder / "system.journal", 260)
    assert check(manifest, root)[0] == set()
    # Rotation: the active file is archived under a new name, and a new one started.
    (folder / "system.journal").rename(folder / f"system@{SEQUENCE.hex()}-{201:016x}-0.journal")
    data = bytearray((folder / f"system@{SEQUENCE.hex()}-{201:016x}-0.journal").read_bytes())
    data[16] = ji.STATE_ARCHIVED
    (folder / f"system@{SEQUENCE.hex()}-{201:016x}-0.journal").write_bytes(bytes(data))
    journal(folder / "system.journal", head=261, tail=270)
    # Vacuuming: the oldest archive goes.
    next(folder.glob(f"system@*-{1:016x}-*.journal")).unlink()
    found, report = check(manifest, root, advance=True)
    assert found == set()
    assert [item["reason"] for item in report["journals"]["explained"]] == ["vacuumed (oldest first)"]
    assert check(manifest, root)[0] == set(), "the advanced record follows the rotation"


def test_a_deleted_archive_from_the_middle_is_found(machine):
    root, folder, manifest = machine
    next(folder.glob(f"system@*-{101:016x}-*.journal")).unlink()
    found, report = check(manifest, root)
    assert {rule for rule, _ in found} == {"JOURNAL_FILE_DELETED"}
    assert report["findings"][0]["detail"] == dict(entries=100, first=101, last=200, archived=True)


def test_a_deleted_active_journal_is_found_even_when_it_starts_again(machine):
    root, folder, manifest = machine
    for path in folder.iterdir():
        path.unlink()
    journal(folder / "system.journal", head=1, tail=3, sequence=uuid.UUID(int=8).bytes,
            since=1_800_000_000_000_000)  # journald started afresh, later.
    found, report = check(manifest, root)
    assert found == {("JOURNAL_FILE_DELETED", "system.journal"), ("JOURNAL_FILE_DELETED", "user-1000.journal")}, \
        "journald never deletes the files it writes to"
    assert [item["reason"] for item in report["journals"]["explained"]] == ["vacuumed (oldest first)"] * 2


def test_entries_removed_from_a_file_are_found(machine):
    root, folder, manifest = machine
    grow(folder / "system.journal", 240, entries=40)
    grow(folder / "user-1000.journal", 240, entries=8)
    found, report = check(manifest, root)
    assert found == {("JOURNAL_ENTRIES_REMOVED", "system.journal"), ("JOURNAL_ENTRIES_REMOVED", "user-1000.journal")}
    detail = next(f["detail"] for f in report["findings"] if f["log"].endswith("/system.journal"))
    assert detail["why"] == ["last entry number went back", "fewer entries"]
    assert detail["entries"] == [50, 40] and detail["last"] == [250, 240]


def test_a_changed_first_entry_and_a_cut_file_are_found(machine):
    root, folder, manifest = machine
    data = bytearray((folder / "system.journal").read_bytes())
    struct.pack_into("<Q", data, 168, 211)  # The first ten entries are gone and the count rewritten.
    struct.pack_into("<Q", data, 152, 50)
    (folder / "system.journal").write_bytes(bytes(data))
    os.truncate(folder / "user-1000.journal", HEADER + 100)
    found, report = check(manifest, root)
    why = {f["log"].rsplit("/", 1)[1]: f["detail"]["why"] for f in report["findings"]}
    assert why == {"system.journal": ["first entry number changed"],
                   "user-1000.journal": ["file shorter than its header says"]}


def test_an_edited_archive_is_found_and_an_untouched_one_is_not_read_again(machine, monkeypatch):
    root, folder, manifest = machine
    old = next(folder.glob(f"system@*-{1:016x}-*.journal"))
    read = []
    real = ji._digest
    monkeypatch.setattr(ji, "_digest", lambda path: read.append(path) or real(path))
    assert check(manifest, root)[0] == set() and read == [], "unchanged archives keep their digest"
    data = bytearray(old.read_bytes())
    data[HEADER + 10] ^= 0xFF  # One byte of one record, same size, same header.
    old.write_bytes(bytes(data))
    found, report = check(manifest, root)
    assert found == {("JOURNAL_ARCHIVE_CHANGED", old.name)} and read == [str(old)]


def test_volatile_journals_cleared_at_boot_or_flushed_are_explained(tmp_path):
    root = tmp_path / "root"
    run = root / "run/log/journal" / MACHINE
    journal(run / "system.journal", head=1, tail=30)
    boot = root / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True)
    boot.write_text("boot-one\n")
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, root=str(root))
    (run / "system.journal").unlink()
    found, _ = check(manifest, root)
    assert found == {("JOURNAL_FILE_DELETED", "system.journal")}, "gone in the same boot, with nowhere it went"
    journal(root / "var/log/journal" / MACHINE / "system.journal", head=1, tail=20)
    assert check(manifest, root)[0] == {("JOURNAL_FILE_DELETED", "system.journal")}, "it ends before the lost one did"
    journal(root / "var/log/journal" / MACHINE / "system.journal", head=1, tail=45)
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "flushed to the persistent journal"
    (root / "var/log/journal" / MACHINE / "system.journal").unlink()
    boot.write_text("boot-two\n")
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "kept in memory, cleared at boot"


def test_an_older_sequence_that_was_all_archived_ages_out(tmp_path):
    root = tmp_path / "root"
    folder = root / "var/log/journal" / MACHINE
    archive(folder, 1, 50, sequence=uuid.UUID(int=1).bytes, since=1_600_000_000_000_000)  # Before a reinstall.
    archive(folder, 1, 80, sequence=SEQUENCE)
    journal(folder / "system.journal", head=81, tail=90)
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, root=str(root))
    next(folder.glob(f"system@{uuid.UUID(int=1).hex}-*.journal")).unlink()
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "vacuumed (oldest first)"


def test_vacuum_order_runs_by_time_across_sequences(tmp_path):
    root = tmp_path / "root"
    folder = root / "var/log/journal" / MACHINE
    older, newer = uuid.UUID(int=1).bytes, SEQUENCE
    journal(folder / "system@old.journal", head=1, tail=50, state=ji.STATE_ARCHIVED, sequence=older,
            since=1_600_000_000_000_000)  # Its entries are the oldest by time.
    archive(folder, 1, 80, sequence=newer)
    archive(folder, 81, 90, sequence=newer)
    journal(folder / "system.journal", head=91, tail=95, sequence=newer)
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, root=str(root))
    first_of_newer = next(folder.glob(f"system@{newer.hex()}-{1:016x}-*.journal"))
    first_of_newer.unlink()
    found, _ = check(manifest, root)
    assert found == {("JOURNAL_FILE_DELETED", first_of_newer.name)}, "an older sequence's archive is still there"
    (folder / "system@old.journal").unlink()
    found, report = check(manifest, root)
    assert found == set() and len(report["journals"]["explained"]) == 2, "both now go oldest first"


def test_an_empty_journal_that_goes_is_not_a_loss(machine):
    root, folder, manifest = machine
    journal(folder / "user-1001.journal", head=0, tail=250, entries=0)
    li.check(manifest, root=str(root), advance=True)
    (folder / "user-1001.journal").unlink()  # journald removes an empty file at rotation.
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "empty"


def test_vacuuming_is_judged_per_folder(machine):
    root, folder, manifest = machine
    other = root / "var/log/journal" / (MACHINE[:-1] + "0")  # Another machine's (or namespace's) journals.
    archive(other, 1, 10)
    li.check(manifest, root=str(root), advance=True)
    next(folder.glob(f"system@*-{1:016x}-*.journal")).unlink()
    found, report = check(manifest, root)
    assert found == set(), "the other folder's files do not change this folder's oldest"


def test_advance_keeps_the_record_of_a_journal_with_a_finding_or_unreadable(machine, monkeypatch):
    root, folder, manifest = machine
    grow(folder / "system.journal", 240, entries=40)
    li.check(manifest, root=str(root), advance=True)
    stored = json.loads(manifest.read_text())["journals"]["files"]
    assert next(r for r in stored.values() if r["path"].endswith("/system.journal"))["n_entries"] == 50
    assert check(manifest, root)[0] == {("JOURNAL_ENTRIES_REMOVED", "system.journal")}, "reported until accept"
    assert len(check(manifest, root)[1]["findings"]) == 1, "found against the progress and the baseline, once"
    real_open = os.open
    blocked = str(folder / "user-1000.journal")
    monkeypatch.setattr(os, "open", lambda path, *a, **k: (_ for _ in ()).throw(PermissionError(13, "denied"))
                        if str(path) == blocked else real_open(path, *a, **k))
    found, report = check(manifest, root, advance=True)
    assert "/var/log/journal/%s/user-1000.journal" % MACHINE in report["journals"]["gaps"]
    assert ("JOURNAL_FILE_DELETED", "user-1000.journal") not in found
    monkeypatch.setattr(os, "open", real_open)
    stored = json.loads(manifest.read_text())["journals"]["files"]
    assert any(r["path"].endswith("/user-1000.journal") for r in stored.values()), "kept to compare later"
    li.accept(manifest, root=str(root))
    assert check(manifest, root)[0] == set()


def test_a_baseline_without_journals_records_them_at_the_next_advance(machine):
    root, folder, manifest = machine
    stored = json.loads(manifest.read_text())
    stored.pop("journals")
    manifest.write_text(json.dumps(stored))
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["recorded"] is False
    li.check(manifest, root=str(root), advance=True)
    next(folder.glob(f"system@*-{101:016x}-*.journal")).unlink()
    assert {rule for rule, _ in check(manifest, root)[0]} == {"JOURNAL_FILE_DELETED"}


def test_corrupt_files_are_listed_and_hashed(machine):
    root, folder, manifest = machine
    (folder / "system.journal").rename(folder / "system@0000-0000.journal~")  # journald's name for a dirty file.
    journal(folder / "system.journal", head=251, tail=260)
    found, report = check(manifest, root, advance=True)
    assert found == set()
    assert report["journals"]["corrupt"] == ["/var/log/journal/%s/system@0000-0000.journal~" % MACHINE]
    stored = json.loads(li.progress_path(manifest).read_text())["journals"]["files"]
    assert len(next(r for r in stored.values() if r["dirty"])["sha256"]) == 64


def test_journal_findings_go_to_the_wiped_log_playbook():
    from megalodon import response_engine
    text = response_engine.DEFAULT_POLICY_TEXT
    playbook = text[text.index('name = "trojaned-program-or-wiped-log"'):]
    playbook = playbook[:playbook.index("actions")]
    for rule in ji.SEVERITY:
        assert f'"{rule}"' in playbook


def test_an_empty_journal_does_not_hide_vacuuming(machine):
    root, folder, manifest = machine
    journal(folder / "user-1001.journal", head=0, tail=250, entries=0)  # Created, nothing written to it yet.
    journal(folder / "system@0-0.journal~", head=0, tail=0, entries=0)  # An empty file set aside as damaged.
    li.check(manifest, root=str(root), advance=True)
    next(folder.glob(f"system@*-{1:016x}-*.journal")).unlink()
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "vacuumed (oldest first)"


def test_an_older_active_journal_does_not_block_vacuuming_archives(tmp_path):
    root = tmp_path / "root"
    folder = root / "var/log/journal" / MACHINE
    journal(folder / "user-1000.journal", head=1, tail=40, entries=5)  # Active since the sequence began.
    archive(folder, 10, 20)
    archive(folder, 21, 30)
    journal(folder / "system.journal", head=31, tail=40)
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, root=str(root))
    next(folder.glob(f"system@*-{10:016x}-*.journal")).unlink()  # Vacuuming acts on archived files only.
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "vacuumed (oldest first)"
    next(folder.glob(f"system@*-{21:016x}-*.journal")).unlink()  # The last archive; only active files are left.
    assert check(manifest, root)[0] == set()


def test_a_journal_that_grows_while_it_is_read_is_not_cut(machine, monkeypatch):
    root, folder, manifest = machine
    path = folder / "system.journal"
    real_lstat = os.lstat

    def lstat_then_grow(target, *args, **kwargs):
        info = real_lstat(target, *args, **kwargs)
        if str(target) == str(path):  # journald extends the file and its arena just after the size was read.
            data = bytearray(path.read_bytes())
            struct.pack_into("<Q", data, 96, 8192)
            path.write_bytes(bytes(data) + bytes(8192 + HEADER - len(data)))
        return info
    monkeypatch.setattr(os, "lstat", lstat_then_grow)
    found, _ = check(manifest, root)
    assert found == set(), "the size is read after the header, from the same open file"


def test_a_flush_must_cover_the_entries_of_the_lost_runtime_journal(tmp_path):
    root = tmp_path / "root"
    run = root / "run/log/journal" / MACHINE
    journal(run / "system.journal", head=1, tail=30)
    boot = root / "proc/sys/kernel/random/boot_id"
    boot.parent.mkdir(parents=True)
    boot.write_text("boot-one\n")
    manifest = tmp_path / "logs.json"
    li.baseline(manifest, root=str(root))
    (run / "system.journal").unlink()
    persistent = root / "var/log/journal" / MACHINE
    journal(persistent / "system.journal", head=100, tail=200)
    assert check(manifest, root)[0] == {("JOURNAL_FILE_DELETED", "system.journal")}, "none of 1-30 is there"
    archive(persistent, 1, 12)
    journal(persistent / "user-1000.journal", head=20, tail=99, entries=10)
    assert check(manifest, root)[0] == {("JOURNAL_FILE_DELETED", "system.journal")}, "13-19 are nowhere"
    archive(persistent, 13, 19)
    found, report = check(manifest, root)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "flushed to the persistent journal"


def test_vacuuming_that_takes_the_newest_records_is_reported(machine):
    root, folder, manifest = machine
    # journalctl --vacuum-time=2d rotates the active files first, then deletes only archives older than that:
    # the oldest go, and the files just rotated stay.
    next(folder.glob(f"system@*-{1:016x}-*.journal")).unlink()
    assert check(manifest, root)[0] == set()
    # A vacuum that also deletes what was being written at the last check removes the newest records: log wiping.
    rotated = folder / f"system@{SEQUENCE.hex()}-{201:016x}-0.journal"
    (folder / "system.journal").rename(rotated)
    data = bytearray(rotated.read_bytes())
    data[16] = ji.STATE_ARCHIVED
    rotated.write_bytes(bytes(data))
    journal(folder / "system.journal", head=251, tail=252)
    rotated.unlink()
    assert ("JOURNAL_FILE_DELETED", "system.journal") in check(manifest, root)[0]


def test_accept_reuses_the_digests_the_last_advancing_check_recorded(machine, monkeypatch):
    # A file archived since the baseline is hashed by the check that first sees it; accept does not read it again.
    root, folder, manifest = machine
    archive(folder, 251, 300)
    li.check(manifest, root=str(root), advance=True)
    monkeypatch.setattr(ji, "_digest", lambda path: pytest.fail(f"{path} was read again"))
    li.accept(manifest, root=str(root))
    assert not li.progress_path(manifest).exists()


@pytest.mark.parametrize("damage", ["entries", "archive"])
def test_progress_cannot_hide_damage_to_a_journal_file_the_review_recorded(machine, damage):
    # The progress file is not watched by the tamper check; rewriting it must not hide a cut-back journal.
    root, folder, manifest = machine
    li.check(manifest, root=str(root), advance=True)
    if damage == "entries":
        grow(folder / "system.journal", 240, entries=40)
        expected = ("JOURNAL_ENTRIES_REMOVED", "system.journal")
    else:
        path = next(folder.glob(f"system@*-{1:016x}-*.journal"))
        data = bytearray(path.read_bytes())
        data[-1] ^= 0xFF
        path.write_bytes(bytes(data))
        expected = ("JOURNAL_ARCHIVE_CHANGED", path.name)
    options = dict(root=str(root))
    li._write(li.progress_path(manifest), dict(schema=li.SCHEMA, recorded_at="2026-11-26T00:00:00Z",
                                                journals=li._journals(options), **li.snapshot(**options)))
    found, report = check(manifest, root, advance=True)
    assert found == {expected}
    assert report["findings"][0]["detail"]["compared_with"] == "the reviewed baseline"
    assert check(manifest, root, advance=True)[0] == {expected}, "reported until accept"
    li.accept(manifest, root=str(root))
    assert check(manifest, root)[0] == set()


def test_a_reviewed_archive_brought_back_changed_keeps_its_reviewed_record(machine):
    # Vacuumed after the review, the archive leaves the progress; a changed copy restored under its file ID is
    # found against the reviewed baseline, and the advancing check must hold the reviewed record, not crash.
    root, folder, manifest = machine
    li.check(manifest, root=str(root), advance=True)
    path = next(folder.glob(f"system@*-{1:016x}-*.journal"))
    original = path.read_bytes()
    path.unlink()
    found, report = check(manifest, root, advance=True)
    assert found == set() and report["journals"]["explained"][0]["reason"] == "vacuumed (oldest first)"
    changed = bytearray(original)
    changed[-1] ^= 0xFF
    path.write_bytes(bytes(changed))
    expected = {("JOURNAL_ARCHIVE_CHANGED", path.name)}
    assert check(manifest, root, advance=True)[0] == expected
    assert check(manifest, root, advance=True)[0] == expected, "reported until accept"
    li.accept(manifest, root=str(root))
    assert check(manifest, root)[0] == set()


def test_a_forged_digest_in_the_progress_cannot_vouch_for_an_archive(machine):
    # The snapshot reuses a cached digest when an archive's inode, size and change times match the record it is
    # given. A rewritten progress can give the archive's current times with the reviewed digest; the floor must
    # take digests only from the reviewed baseline, or read the file again.
    root, folder, manifest = machine
    li.check(manifest, root=str(root), advance=True)
    path = next(folder.glob(f"system@*-{1:016x}-*.journal"))
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF                                      # the same size, different content
    path.write_bytes(bytes(data))
    reviewed = json.loads(manifest.read_text())["journals"]["files"]
    options = dict(root=str(root))
    journals = li._journals(options)
    for file_id, record in journals["files"].items():
        if "sha256" in record:
            record["sha256"] = reviewed[file_id]["sha256"]   # what an intruder would write
    li._write(li.progress_path(manifest), dict(schema=li.SCHEMA, recorded_at="2026-11-26T00:00:00Z",
                                                journals=journals, **li.snapshot(**options)))
    found, report = check(manifest, root, advance=True)
    assert found == {("JOURNAL_ARCHIVE_CHANGED", path.name)}
    assert check(manifest, root, advance=True)[0] == found, "reported until accept"


def test_an_unchanged_archive_is_not_read_again_for_the_floor(machine, monkeypatch):
    root, folder, manifest = machine
    li.check(manifest, root=str(root), advance=True)
    read = []
    real = ji._digest
    monkeypatch.setattr(ji, "_digest", lambda path: read.append(path) or real(path))
    assert check(manifest, root, advance=True)[0] == set()
    assert read == [], "both caches vouch for the archives: nothing is hashed again"


def _forge(manifest, root):
    options = dict(root=str(root))
    li._write(li.progress_path(manifest), dict(schema=li.SCHEMA, recorded_at="2026-11-26T00:00:00Z",
                                                journals=li._journals(options), **li.snapshot(**options)))


def test_progress_cannot_forget_a_deleted_archive(machine):
    root, folder, manifest = machine
    li.check(manifest, root=str(root), advance=True)
    middle = next(folder.glob(f"system@*-{101:016x}-*.journal"))
    middle.unlink()                                       # not the oldest: not what vacuuming does
    _forge(manifest, root)
    found, report = check(manifest, root, advance=True)
    assert found == {("JOURNAL_FILE_DELETED", middle.name)}
    assert report["findings"][0]["detail"]["compared_with"] == "the reviewed baseline"
    assert check(manifest, root, advance=True)[0] == found, "reported until accept"


def test_vacuuming_after_the_review_stays_quiet_for_the_floor(machine):
    # The oldest archives go first; the file being written at the review is archived, then vacuumed in turn.
    root, folder, manifest = machine
    li.check(manifest, root=str(root), advance=True)
    for head in (1, 101):
        next(folder.glob(f"system@*-{head:016x}-*.journal")).unlink()
        assert check(manifest, root, advance=True)[0] == set()
    active = folder / "system.journal"
    active.rename(folder / f"system@{SEQUENCE.hex()}-{201:016x}-{1_700_000_000_000_000 + 201:016x}.journal")
    data = bytearray(next(folder.glob(f"system@*-{201:016x}-*.journal")).read_bytes())
    data[16] = ji.STATE_ARCHIVED
    next(folder.glob(f"system@*-{201:016x}-*.journal")).write_bytes(bytes(data))
    journal(active, head=251, tail=300)
    assert check(manifest, root, advance=True)[0] == set()
    next(folder.glob(f"system@*-{201:016x}-*.journal")).unlink()
    assert check(manifest, root, advance=True)[0] == set(), "archived after the review, vacuumed: quiet"
