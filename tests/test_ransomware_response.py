"""The ransomware watch answers at once: it names the writing processes, and a finding is decided and enforced."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Event, Thread
import time

import pytest

from megalodon import enforcement as en
from megalodon import ransomware_watch as rw
from megalodon import response_engine as re_
from test_enforcement import child, enable, p, state_of  # noqa: F401
from test_ransomware_watch import TEXT, encrypted, write

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify is Linux-only")


def fake_process(proc, pid, *, start, exe, files):
    """A /proc entry: `files` maps fd number to (path, flags in octal)."""
    base = proc / str(pid)
    (base / "fd").mkdir(parents=True)
    (base / "fdinfo").mkdir()
    fields = ["S"] + ["0"] * 18 + [str(start)] + ["0"] * 10
    (base / "stat").write_text(f"{pid} (tool) " + " ".join(fields) + "\n")
    (base / "comm").write_text("tool\n")
    os.symlink(exe, base / "exe")
    for fd, (path, flags) in files.items():
        os.symlink(path, base / "fd" / str(fd))
        (base / "fdinfo" / str(fd)).write_text(f"pos:\t0\nflags:\t{flags}\nmnt_id:\t1\n")


def test_suspects_are_named_by_start_time_and_told_apart_by_writing(tmp_path, monkeypatch):
    proc, docs = tmp_path / "proc", tmp_path / "docs"
    docs.mkdir()
    fake_process(proc, 4100, start=777, exe="/tmp/.x/locker (deleted)",
                 files={3: (f"{docs}/a.pdf", "0100002"), 4: ("/etc/hosts", "0100000")})
    fake_process(proc, 4200, start=888, exe="/usr/bin/viewer", files={5: (f"{docs}/b.pdf", "0100000")})
    fake_process(proc, 4300, start=999, exe="/usr/bin/editor", files={6: (f"{docs}/c.txt", "0101")})
    fake_process(proc, 4400, start=1, exe="/usr/bin/other", files={7: ("/var/tmp/x", "01")})
    real_listdir = os.listdir
    # Whatever order /proc lists processes in, the result is the same: here, the reverse of PID order.
    monkeypatch.setattr(rw.os, "listdir", lambda path: sorted(real_listdir(path), reverse=True)
                        if str(path) == str(proc) else real_listdir(path))
    found = rw.suspects([docs], proc=str(proc))
    assert [(f["pid"], f["start"], f["program"], f["writing"]) for f in found] == [
        (4100, 777, "/tmp/.x/locker", True), (4300, 999, "/usr/bin/editor", True),
        (4200, 888, "/usr/bin/viewer", False)], \
        "writers first; a deleted program keeps its path; a write-only open counts; files elsewhere do not"


def test_the_engine_targets_writers_only():
    finding = dict(rule_id="RANSOMWARE_ENCRYPTION", severity="CRITICAL", message="m", evidence=dict(processes=[
        dict(pid=10, start=5, program="/tmp/locker", writing=True),
        dict(pid=11, start=6, program="/opt/viewer/viewer", writing=False),
        dict(pid=12, start=7, program="/usr/bin/other")]))
    [signal], refused = re_.ingest_signals([json.dumps(finding)], re_._now())
    assert refused == 0
    assert sorted(signal.entities["process_id"]) == ["10@5:/tmp/locker", "12@7:/usr/bin/other"], \
        "a process that was only reading is evidence, not a target; one that does not say is still a target"
    assert "/opt/viewer/viewer" not in signal.entities.get("process", ()), "nor is its program"


@linux
def test_a_writer_seen_during_the_burst_is_named_after_it_closed_its_files(tmp_path):
    """Ransomware closes each file as it goes: the processes are looked for while it writes, not only at the end."""
    for i in range(4):
        write(tmp_path / f"r{i}.txt", TEXT)
    detector = rw.RansomwareDetector(min_files=4, window_seconds=60)
    detector.seed([tmp_path])
    writer = dict(pid=4242, start=9, name="locker", program="/tmp/locker", open_files=1, writing=True)
    holding = [writer]
    found = []
    watcher = rw.Watcher([tmp_path], detector, found.append, suspects_fn=lambda roots: list(holding))
    stop = Event()
    thread = Thread(target=watcher.run, args=(stop,), kwargs=dict(poll=0.05), daemon=True)
    thread.start()
    try:
        write(tmp_path / "r0.txt", encrypted())
        deadline = time.monotonic() + 5
        while not watcher.tally and time.monotonic() < deadline:
            time.sleep(0.02)
        holding.clear()                               # it has closed everything by the time of the alarm
        for i in range(1, 4):
            write(tmp_path / f"r{i}.txt", encrypted())
        while not found and time.monotonic() < deadline:
            time.sleep(0.02)
    finally:
        stop.set()
        thread.join(2)
        watcher.close()
    assert [f.rule_id for f in found] == ["RANSOMWARE_ENCRYPTION"]
    [named] = found[0].evidence["processes"]
    assert (named["pid"], named["start"], named["writing"], named["samples"]) == (4242, 9, True, 1)


def test_the_tally_forgets_processes_outside_the_window(tmp_path):
    clock = [100.0]
    detector = rw.RansomwareDetector(min_files=2, window_seconds=30)
    seen = [[dict(pid=1, start=1, program="/a", writing=True)], [dict(pid=2, start=2, program="/b", writing=False)]]
    watcher = rw.Watcher([tmp_path], detector, None, suspects_fn=lambda roots: seen.pop(0) if seen else [],
                         clock=lambda: clock[0])
    try:
        watcher.sample()
        watcher.sample()
        assert len(watcher.tally) == 1, "looked at most every SAMPLE_GAP seconds"
        clock[0] += 31
        assert [p["pid"] for p in watcher.processes()] == [2], "the first writer was seen too long ago"
    finally:
        watcher.close()


def test_never_this_process(child, monkeypatch):
    # The child stands in for this process, so a missing guard pauses it and not the test run.
    target = f"{child.pid}@{en._start(child.pid)}:{os.readlink(f'/proc/{child.pid}/exe')}"
    monkeypatch.setattr(en, "getpid", lambda: child.pid)
    with pytest.raises(en.EnforcementError, match="cannot suspend itself"):
        en.Executor().suspend_process(target, {})
    time.sleep(0.1)
    assert state_of(child.pid) in "SR"


LOCKER = r'''
import os, sys, time
folder = sys.argv[1]
hold = open(os.path.join(folder, "held.txt"), "r+b")      # open for writing throughout, as an encryptor's output is
for name in sorted(n for n in os.listdir(folder) if n.startswith("doc")):
    with open(os.path.join(folder, name), "r+b") as out:
        out.write(b"\xaa\xbb" + os.urandom(8190))
print("done", flush=True)
time.sleep(60)
'''


@linux
def test_a_finding_is_decided_and_the_encryptor_paused_at_once(p, tmp_path):
    folder = tmp_path / "docs"
    folder.mkdir()
    for i in range(6):
        write(folder / f"doc{i}.txt", TEXT)
    write(folder / "held.txt", TEXT)
    enable(p, ["suspend_process"], ["ransomware"])
    responder = rw.Responder(policy=p["policy"], ledger=p["ledger"], state=p["state"],
                             enforcement_policy=p["enforce"], journal=p["journal"],
                             enforcement_state=p["enforce_state"])
    detector = rw.RansomwareDetector(min_files=5, window_seconds=60)
    detector.seed([folder])
    answers = []
    watcher = rw.Watcher([folder], detector, lambda finding: answers.append(responder(finding)))
    stop = Event()
    thread = Thread(target=watcher.run, args=(stop,), kwargs=dict(poll=0.05), daemon=True)
    thread.start()
    script = tmp_path / "locker.py"
    script.write_text(LOCKER)
    locker = subprocess.Popen([sys.executable, "-I", str(script), str(folder)], stdout=subprocess.PIPE, text=True)
    try:
        assert locker.stdout.readline().strip() == "done"
        deadline = time.monotonic() + 5
        while not answers and time.monotonic() < deadline:
            time.sleep(0.02)
        stop.set()
        thread.join(2)
        [answer] = answers
        assert (answer["rule_id"], answer["decided"], answer["enforcement"]["enabled"]) == (
            "RANSOMWARE_ENCRYPTION", True, True)
        [applied] = answer["enforcement"]["applied"]
        assert applied["action"] == "suspend_process" and applied["target"].startswith(f"{locker.pid}@")
        assert state_of(locker.pid) == "T", "paused before the next file event was read"
        en.undo(applied["id"], journal=p["journal"])
        assert state_of(locker.pid) in "SR"
    finally:
        stop.set()
        watcher.close()
        locker.kill()
        locker.wait()


def test_a_finding_without_enforcement_or_a_policy_is_still_reported(p, tmp_path):
    finding = rw.Finding("RANSOMWARE_ENCRYPTION", "CRITICAL", re_._now(), "m",
                         dict(processes=[dict(pid=10, start=5, program="/tmp/locker", writing=True)]))
    off = rw.Responder(policy=p["policy"], ledger=p["ledger"], state=p["state"],
                       enforcement_policy=tmp_path / "none.toml", journal=p["journal"],
                       enforcement_state=p["enforce_state"])
    answer = off(finding)
    assert (answer["decided"], answer["decisions"]) == (True, 1)
    assert answer["enforcement"]["enabled"] is False
    assert "no enforcement policy" in answer["enforcement"]["note"]
    assert answer["enforcement"]["expired"] == []
    missing = rw.Responder(policy=tmp_path / "missing.toml", ledger=p["ledger"], state=p["state"],
                           enforcement_policy=p["enforce"], journal=p["journal"],
                           enforcement_state=p["enforce_state"])
    answer = missing(finding)
    assert answer["decided"] is False and "not decided" in answer["error"], "the watch keeps going"
    note = rw.Finding("RANSOM_NOTE", "HIGH", re_._now(), "m", dict(file="x", folder=str(tmp_path)))
    assert off(note) == dict(rule_id="RANSOM_NOTE", decided=True, decisions=0, would_apply=0), \
        "no playbook covers a note alone: nothing to carry out"


def test_a_pass_never_loses_another_pass_s_state(p, monkeypatch):
    """The watch and the timer can decide at the same moment: neither may write over the other's state."""
    real = re_.decide
    entered, release = Event(), Event()

    def slow(policy, state, signals, now, **kw):
        if signals and signals[0].rule_id == "FIRST_RULE":
            entered.set()
            release.wait(5)
        return real(policy, state, signals, now, **kw)
    monkeypatch.setattr(re_, "decide", slow)

    def ingest(rule):
        re_.ingest([json.dumps(dict(rule_id=rule, severity="HIGH"))], policy_path=p["policy"], ledger=p["ledger"],
                   state_path=p["state"], protected=set())
    first = Thread(target=ingest, args=("FIRST_RULE",))
    first.start()
    assert entered.wait(5)
    second = Thread(target=ingest, args=("SECOND_RULE",))
    second.start()
    time.sleep(0.3)
    assert second.is_alive(), "waits for the first pass"
    release.set()
    first.join(5)
    second.join(5)
    seen = json.loads(p["state"].read_text())["seen"]
    assert sorted(key.split(":")[1] for key in seen) == ["FIRST_RULE", "SECOND_RULE"]


def test_collecting_runs_outside_the_lock_and_keeps_its_cursor(p, monkeypatch):
    def collect(policy, state, now, *, root="/"):
        # A live watch decides while the timer is still collecting: it must not wait, nor be written over.
        done = []
        thread = Thread(target=lambda: done.append(re_.ingest(
            [json.dumps(dict(rule_id="DURING_COLLECT", severity="HIGH"))], policy_path=p["policy"],
            ledger=p["ledger"], state_path=p["state"], protected=set())))
        thread.start()
        thread.join(5)
        assert done, "not blocked by the collecting pass"
        state["cursor"] = 42
        return [], []
    monkeypatch.setattr(re_, "collect", collect)
    re_.run(policy_path=p["policy"], ledger=p["ledger"], state_path=p["state"], protected=set())
    state = json.loads(p["state"].read_text())
    assert state["cursor"] == 42 and any("DURING_COLLECT" in key for key in state["seen"])


def test_saved_folders_and_the_cli(tmp_path, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    saved = tmp_path / "conf" / "ransomware.json"
    (tmp_path / "docs").mkdir()
    assert code("ransomware", "watch", "--folders-file", str(saved), "--config", str(tmp_path / "x.toml")) == 2
    assert "ransomware init --dir" in capsys.readouterr().err
    assert code("ransomware", "init", "--dir", str(tmp_path / "docs"), "--dir", str(tmp_path / "docs"),
                "--min-files", "4", "--folders-file", str(saved)) == 0
    out = json.loads(capsys.readouterr().out)
    assert (out["folders"], out["min_files"]) == ([str(tmp_path / "docs")], 4)
    assert saved.stat().st_mode & 0o777 == 0o600
    assert rw.load_folders(saved) == dict(folders=[str(tmp_path / "docs")], min_files=4, window_seconds=60)
    assert code("ransomware", "init", "--dir", str(tmp_path / "docs"), "--folders-file", str(saved)) == 2, \
        "saved folders are replaced only when asked"
    assert code("ransomware", "init", "--dir", str(tmp_path / "missing"), "--folders-file",
                str(tmp_path / "other.json")) == 2
    os.chmod(saved, 0o620)
    with pytest.raises(rw.WatchError, match="others cannot change"):
        rw.load_folders(saved)
    os.chmod(saved, 0o600)
    saved.write_text(json.dumps(["/etc"]))
    with pytest.raises(rw.WatchError, match="not a saved list"):
        rw.load_folders(saved)


def test_the_scheduled_watch_answers_at_once():
    from megalodon import schedule
    job = next(j for j in schedule.JOBS if j.name == "ransomware")
    assert job.calendar is None and job.command == ("ransomware", "watch", "--respond")
    assert job.setup.startswith("megalodon ransomware init --dir")
    [text] = schedule.units(job, ["megalodon"], True).values()
    assert "ExecStart=megalodon ransomware watch --respond" in text and "Restart=on-failure" in text
    enforce = next(j for j in schedule.JOBS if j.name == "enforce")
    assert job.writable == enforce.writable, "it may carry out what the enforce job would"
