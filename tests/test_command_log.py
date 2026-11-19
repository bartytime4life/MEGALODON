"""Tamper-evident command log: forward-secure signatures, gaps, cuts, crashes and the heartbeat's view from outside."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import threading

import pytest

from megalodon import command_log as cl
from megalodon import tamper
from test_process_network import proc  # noqa: F401


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        self.now += timedelta(seconds=1)
        return self.now


@pytest.fixture
def log(tmp_path):
    paths = dict(state=tmp_path / "state.json", log=tmp_path / "commands.jsonl")
    key = cl.init(**paths)["key"]
    recorder = cl.Recorder(clock=Clock(), **paths)
    recorder.add("start", mode="given")
    for number in range(1, 6):
        recorder.add("exec", pid=1000 + number, uid=1000, program="/usr/bin/true", argv=["true", str(number)])
    recorder.add("stop", recorded=5)
    recorder.flush()
    recorder.close()
    return dict(paths, key=key, path=tmp_path)


def rewrite(path, change):
    lines = [json.loads(line) for line in Path(path).read_text().splitlines()]
    lines = change(lines)
    Path(path).write_text("".join(json.dumps(e, sort_keys=True, separators=(",", ":")) + "\n" for e in lines))


def rules(report):
    return [(f["rule_id"], f["subject"]) for f in report["findings"]]


def test_a_clean_log_verifies_and_the_key_is_not_kept(log):
    report = cl.verify(log["key"], log=log["log"])
    assert (report["lines"], report["verified"], report["first"], report["last"], report["findings"]) == (
        7, 7, 1, 7, [])
    state = json.loads(log["state"].read_text())
    assert state["key"] != log["key"], "the first key is gone from the machine once a line is written"
    assert log["key"] not in log["log"].read_text()
    assert oct(log["state"].stat().st_mode & 0o777) == oct(log["log"].stat().st_mode & 0o777) == "0o600"
    assert cl.head(log["state"]) == dict(sequence=7, mac=state["last_mac"], key_id=state["key_id"])
    with pytest.raises(cl.CommandLogError, match="not the one this log was started with"):
        cl.verify("11" * 32, log=log["log"])
    with pytest.raises(cl.CommandLogError, match="already set up"):
        cl.init(state=log["state"], log=log["log"])


def test_an_intruder_with_todays_key_cannot_rewrite_the_past(log):
    stolen = bytes.fromhex(json.loads(log["state"].read_text())["key"])

    def forge(lines):
        # Line 3 changed and signed again with every key the intruder can make from the one they stole.
        lines[2]["argv"] = ["true", "nothing to see"]
        lines[2]["mac"] = cl.sign(stolen, lines[2])
        return lines
    rewrite(log["log"], forge)
    assert rules(cl.verify(log["key"], log=log["log"])) == [("COMMAND_LOG_FORGED", "line:3"),
                                                            ("COMMAND_LOG_FORGED", "line:4")], \
        "line 3 fails its own key, and line 4 no longer follows it"


def test_removed_reordered_and_cut_lines(log, tmp_path):
    original = log["log"].read_text()
    rewrite(log["log"], lambda lines: lines[:3] + lines[4:])
    assert rules(cl.verify(log["key"], log=log["log"])) == [("COMMAND_LOG_GAP", "lines:4-4")]
    log["log"].write_text(original)
    rewrite(log["log"], lambda lines: lines[:2] + [lines[3], lines[2]] + lines[4:])
    assert ("COMMAND_LOG_FORGED", "line:3") in rules(cl.verify(log["key"], log=log["log"]))
    log["log"].write_text(original)
    rewrite(log["log"], lambda lines: lines[:-2])
    assert cl.verify(log["key"], log=log["log"])["findings"] == [], "a cut end looks whole from inside alone"
    assert rules(cl.verify(log["key"], log=log["log"], expect_sequence=7)) == [
        ("COMMAND_LOG_TRUNCATED", "lines:6-7")], "the heartbeat's last line shows it"


def test_a_crash_between_the_log_and_its_state(log):
    saved = log["state"].read_text()
    recorder = cl.Recorder(clock=Clock(), state=log["state"], log=log["log"])
    recorder.add("start", mode="given")
    recorder.add("exec", pid=2001, program="/usr/bin/id", argv=["id"])
    recorder.flush()
    recorder.close()
    log["state"].write_text(saved)                  # the lines reached the disk, the state did not
    os.chmod(log["state"], 0o600)
    again = cl.Recorder(clock=Clock(), state=log["state"], log=log["log"])
    assert again.next == 10, "the key moved past the lines already written"
    again.add("exec", pid=2002, program="/usr/bin/id", argv=["id"])
    again.flush()
    again.close()
    report = cl.verify(log["key"], log=log["log"])
    assert report["verified"] == report["lines"] == 10
    assert rules(report) == [("COMMAND_LOG_STOPPED_UNCLEANLY", "line:8")] or rules(report) == [], \
        "only a restart without a stop is reported"


def test_restarts_lost_events_and_recording(log):
    class Source:
        def __init__(self, stop, me):
            self.stop, self.batches = stop, [[("exec", me, 0), ("lost", 0, 0)], []]

        def events(self, timeout):
            if not self.batches:
                self.stop.set()
                return []
            return self.batches.pop(0)

        def close(self):
            pass
    crashed = cl.Recorder(clock=Clock(), state=log["state"], log=log["log"])
    crashed.add("start", mode="given")
    crashed.flush()                                  # no stop line: it was killed
    crashed.close()                                  # as its process ending would
    stop = threading.Event()
    assert cl.record(stop, state=log["state"], log=log["log"], source=Source(stop, os.getpid()), clock=Clock()) == 1
    report = cl.verify(log["key"], log=log["log"])
    assert rules(report) == [("COMMAND_LOG_STOPPED_UNCLEANLY", "line:9"), ("COMMAND_LOG_EVENTS_LOST", "line:11")]
    mine = [e for e in cl.entries(log["log"]) if e.get("pid") == os.getpid()]
    assert mine and mine[0]["program"] == os.readlink("/proc/self/exe")


def test_passwords_and_tokens_are_blanked(tmp_path):
    secret = "Hunter" + "2pass"
    argv, hidden = cl._redact(["mysql", "-uroot", "-p" + secret, "db"])
    assert argv == ["mysql", "-uroot", f"-p[hidden: {len(secret)} characters]", "db"] and hidden == 1
    argv, _ = cl._redact(["deploy", "--password", secret, "--token=" + secret])
    assert secret not in " ".join(argv) and "--password" in argv
    argv, _ = cl._redact(["curl", "-u", "me:" + secret, "https://api.internal"])
    assert argv == ["curl", "-u", "me:[hidden]", "https://api.internal"]
    proc(tmp_path, 4242, "/usr/bin/deploy", [], cmdline=b"\0".join([b"deploy", b"--password", secret.encode()]))
    (tmp_path / "proc/4242/loginuid").write_text("1000")
    (tmp_path / "proc/4242/sessionid").write_text("7")
    entry = cl.describe(tmp_path / "proc", 4242)
    assert entry["argv"] == ["deploy", "--password", f"[hidden: {len(secret)} characters]"] and entry["hidden"] == 1
    assert (entry["login_uid"], entry["session"], entry["program"]) == (1000, 7, "/usr/bin/deploy")
    assert cl.describe(tmp_path / "proc", 4242, redact=False)["argv"][2] == secret


def heartbeat_lines(key, logs):
    lines = []
    for sequence, log in enumerate(logs, 1):
        body = dict(schema=tamper.HEARTBEAT_SCHEMA, sensor="web-1", sequence=sequence,
                    sent_at=f"2026-11-19T12:{sequence:02d}:00Z", state_digest="0" * 64, tamper_baseline=False,
                    findings=[])
        if log:
            body["command_log"] = dict(sequence=log[0], mac="a" * 64, key_id=log[1])
        body["mac"] = tamper._sign(key, body)
        lines.append(json.dumps(body))
    return lines


def test_the_heartbeat_carries_the_last_line_off_the_machine(log, tmp_path):
    config = tmp_path / "heartbeat.json"
    tamper.init_heartbeat("https://monitor.example/beat", config=config)
    _settings, body = tamper.heartbeat(config, manifest=tmp_path / "none.json", sequence_path=tmp_path / "seq.json",
                                       runner=lambda *a: "", uptime=lambda: 1.0, command_state=log["state"])
    assert body["command_log"]["sequence"] == 7 and body["command_log"]["key_id"] == cl.head(log["state"])["key_id"]
    key = "ab" * 32
    now = datetime(2026, 11, 19, 12, 10, tzinfo=timezone.utc)
    found = tamper.monitor(heartbeat_lines(key, [(10, "k1"), (12, "k1"), (5, "k1")]), key, now=now)
    assert [f["rule_id"] for f in found["findings"]] == ["COMMAND_LOG_ROLLED_BACK"]
    assert found["command_log_sequence"] == 5
    found = tamper.monitor(heartbeat_lines(key, [(10, "k1"), (3, "k2")]), key, now=now)
    assert [f["rule_id"] for f in found["findings"]] == ["COMMAND_LOG_RESTARTED"]
    found = tamper.monitor(heartbeat_lines(key, [(10, "k1"), None]), key, now=now)
    assert [f["rule_id"] for f in found["findings"]] == ["COMMAND_LOG_LOST"]
    # A replayed old heartbeat is reported as a replay, not as the log going back.
    beats = heartbeat_lines(key, [(10, "k1"), (12, "k1")])
    found = tamper.monitor(beats + beats[:1], key, now=now)
    assert [f["rule_id"] for f in found["findings"]] == ["HEARTBEAT_REPLAYED"]


def test_the_cli(log, tmp_path, capsys):
    from megalodon.cli import main
    key_file = tmp_path / "key.txt"
    key_file.write_text(log["key"] + "\n")
    os.chmod(key_file, 0o600)
    with pytest.raises(SystemExit) as exit_:
        main(["commands", "verify", "--key-file", str(key_file), "--log", str(log["log"])])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out)["verified"] == 7
    with pytest.raises(SystemExit) as exit_:
        main(["commands", "show", "--contains", "true 3", "--log", str(log["log"])])
    out = capsys.readouterr().out
    assert exit_.value.code == 0 and "#4" in out and "true 3" in out and "true 4" not in out
    with pytest.raises(SystemExit) as exit_:
        main(["commands", "init", "--state", str(tmp_path / "s2.json"), "--log", str(tmp_path / "l2.jsonl"),
              "--key-file", str(key_file)])
    assert exit_.value.code == 2, "an existing key file is never overwritten"
    assert not (tmp_path / "s2.json").exists(), "and no log is set up with a key saved nowhere"
    second = tmp_path / "second-key.txt"
    with pytest.raises(SystemExit) as exit_:
        main(["commands", "init", "--state", str(tmp_path / "s2.json"), "--log", str(tmp_path / "l2.jsonl"),
              "--key-file", str(second)])
    assert exit_.value.code == 0 and oct(second.stat().st_mode & 0o777) == "0o600"
    assert len(second.read_text().strip()) == 64 and second.read_text().strip() not in capsys.readouterr().out


def test_one_recorder_at_a_time(log):
    first = cl.Recorder(state=log["state"], log=log["log"])
    with pytest.raises(cl.CommandLogError, match="another command recorder is running"):
        cl.Recorder(state=log["state"], log=log["log"])
    first.close()
    with cl.Recorder(state=log["state"], log=log["log"]) as second:
        second.add("exec", pid=1, program="/bin/true", argv=["true"])
    assert cl.verify(log["key"], log=log["log"])["findings"] == []


def test_lines_that_are_not_records_fail_verification(log):
    log["log"].write_text("not json\n")
    report = cl.verify(log["key"], log=log["log"])
    assert rules(report) == [("COMMAND_LOG_FORGED", "file:commands.jsonl:1")] and report["unreadable"] == 1
    log["log"].write_text(json.dumps(dict(kind="exec", argv=["ls"])) + "\n")     # a record with no number
    assert rules(cl.verify(log["key"], log=log["log"])) == [("COMMAND_LOG_FORGED", "file:commands.jsonl:1")]


def test_rotation_keeps_every_file_and_a_chosen_start(log, monkeypatch):
    monkeypatch.setattr(cl, "ROTATE_BYTES", 1)                  # every flush starts a new file
    with cl.Recorder(clock=Clock(), state=log["state"], log=log["log"]) as recorder:
        for batch in range(3):
            recorder.add("exec", pid=3000 + batch, program="/bin/true", argv=["true", str(batch)])
            recorder.flush()
    files = cl.log_files(log["log"])
    assert len(files) == 4 and files[-1] == log["log"], "three rotated files, none written over"
    assert cl.verify(log["key"], log=log["log"])["findings"] == []
    assert cl.verify(log["key"], log=log["log"], from_sequence=8)["findings"] == [], "earlier lines are skipped"
    # The oldest file moved off the machine on purpose: the verifier says where its own copy ends.
    oldest = files[0]
    oldest.unlink()
    assert rules(cl.verify(log["key"], log=log["log"])) == [("COMMAND_LOG_GAP", "lines:1-7")]
    report = cl.verify(log["key"], log=log["log"], from_sequence=8)
    assert report["findings"] == [] and report["first"] == 8
