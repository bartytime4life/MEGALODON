"""The systemd journal as the response engine's auth log, for systems that keep logins only there.

A stand-in journalctl prints neutral placeholders; no log text is generated here. auth-review's own tests cover
reading what the journal holds.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys

import pytest

from megalodon import auth_review
from megalodon import response_engine as re_

NOW = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.90"

STANDIN = '''#!{python} -I
import json, os, sys, time
plan = json.load(open({plan!r}))
json.dump(dict(argv=sys.argv[1:], env=dict(os.environ)), open({seen!r}, "w"))
sys.stdout.write(plan.get("out", "")); sys.stdout.flush()
for _ in range(plan.get("flood", 0)):
    sys.stdout.write("placeholder " * 80 + "\\n")
sys.stderr.write(plan.get("err", ""))
time.sleep(plan.get("sleep", 0))
sys.exit(plan.get("code", 0))
'''


@pytest.fixture
def journal(tmp_path, monkeypatch):
    plan, seen, program = tmp_path / "plan.json", tmp_path / "seen.json", tmp_path / "journalctl"
    program.write_text(STANDIN.format(python=sys.executable, plan=str(plan), seen=str(seen)))
    program.chmod(0o755)
    monkeypatch.setattr(auth_review, "JOURNALCTL", (str(tmp_path / "absent"), str(program)))

    def set(**how):
        plan.write_text(json.dumps(how))
    set()
    return dict(set=set, seen=lambda: json.loads(seen.read_text()), program=program)


@pytest.fixture
def paths(tmp_path, monkeypatch, journal):
    monkeypatch.setattr(re_, "AUTH_LOGS", (str(tmp_path / "none"),))
    monkeypatch.setattr(re_, "JOURNALD_RUNNING", str(tmp_path))                  # journald runs
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text()
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    for name in ("audit_db", "ancestry_allow_file", "credential_allow_file"):
        text = "\n".join(f'{name} = ""' if line.startswith(f"{name} = ") else line for line in text.splitlines())
    policy.write_text(text + "\n")
    return dict(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
                protected=set())


def run(paths, now=NOW + timedelta(minutes=5)):
    return re_.run(now=now, **paths)


def test_init_reads_the_journal_where_no_auth_log_is_kept_and_journald_runs(paths):
    assert re_.load_policy(paths["policy_path"]).sources["auth_log"] == "journal"


def test_the_journals_auth_messages_are_read_from_a_day_before_the_cursor(paths, journal, monkeypatch):
    journal["set"](out="placeholder one\nplaceholder two\n")
    handed = {}

    def review(lines, *, source, on_finding=None, **_):
        handed.update(lines=list(lines), source=source)
        on_finding(dict(rule_id="AUTH_FAILURE_BURST", severity="HIGH", observed_at=NOW.isoformat(), subject=ATTACKER,
                        message="placeholder", evidence=dict(source=ATTACKER), identity=ATTACKER))
        return {}, None
    monkeypatch.setattr(auth_review, "review", review)
    result = run(paths)
    assert handed == dict(lines=[b"placeholder one\n", b"placeholder two\n"], source="journal")
    seen = journal["seen"]()
    first_cursor = NOW + timedelta(minutes=5) - timedelta(hours=re_.AUTH_FIRST_HOURS)
    since = int((first_cursor - timedelta(hours=re_.JOURNAL_CONTEXT_HOURS)).timestamp())
    assert seen["argv"] == ["--no-pager", "--utc", "-o", "short-iso-precise", f"--since=@{since}",
                            "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]
    assert "-q" not in seen["argv"], "its warning that it shows only this user's messages must be seen"
    assert set(seen["env"]) <= {"PATH", "LC_ALL", "SYSTEMD_COLORS", "SYSTEMD_PAGER", "SYSTEMD_LESS", "LC_CTYPE"}
    assert not [g for g in result["gaps"] if g.startswith("auth")]
    [decision] = [json.loads(line) for line in Path(paths["ledger"]).read_text().splitlines()]
    assert decision["playbook"] == "attacker-at-the-door"
    run(paths, now=NOW + timedelta(minutes=10))
    since = int((NOW - timedelta(hours=re_.JOURNAL_CONTEXT_HOURS)).timestamp())
    assert f"--since=@{since}" in journal["seen"]()["argv"], "the next pass reads from a day before its cursor"
    assert len(Path(paths["ledger"]).read_text().splitlines()) == 1, "and decides nothing twice"


def test_a_journal_line_is_one_auth_review_reads():
    _, reviewer = auth_review.review([b"2026-11-27T12:00:00.123456+00:00 host sshd[1]: placeholder\n"],
                                     source="journal", reference=NOW)
    assert reviewer.stats["unrecognized_lines"] == 0 and reviewer.stats["invalid_timestamps"] == 0


@pytest.mark.parametrize("how,gap", [
    (dict(err="No journal files were found.\n", out="-- No entries --\n"), "auth: the journal holds no files here"),
    (dict(err="Hint: You are currently not seeing messages from other users and the system.\n"),
     "auth: the journal shows only this user's own messages"),
    (dict(err="Failed to open the journal: placeholder\n", code=1),
     "auth: the journal cannot be read: Failed to open the journal: placeholder"),
    (dict(code=1), "auth: the journal cannot be read: exit status 1"),
])
def test_a_journal_that_cannot_be_read_whole_is_a_gap(paths, journal, how, gap):
    journal["set"](**how)
    assert any(g.startswith(gap) for g in run(paths)["gaps"])


def test_a_journal_that_hangs_is_stopped_and_a_gap(paths, journal, monkeypatch):
    monkeypatch.setattr(auth_review, "JOURNAL_TIMEOUT", 1)
    journal["set"](sleep=30)
    assert "auth: journalctl did not finish within 1 s" in run(paths)["gaps"]


def test_a_journal_past_the_size_limit_is_stopped_and_a_gap(paths, journal, monkeypatch):
    monkeypatch.setattr(auth_review, "MAX_INPUT_BYTES", 64 * 1024)
    journal["set"](flood=10_000)
    assert "auth: the journal's auth messages exceed the 64 MiB limit" in run(paths)["gaps"]


def test_no_journalctl_is_a_gap(paths, journal, monkeypatch):
    monkeypatch.setattr(auth_review, "JOURNALCTL", (str(journal["program"]) + ".gone",))
    assert "auth: the journal cannot be read: journalctl is not installed" in run(paths)["gaps"]


def test_init_prefers_an_auth_log_file_and_writes_nothing_without_journald(tmp_path, monkeypatch, journal):
    log = tmp_path / "auth.log"
    log.write_text("")
    monkeypatch.setattr(re_, "AUTH_LOGS", (str(log),))
    monkeypatch.setattr(re_, "JOURNALD_RUNNING", str(tmp_path))
    re_.write_default_policy(tmp_path / "one.toml")
    assert re_.load_policy(tmp_path / "one.toml").sources["auth_log"] == str(log)
    log.unlink()
    monkeypatch.setattr(re_, "JOURNALD_RUNNING", str(tmp_path / "no-journald"))
    re_.write_default_policy(tmp_path / "two.toml")
    assert re_.load_policy(tmp_path / "two.toml").sources["auth_log"] == ""


def test_auth_review_reads_the_journal_from_the_command_line(journal, capsys):
    from megalodon.cli import main
    journal["set"](out="placeholder\n", err="No journal files were found.\n")
    with pytest.raises(SystemExit) as done:
        main(["auth-review", "--journal", "--hours", "6"])
    report = json.loads(capsys.readouterr().out)
    assert done.value.code == 0 and report["source"] == "journal" and report["input"]["lines"] == 1
    assert report["gaps"] == ["the journal holds no files here: journald keeps none, or keeps them where this user "
                              "cannot see them"]
    since = int(journal["seen"]()["argv"][4].removeprefix("--since=@"))
    assert abs(datetime.now(timezone.utc).timestamp() - 6 * 3600 - since) < 120
    journal["set"](code=1, err="placeholder failure\n")
    with pytest.raises(SystemExit) as done:
        main(["auth-review", "--journal"])
    assert done.value.code == 2 and "the journal cannot be read: placeholder failure" in capsys.readouterr().err
    with pytest.raises(SystemExit) as done:
        main(["auth-review", "--journal", "--input", "-"])
    assert done.value.code == 2, "one input or the other"


def test_a_quiet_servers_journal_is_never_read_further_back_than_two_days(paths, journal):
    run(paths)                                                   # nothing found: the cursor stands still
    run(paths, now=NOW + timedelta(days=30))
    since = int((NOW + timedelta(days=30) - timedelta(hours=re_.AUTH_FIRST_HOURS + re_.JOURNAL_CONTEXT_HOURS))
                .timestamp())
    assert f"--since=@{since}" in journal["seen"]()["argv"]


def _attempts(monkeypatch, end):
    """One failed login a minute from a day before NOW until `end()`, given to the real auth-review as values from
    wherever a pass starts reading: no log text."""
    start = NOW - timedelta(days=1)
    monkeypatch.setattr(auth_review, "read_journal", lambda since, notes: [since])

    def review(lines, *, source, on_finding=None, lure_users=(), **_):
        reviewer = auth_review.AuthReviewer(on_finding=on_finding, lure_users=lure_users)
        t = max(start, lines[0].replace(second=0, microsecond=0))
        while t <= end():
            if t >= lines[0]:
                reviewer._failure(t, ATTACKER, f"user{t.minute % 7}")
            t += timedelta(minutes=1)
        return reviewer.report(source), reviewer
    monkeypatch.setattr(auth_review, "review", review)


def _decided(paths):
    path = Path(paths["ledger"])
    return [json.loads(line)["signal"] for line in path.read_text().splitlines()] if path.exists() else []


def test_a_journal_read_again_from_elsewhere_decides_nothing_new(paths, monkeypatch):
    _attempts(monkeypatch, lambda: NOW)                         # nothing logged after NOW
    run(paths, now=NOW + timedelta(minutes=5))
    first = len(_decided(paths))
    assert first
    for minutes in (10, 15, 20, 90):                            # each pass starts reading somewhere else
        run(paths, now=NOW + timedelta(minutes=minutes))
    assert len(_decided(paths)) == first, "the same attempts, read from another start, are not decided again"


def test_an_attack_that_goes_on_is_still_decided_about_hourly(paths, monkeypatch):
    clock = {"now": NOW}
    _attempts(monkeypatch, lambda: clock["now"])
    for minutes in range(5, 6 * 60, 5):                         # six hours of passes, five minutes apart
        clock["now"] = NOW + timedelta(minutes=minutes)
        run(paths, now=clock["now"])
    later = [s for s in _decided(paths) if s["observed_at"] > re_._iso(NOW)]
    per_rule = {}
    for s in later:
        per_rule.setdefault(s["rule_id"], []).append(s["observed_at"])
    assert per_rule and all(5 <= len(times) <= 7 for times in per_rule.values()), per_rule
    for times in per_rule.values():
        gaps = [datetime.fromisoformat(b.replace("Z", "+00:00")) - datetime.fromisoformat(a.replace("Z", "+00:00"))
                for a, b in zip(times, times[1:])]
        assert all(timedelta(hours=1) <= g < timedelta(hours=2) for g in gaps), gaps


def test_what_was_decided_is_kept_only_as_long_as_a_repeat_could_fall_within_it(monkeypatch):
    def burst(seconds, address):
        return dict(rule_id="AUTH_FAILURE_BURST", severity="HIGH", observed_at=(NOW + timedelta(seconds=seconds))
                    .isoformat(), subject=address, message="placeholder", evidence=dict(source=address),
                    identity=address)
    _, cursor = re_.auth_signals(dict(findings=[burst(0, "198.51.100.1")]), None)
    for seconds, decided in ((40 * 60, False), (59 * 60, False), (61 * 60, True)):
        signals, _ = re_.auth_signals(dict(findings=[burst(seconds, "198.51.100.1")]), cursor)
        assert bool(signals) is decided, f"a repeat {seconds // 60} min after it, within the hour: held back"
    _, cursor = re_.auth_signals(dict(findings=[burst(0, "198.51.100.1"), burst(4000, "198.51.100.2")]), None)
    assert list(cursor["recent"]) == ["AUTH_FAILURE_BURST:198.51.100.2"], "the first is past any repeat's cooldown"
    signals, _ = re_.auth_signals(dict(findings=[burst(4100, "198.51.100.2"), burst(4100, "198.51.100.3")]), cursor)
    assert [s.entities["address"] for s in signals] == [{"198.51.100.3"}]
    monkeypatch.setattr(re_, "MAX_AUTH_RECENT", 2)
    _, cursor = re_.auth_signals(dict(findings=[burst(n, f"198.51.100.{n + 10}") for n in range(5)]), None)
    assert sorted(cursor["recent"]) == ["AUTH_FAILURE_BURST:198.51.100.13", "AUTH_FAILURE_BURST:198.51.100.14"]
    signals, _ = re_.auth_signals(dict(findings=[burst(10, "198.51.100.1")]), dict(at=re_._iso(NOW), keys=[]))
    assert len(signals) == 1, "a cursor from before this was kept still works"
