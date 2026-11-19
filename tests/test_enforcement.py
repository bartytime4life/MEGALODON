"""Enforcement: only allowed decisions, made under the pinned policy and recent, are carried out, once, and undone."""
from __future__ import annotations

from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from megalodon import response_engine as re_


def paths(tmp_path):
    return dict(policy=tmp_path / "response.toml", ledger=tmp_path / "ledger.jsonl", state=tmp_path / "state.json",
                enforce=tmp_path / "enforce.toml", journal=tmp_path / "enforced.jsonl",
                enforce_state=tmp_path / "enforce-state.json", quarantine=tmp_path / "quarantine")


def decide(p, signals, now=None):
    re_.run(policy_path=p["policy"], ledger=p["ledger"], state_path=p["state"], signals=signals, protected=set(),
            now=now)


def enable(p, actions, playbooks, **extra):
    text = p["enforce"].read_text()
    text = text.replace("enabled = false", "enabled = true").replace("actions = []", f"actions = {json.dumps(actions)}")
    text = text.replace("playbooks = []", f"playbooks = {json.dumps(playbooks)}")
    text = text.replace(f'quarantine_folder = "{en.DEFAULT_QUARANTINE}"', f'quarantine_folder = "{p["quarantine"]}"')
    for key, value in extra.items():
        text = text.replace(f"{key} = ", f"{key} = {value}\n# was: {key} = ", 1)
    p["enforce"].write_text(text)


def enforce(p, **kw):
    return en.run(policy_path=p["enforce"], response_policy=p["policy"], ledger=p["ledger"], journal=p["journal"],
                  state_path=p["enforce_state"], protected=set(), **kw)


@pytest.fixture
def p(tmp_path):
    p = paths(tmp_path)
    re_.write_default_policy(p["policy"])
    en.init(p["enforce"], response_policy=p["policy"])
    return p


def state_of(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    return text[text.rindex(")") + 2]


@pytest.fixture
def child():
    process = subprocess.Popen(["sleep", "60"])
    time.sleep(0.1)
    yield process
    process.kill()
    process.wait()


def memory_signal(process, start=None):
    text = Path(f"/proc/{process.pid}/stat").read_text()
    started = int(text[text.rindex(")") + 2:].split()[19])
    exe = os.readlink(f"/proc/{process.pid}/exe")
    report = dict(checked_at="2026-11-19T00:00:00Z", findings=[dict(
        rule_id="MEMORY_ELF_IN_ANONYMOUS", severity="CRITICAL", subject=f"memory:{process.pid}:{start}",
        detail="an ELF image in anonymous memory",
        evidence=dict(processes=[dict(pid=process.pid, start=started if start is None else start, program=exe)]))])
    return re_.memory_signals(report)


def test_off_by_default_and_a_strict_policy(p):
    assert "enabled = false" in p["enforce"].read_text() and oct(p["enforce"].stat().st_mode & 0o777) == "0o600"
    assert enforce(p)["enabled"] is False
    assert not p["journal"].with_name("enforced.jsonl.lock").exists(), "a run that is off creates nothing"
    os.chmod(p["enforce"], 0o666)                                   # anyone could turn enforcement on
    with pytest.raises(re_.ResponseError, match="writable only by you"):
        en.load_policy(p["enforce"])
    os.chmod(p["enforce"], 0o600)
    p["enforce"].write_text(p["enforce"].read_text().replace("actions = []", 'actions = ["wipe_disk"]'))
    with pytest.raises(en.EnforcementError, match="actions may list only"):
        en.load_policy(p["enforce"])


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"), reason="needs pidfd")
def test_the_exact_process_is_suspended_once_and_resumed(p, child):
    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    decide(p, memory_signal(child))
    result = enforce(p)
    assert [r["action"] for r in result["applied"]] == ["suspend_process"]
    for _ in range(50):
        if state_of(child.pid) == "T":
            break
        time.sleep(0.02)
    assert state_of(child.pid) == "T", "stopped, not killed"
    assert enforce(p)["applied"] == [], "carried out once"
    journal = en.entries(p["journal"])
    assert oct(p["journal"].stat().st_mode & 0o777) == "0o600" and journal[0]["status"] == "applied"
    assert [r["id"] for r in en.active(p["journal"])] == [result["applied"][0]["id"]]
    en.undo(result["applied"][0]["id"], journal=p["journal"])
    time.sleep(0.05)
    assert state_of(child.pid) in "SR" and en.active(p["journal"]) == []
    with pytest.raises(en.EnforcementError, match="no applied"):
        en.undo(result["applied"][0]["id"], journal=p["journal"])


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "pidfd_open"), reason="needs pidfd")
def test_a_different_start_time_is_never_signalled(p, child):
    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    decide(p, memory_signal(child, start=1))                         # the PID now names another process
    result = enforce(p)
    assert result["applied"] == [] and "no longer the one decided on" in result["refused"][0]["reason"]
    assert state_of(child.pid) in "SR"


def test_refused_unless_pinned_recent_and_listed(p, child):
    enable(p, ["suspend_process"], ["some-other-playbook"])
    decide(p, memory_signal(child))
    assert "not listed" in enforce(p)["refused"][0]["reason"]
    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    p["enforce"].write_text(p["enforce"].read_text().replace('["some-other-playbook"]', '["code-loaded-into-memory"]'))
    decide(p, memory_signal(child, start=2))
    later = en._now() + timedelta(minutes=30)
    assert "too old" in enforce(p, now=later)["refused"][0]["reason"]
    with open(p["policy"], "a") as policy:                          # the response policy is edited after review
        policy.write("# edited\n")
    decide(p, memory_signal(child, start=3))
    assert "other than the pinned one" in enforce(p)["refused"][0]["reason"]
    assert state_of(child.pid) in "SR"


def test_a_file_is_quarantined_and_restored(p, tmp_path):
    shell = tmp_path / "uploads/shell.php"
    shell.parent.mkdir()
    shell.write_text("<?php echo 1; ?>")
    os.chmod(shell, 0o640)
    digest = hashlib.sha256(shell.read_bytes()).hexdigest()
    enable(p, ["quarantine_file"], ["web-shell-file"])
    report = dict(checked_at="2026-11-19T00:00:00Z", findings=[dict(rule_id="WEB_SHELL_PATTERN", severity="HIGH",
                                                                    path=str(shell))])
    decide(p, re_.path_signals(report, "webroot", "path"))
    result = enforce(p)
    assert [r["action"] for r in result["applied"]] == ["quarantine_file"] and not shell.exists()
    kept = Path(result["applied"][0]["undo"]["kept"])
    assert stat_mode(kept) == 0 and result["applied"][0]["undo"]["sha256"] == digest
    en.undo(result["applied"][0]["id"], journal=p["journal"])
    assert hashlib.sha256(shell.read_bytes()).hexdigest() == digest and stat_mode(shell) == 0o640
    assert not kept.exists()


def stat_mode(path):
    return os.stat(path).st_mode & 0o777


class Commands:
    def __init__(self, missing=()):
        self.ran, self.missing = [], set(missing)

    def __call__(self, argv, data=None):
        self.ran.append(list(argv))
        if argv[:3] == ["nft", "list", "table"] and "table" in self.missing:
            self.missing.discard("table")
            return SimpleNamespace(returncode=1, stdout="", stderr="No such file or directory")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def test_an_address_block_expires_and_is_undone(p):
    commands = Commands(missing=["table"])
    enable(p, ["block_address"], ["dropped-tool-phoning-home"])
    report = dict(checked_at="2026-11-19T00:00:00Z", findings=[dict(
        rule_id="OUTBOUND_FROM_TEMPORARY", severity="HIGH", program="/tmp/x", address="93.184.216.250", port=443,
        protocol="tcp", detail="a dropped tool", evidence=dict(processes=[]))])
    decide(p, re_.egress_signals(report))
    result = enforce(p, executor=en.Executor(run=commands, quarantine=p["quarantine"]))
    assert [r["action"] for r in result["applied"]] == ["block_address"]
    assert commands.ran[:2] == [["nft", "list", "table", "inet", "megalodon"], ["nft", "-f", "-"]]
    assert commands.ran[2] == ["nft", "add", "element", "inet", "megalodon", "blocked_v4", "{", "93.184.216.250",
                               "timeout", "3600s", "}"], "a block that expires by itself"
    # A second block uses the table that is there; loading it again would add its rules again.
    en.Executor(run=commands).block_address("93.184.216.251", dict(playbook="x", actions=[]))
    assert commands.ran[-2:] == [["nft", "list", "table", "inet", "megalodon"],
                                 ["nft", "add", "element", "inet", "megalodon", "blocked_v4", "{", "93.184.216.251",
                                  "timeout", "3600s", "}"]]
    en.undo(result["applied"][0]["id"], journal=p["journal"], executor=en.Executor(run=commands))
    assert commands.ran[-1] == ["nft", "delete", "element", "inet", "megalodon", "blocked_v4", "{", "93.184.216.250",
                                "}"]


def test_accounts_are_locked_with_their_expiry_and_root_never(tmp_path):
    commands = Commands()
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/shadow").write_text("nobody:*:19000:0:99999:7:::\nsvc:!:19000:0:99999:7::20000:\n")
    executor = en.Executor(root=str(tmp_path), run=commands)
    with pytest.raises(en.EnforcementError, match="UID 0"):
        executor.lock_account("root", {})
    undo = executor.lock_account("nobody", {})
    assert commands.ran[-1] == ["usermod", "--lock", "--expiredate", "1", "nobody"] \
        and undo == dict(previous_expiry="", password_was_locked=False)
    executor.undo_lock_account(dict(target="nobody", undo=undo))
    assert commands.ran[-1] == ["usermod", "--unlock", "--expiredate", "", "nobody"]


def test_rate_limit_dry_run_and_stage0(p, monkeypatch):
    calls = []

    class Recording(en.Executor):
        def suspend_process(self, target, decision):
            calls.append(target)
            return {}
    enable(p, ["suspend_process"], ["code-loaded-into-memory"], max_actions_per_hour="1")
    fake = SimpleNamespace(pid=os.getpid())
    signals = memory_signal(fake) + [s for s in memory_signal(fake, start=4)]
    decide(p, signals)
    preview = enforce(p, dry_run=True)
    assert [r["status"] for r in preview["applied"]] == ["would_enforce", "would_enforce"] and calls == []
    result = enforce(p, executor=Recording())
    assert len(calls) == 1 and "rate limit" in result["refused"][0]["reason"]
    from megalodon import execution_boundary
    monkeypatch.setattr(execution_boundary, "_stage0_selected", True)
    p["journal"].with_name("enforced.jsonl.lock").unlink()
    with pytest.raises(en.EnforcementError, match="Stage 0"):
        enforce(p, executor=Recording())
    with pytest.raises(en.EnforcementError, match="Stage 0"):
        en.undo("anything", journal=p["journal"])
    assert not p["journal"].with_name("enforced.jsonl.lock").exists(), "refused before the lock file is created"


def test_the_cli(p, capsys, monkeypatch):
    from megalodon.cli import main
    monkeypatch.setattr(en, "DEFAULT_JOURNAL", str(p["journal"]))
    with pytest.raises(SystemExit) as exit_:
        main(["enforce", "list", "--policy", str(p["enforce"])])
    assert exit_.value.code == 0 and json.loads(capsys.readouterr().out) == dict(active=[])


def test_a_folder_swapped_for_a_symlink_is_never_followed(p, tmp_path):
    # A stand-in for a protected folder, reached through an upload subfolder replaced by a symlink.
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "accounts").write_text("placeholder\n")
    (tmp_path / "uploads").mkdir()
    os.symlink(protected, tmp_path / "uploads/sub")
    enable(p, ["quarantine_file"], ["web-shell-file"])
    report = dict(checked_at="2026-11-19T00:00:00Z", findings=[dict(rule_id="WEB_SHELL_PATTERN", severity="HIGH",
                                                                    path=str(tmp_path / "uploads/sub/accounts"))])
    decide(p, re_.path_signals(report, "webroot", "path"))
    result = enforce(p)
    assert result["applied"] == [] and "symlink" in result["refused"][0]["reason"]
    assert (protected / "accounts").read_text() == "placeholder\n", "the file behind the symlink is untouched"
    assert not p["quarantine"].exists() or not any(p["quarantine"].iterdir())


def test_undo_never_restores_through_a_symlinked_folder(p, tmp_path):
    shell = tmp_path / "uploads/shell.php"
    shell.parent.mkdir()
    shell.write_text("<?php echo 1; ?>")
    enable(p, ["quarantine_file"], ["web-shell-file"])
    report = dict(checked_at="2026-11-19T00:00:00Z", findings=[dict(rule_id="WEB_SHELL_PATTERN", severity="HIGH",
                                                                    path=str(shell))])
    decide(p, re_.path_signals(report, "webroot", "path"))
    record = enforce(p)["applied"][0]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "uploads").rmdir()
    os.symlink(elsewhere, tmp_path / "uploads")
    with pytest.raises(en.EnforcementError, match="symlink"):
        en.undo(record["id"], journal=p["journal"])
    assert list(elsewhere.iterdir()) == [] and Path(record["undo"]["kept"]).exists()


def test_a_password_locked_before_stays_locked_after_undo(tmp_path):
    commands = Commands()
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/shadow").write_text("nobody:!placeholder:19000:0:99999:7::20000:\n")
    executor = en.Executor(root=str(tmp_path), run=commands)
    undo = executor.lock_account("nobody", {})
    assert undo == dict(previous_expiry="20000", password_was_locked=True)
    executor.undo_lock_account(dict(target="nobody", undo=undo))
    assert commands.ran[-1] == ["usermod", "--expiredate", "20000", "nobody"], "the expiry comes back, the lock stays"


def test_one_run_at_a_time(p):
    import fcntl
    held = []

    class Probe(en.Executor):
        def suspend_process(self, target, decision):
            # A second run trying now would wait: the lock is held from reading the state to writing it.
            fd = os.open(str(p["journal"]) + ".lock", os.O_RDWR)
            try:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held.append(True)
            finally:
                os.close(fd)
            return {}
    enable(p, ["suspend_process"], ["code-loaded-into-memory"])
    decide(p, memory_signal(SimpleNamespace(pid=os.getpid())))
    assert len(enforce(p, executor=Probe())["applied"]) == 1 and held == [True]
    fd = os.open(str(p["journal"]) + ".lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)       # released once the run is done
    finally:
        os.close(fd)


def test_the_enforce_service_can_write_the_account_files():
    from megalodon import schedule
    jobs = {job.name: job for job in schedule.JOBS}
    enforce_unit = schedule.units(jobs["enforce"], ["megalodon"], True)["megalodon-enforce.service"]
    assert "ProtectSystem=full" in enforce_unit and "ReadWritePaths=/etc\n" in enforce_unit
    assert "ReadWritePaths" not in schedule.units(jobs["hardening"], ["megalodon"], True)["megalodon-hardening.service"]
