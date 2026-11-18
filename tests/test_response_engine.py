"""Response engine, shadow mode: policy, correlation, playbooks, guards, ledger, and that nothing is carried out."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import stat

import pytest

from megalodon import response_engine as re_

NOW = datetime(2026, 11, 18, 22, 0, tzinfo=timezone.utc)
ATTACKER, C2 = "203.0.114.9", "203.0.114.77"


@pytest.fixture
def paths(tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    return dict(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
                protected=set())


def edit_policy(paths, old, new):
    path = paths["policy_path"]
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new), encoding="utf-8")


def process_signal(flag="STDIO_SHELL_ON_NETWORK", exe="/tmp/.cache/agent", remotes=(f"{ATTACKER}:4444",)):
    review = {"reviewed_at": "2026-11-18T22:00:00Z", "programs": [
        {"program": "agent", "executable": exe, "flags": [flag], "remotes": list(remotes)}]}
    return re_.process_signals(review)


def network_signal(rule, target, row=1, severity="HIGH", src="192.168.1.20"):
    return re_.Signal(f"network:{row}", "network", rule, severity, "2026-11-18T22:00:00Z", rule,
                      re_._entities(address=[target], peer=[src, target]))


def ledger(paths):
    return [json.loads(line) for line in Path(paths["ledger"]).read_text().splitlines()]


def actions(decision):
    return [(a["action"], a["target"], a["status"]) for a in decision["actions"]]


# ------------------------------------------------------------- policy

def test_default_policy_is_private_and_only_shadow_mode_exists(paths):
    policy = re_.load_policy(paths["policy_path"])
    assert len(policy.playbooks) == 8 and stat.S_IMODE(paths["policy_path"].stat().st_mode) == 0o600
    with pytest.raises(re_.ResponseError, match="exists"):
        re_.write_default_policy(paths["policy_path"])
    for old, new, message in [
            ('mode = "shadow"', 'mode = "enforce"', "only shadow mode exists"),
            ('"collect_evidence", "suspend_process", "block_address", "notify"]', '"run_command"]', "actions must"),
            ('min_severity = "MEDIUM"', 'min_severity = "URGENT"', "min_severity"),
            ("correlation_minutes = 30", "correlation_minutes = 30\nauto_apply = true", "unsupported settings"),
            ('name = "ransomware"', 'name = "reverse-shell"', "distinct"),
            ("never_touch_addresses = []", 'never_touch_addresses = ["nope"]', "invalid address")]:
        original = paths["policy_path"].read_text(encoding="utf-8")
        edit_policy(paths, old, new)
        with pytest.raises(re_.ResponseError, match=message):
            re_.load_policy(paths["policy_path"])
        paths["policy_path"].write_text(original, encoding="utf-8")
    os.chmod(paths["policy_path"], 0o622)
    with pytest.raises(re_.ResponseError, match="writable only by you"):
        re_.load_policy(paths["policy_path"])


# ------------------------------------------------------------- decisions

def test_a_reverse_shell_gets_evidence_suspension_and_a_block(paths):
    result = re_.run(signals=process_signal(), now=NOW, **paths)
    assert (result["decisions"], result["carried_out"]) == (1, 0)
    decision = ledger(paths)[0]
    assert decision["playbook"] == "reverse-shell" and decision["mode"] == "shadow" and decision["carried_out"] is False
    assert actions(decision) == [("collect_evidence", None, "would_apply"),
                                 ("suspend_process", "/tmp/.cache/agent", "would_apply"),
                                 ("block_address", ATTACKER, "would_apply"),
                                 ("notify", None, "would_apply")]
    assert decision["actions"][2]["minutes"] == 15
    assert decision["policy_sha256"] == re_.load_policy(paths["policy_path"]).digest


def test_guards_refuse_what_would_cut_off_or_break_the_machine(paths):
    paths["protected"] = {"8.8.8.8"}
    edit_policy(paths, "never_touch_addresses = []", 'never_touch_addresses = ["203.0.115.0/24"]')
    signals = (process_signal(exe="/usr/sbin/sshd", remotes=["8.8.8.8:53"])
               + process_signal(flag="SHELL_HOLDS_SOCKET", exe="/bin/bash", remotes=["192.168.1.30:4444"])
               + process_signal(flag="PIPED_TO_SHELL", exe="/home/u/x", remotes=["203.0.115.8:80"]))
    re_.run(signals=signals, now=NOW, **paths)
    refused = {(a["action"], a["target"]): a["guard"] for d in ledger(paths) for a in d["actions"]
               if a["status"] == "refused"}
    assert "system program" in refused[("suspend_process", "/usr/sbin/sshd")]
    assert "gateway, DNS server or own address" in refused[("block_address", "8.8.8.8")]
    assert "not a public address" in refused[("block_address", "192.168.1.30")]
    assert "never_touch_addresses" in refused[("block_address", "203.0.115.8")]
    assert ("suspend_process", "/bin/bash") not in refused


def test_corroboration_turns_a_network_signal_into_an_action(paths):
    re_.run(signals=[network_signal("BEACONING", C2)], now=NOW, **paths)
    first = ledger(paths)[0]
    assert first["playbook"] == "command-and-control-or-exfiltration"
    assert ("block_address", C2, "refused") in actions(first) and first["incident"]["corroborated"] is False
    assert "second, independent source" in first["actions"][1]["guard"]
    # A host finding about the same address joins the incident.
    re_.run(signals=process_signal(remotes=[f"{C2}:443"]), now=NOW + timedelta(minutes=5), **paths)
    re_.run(signals=[network_signal("BEACONING", C2, row=2)], now=NOW + timedelta(minutes=6), **paths)
    third = ledger(paths)[-1]
    assert third["incident"]["corroborated"] is True and third["incident"]["sources"] == ["network", "process_review"]
    assert ("block_address", C2, "would_apply") in actions(third)


def test_each_finding_is_decided_once_and_rate_limits_hold(paths):
    re_.run(signals=process_signal(), now=NOW, **paths)
    assert re_.run(signals=process_signal(), now=NOW + timedelta(minutes=10), **paths)["decisions"] == 0
    assert re_.run(signals=process_signal(), now=NOW + timedelta(hours=25), **paths)["decisions"] == 1, \
        "the same finding a day later is decided again"
    edit_policy(paths, "max_actions_per_hour = 20", "max_actions_per_hour = 3")
    signals = [s for i in range(3) for s in process_signal(exe=f"/tmp/t{i}", remotes=[f"203.0.114.{20 + i}:1"])]
    re_.run(signals=signals, now=NOW + timedelta(days=3), **paths)
    statuses = [a["status"] for d in ledger(paths)[-3:] for a in d["actions"]
                if a["action"] in ("suspend_process", "block_address")]
    assert statuses == ["would_apply", "would_apply", "would_apply", "refused", "refused", "refused"]
    assert "rate limit" in ledger(paths)[-1]["actions"][1]["guard"]


def test_backdoor_accounts_are_locked_but_never_root(paths):
    report = {"checked_at": "2026-11-18T22:00:00Z", "findings": [
        {"change": "added", "category": "account", "location": "svc-backup", "severity": "CRITICAL"},
        {"change": "changed", "category": "account", "location": "root", "severity": "CRITICAL"},
        {"change": "added", "category": "cron", "location": "/etc/cron.d/x", "severity": "CRITICAL"}]}
    re_.run(signals=re_.persistence_signals(report), now=NOW, **paths)
    decisions = ledger(paths)
    assert [d["signal"]["entities"].get("account") for d in decisions] == [["svc-backup"], ["root"]], \
        "the cron finding matches no account playbook"
    assert ("lock_account", "svc-backup", "would_apply") in actions(decisions[0])
    assert ("lock_account", "root", "refused") in actions(decisions[1])


def test_quarantine_never_touches_system_files(paths):
    with open(paths["policy_path"], "a", encoding="utf-8") as out:
        out.write('\n[[response.playbook]]\nname = "dropped-program"\nrules = ["PROGRAM_ADDED"]\n'
                  'min_severity = "MEDIUM"\nactions = ["quarantine_file"]\n')
    report = {"checked_at": "", "findings": [{"rule_id": "PROGRAM_ADDED", "severity": "HIGH", "path": "/usr/bin/x"},
                                             {"rule_id": "PROGRAM_ADDED", "severity": "HIGH", "path": "/tmp/x"}]}
    re_.run(signals=re_.path_signals(report, "binaries", "path"), now=NOW, **paths)
    assert [actions(d)[0] for d in ledger(paths)] == [("quarantine_file", "/usr/bin/x", "refused"),
                                                     ("quarantine_file", "/tmp/x", "would_apply")]


# ------------------------------------------------------------- sources

def test_network_detections_are_read_once_from_the_audit_store(paths, tmp_path):
    from megalodon.capture import iter_sample
    from megalodon.config import Settings
    from megalodon.service import MegalodonService
    from megalodon.storage import Store
    settings = Settings(db_path=tmp_path / "audit.db")
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        for event in iter_sample(include_demo_threat=True):
            service.process(event)
    edit_policy(paths, 'audit_db = "data/megalodon.db"', f'audit_db = "{settings.db_path}"')
    edit_policy(paths, "process_review = true", "process_review = false")
    for name in ("listeners", "persistence", "binaries", "logwatch"):
        edit_policy(paths, f'{name}_manifest = "~/', f'{name}_manifest = "" # ~/')
    first = re_.run(now=NOW, **paths)
    assert first["signals"] > 0 and first["gaps"] == []
    assert {d["signal"]["source"] for d in ledger(paths)} == {"network"}
    assert re_.run(now=NOW, **paths)["signals"] == 0, "the cursor moved past every detection"


def test_piped_findings_such_as_ransomware_are_decided(paths):
    line = json.dumps({"schema": "megalodon-ransomware-finding-v1", "rule_id": "RANSOMWARE_ENCRYPTION",
                       "severity": "CRITICAL", "message": "files encrypted", "evidence": {
                           "folder": "/home/u/Documents", "processes": [{"pid": 4242, "program": "/tmp/enc"}]}})
    result = re_.ingest([line, "not json", "{}"], now=NOW, **paths)
    assert result["refused_lines"] == 2 and result["decisions"] == 1
    assert ("suspend_process", "/tmp/enc", "would_apply") in actions(ledger(paths)[0])


# ------------------------------------------------------------- ledger, report, and no action

def test_ledger_and_report(paths):
    re_.run(signals=process_signal(), now=NOW, **paths)
    assert stat.S_IMODE(Path(paths["ledger"]).stat().st_mode) == 0o600
    summary = re_.report(ledger=paths["ledger"], now=NOW + timedelta(hours=1))
    assert summary["decisions"] == 1 and summary["by_playbook"] == {"reverse-shell": 1}
    assert summary["actions"]["suspend_process would_apply"] == 1
    assert summary["top_targets"] == {f"block_address {ATTACKER}": 1, "suspend_process /tmp/.cache/agent": 1}
    assert re_.report(ledger=paths["ledger"], now=NOW + timedelta(days=30))["decisions"] == 0
    os.chmod(paths["ledger"], 0o644)
    with pytest.raises(re_.ResponseError, match="mode-600"):
        re_.run(signals=process_signal(exe="/tmp/other"), now=NOW, **paths)


def test_the_engine_cannot_act(paths, monkeypatch):
    source = inspect.getsource(re_)
    for forbidden in ("subprocess", "os.kill", "killpg", "import signal", "os.system", "popen", "pkexec", "nft ",
                      "shutil", "os.rename", "os.chmod", "os.chown", "usermod", "passwd -l", "systemctl"):
        assert forbidden not in source, forbidden

    def refuse(*args, **kwargs):
        raise AssertionError("the shadow engine tried to act")
    import subprocess
    for name in ("kill", "killpg", "system"):
        monkeypatch.setattr(os, name, refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    result = re_.run(signals=process_signal(), now=NOW, **paths)
    assert result["would_apply"] == 4 and result["carried_out"] == 0


def test_cli(paths, monkeypatch, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    files = ["--policy", str(paths["policy_path"]), "--ledger", str(paths["ledger"]), "--state",
             str(paths["state_path"])]
    monkeypatch.setattr(re_, "collect", lambda policy, state, now, root="/": (process_signal(), []))
    assert code("respond", "run", *files) == 0
    assert json.loads(capsys.readouterr().out)["would_apply"] == 4
    assert code("respond", "report", "--ledger", str(paths["ledger"])) == 0
    assert json.loads(capsys.readouterr().out)["decisions"] == 1
    assert code("respond", "init", "--policy", str(paths["policy_path"])) == 2
    edit_policy(paths, 'mode = "shadow"', 'mode = "enforce"')
    assert code("respond", "run", *files) == 2


def test_cli_ingest_decides_each_line_as_it_arrives(paths, monkeypatch, capsys):
    import io

    from megalodon.cli import main
    files = ["--policy", str(paths["policy_path"]), "--ledger", str(paths["ledger"]), "--state",
             str(paths["state_path"])]
    decided = []
    real = re_.ingest

    def spy(lines, **options):
        decided.append(len(list(lines)) if not isinstance(lines, list) else len(lines))
        return real(lines, **options)
    monkeypatch.setattr(re_, "ingest", spy)
    finding = {"rule_id": "RANSOMWARE_ENCRYPTION", "severity": "CRITICAL",
               "evidence": {"processes": [{"program": "/tmp/enc"}]}}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(finding) + "\n\n" + json.dumps(
        dict(finding, message="again")) + "\n"))
    with pytest.raises(SystemExit) as exit_:
        main(["respond", "ingest", *files])
    assert exit_.value.code == 0 and decided == [1, 1]
    assert [json.loads(line)["decisions"] for line in capsys.readouterr().out.splitlines()] == [1, 1]


def test_a_large_state_is_read_back(paths):
    signals = [network_signal("HOST_SWEEP", f"203.0.{110 + i // 250}.{i % 250 + 1}", row=i, severity="LOW",
                              src=f"10.{i // 250}.{i % 250}.9") for i in range(1500)]
    re_.run(signals=signals, now=NOW, **paths)
    assert Path(paths["state_path"]).stat().st_size > re_.MAX_POLICY_BYTES
    assert re_.run(signals=process_signal(), now=NOW, **paths)["decisions"] == 1


def test_gaps_reported_by_the_source_checks_are_kept(paths, monkeypatch):
    from megalodon import listener_watch, process_network
    monkeypatch.setattr(listener_watch, "check", lambda manifest: {
        "findings": [], "gaps": ["no visible program owns tcp:2024"], "checked_at": ""})
    monkeypatch.setattr(process_network, "review", lambda root="/": {
        "programs": [], "gaps": ["A socket table was not fully read"]})
    policy = re_.load_policy(paths["policy_path"])
    policy = re_.Policy(**{**policy.__dict__, "sources": {"audit_db": "", "process_review": True,
                                                         "listeners_manifest": "/x/listeners.json"}})
    signals, gaps = re_.collect(policy, {}, NOW)
    assert gaps == ["process_review: A socket table was not fully read",
                    "listeners: no visible program owns tcp:2024"]


def test_a_finding_that_links_two_incidents_corroborates_both(paths):
    other = "203.0.114.78"
    signals = [network_signal("BEACONING", C2, row=1, src="192.168.1.21"),
               network_signal("BEACONING", other, row=2, src="192.168.1.22"),
               *process_signal(remotes=[f"{C2}:443", f"{other}:443"])]
    re_.run(signals=signals, now=NOW, **paths)
    beacons = [d for d in ledger(paths) if d["signal"]["rule_id"] == "BEACONING"]
    assert [d["incident"]["corroborated"] for d in beacons] == [True, True]
    assert len({d["incident"]["id"] for d in ledger(paths)}) == 1
    assert {a[1] for d in beacons for a in actions(d) if a[0] == "block_address" and a[2] == "would_apply"} == \
        {C2, other}


def test_a_host_finding_still_present_keeps_its_incident_open(paths):
    host = process_signal(remotes=[f"{C2}:443"])
    re_.run(signals=host, now=NOW, **paths)
    later = NOW + timedelta(minutes=31)
    re_.run(signals=host + [network_signal("BEACONING", C2, row=9)], now=later, **paths)
    beacon = ledger(paths)[-1]
    assert beacon["signal"]["rule_id"] == "BEACONING" and beacon["incident"]["corroborated"] is True
    assert ("block_address", C2, "would_apply") in actions(beacon)
    assert len(ledger(paths)) == 2, "the repeated host finding is not decided again"
