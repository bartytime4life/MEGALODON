"""Recovery status uses real CLI/rendering code, with all action and service effects replaced."""
from configparser import ConfigParser
from types import SimpleNamespace

import pytest

from megalodon import enforcement as en
from megalodon import schedule
from megalodon import timeline


@pytest.fixture(autouse=True)
def no_process_or_service_effects(monkeypatch):
    def refused(*args, **kwargs):
        pytest.fail("recovery-status tests must not signal, journal, or control a service")
    monkeypatch.setattr(en.Executor, "_signal", refused)
    monkeypatch.setattr(en, "_journal", refused)
    monkeypatch.setattr(schedule, "_systemctl", refused)


def successful_codes(job_name):
    job = next(job for job in schedule.JOBS if job.name == job_name)
    unit = schedule.units(job, ["megalodon"], True)[f"megalodon-{job_name}.service"]
    # systemd permits repeated directives such as ReadWritePaths.
    parsed = ConfigParser(interpolation=None, strict=False)
    parsed.read_string(unit)
    return {0, *(int(code) for code in parsed["Service"].get("SuccessExitStatus", "").split())}


@pytest.mark.parametrize("failed_section", ["expired", "refused"])
def test_failed_recovery_and_actions_are_unsuccessful_service_exits(tmp_path, monkeypatch, capsys,
                                                                 failed_section):
    from megalodon.cli import _enforce
    policy = tmp_path / "enforce.toml"
    policy.write_text("synthetic policy; parsing is replaced for this exit-status test")
    result = dict(enabled=False, applied=[], refused=[], expired=[])
    result[failed_section] = [dict(status="failed", reason="synthetic permission failure")]
    monkeypatch.setattr(en, "run", lambda **kwargs: result)

    code = _enforce(SimpleNamespace(policy=policy, enforce_command="run", dry_run=False))

    assert code == 1
    assert '"status": "failed"' in capsys.readouterr().out
    assert code not in successful_codes("enforce"), "systemd must classify this result as a failure"


def test_read_only_checks_keep_their_findings_exit_contract():
    assert 1 in successful_codes("rootkit"), "findings from an observational check remain a successful run"


def test_expiry_text_does_not_claim_timely_resume_or_change_event_identity():
    event = dict(at="2026-11-20T13:00:00Z", kind="undo", action="suspend_process",
                 target="123@45:/synthetic/program", undo_of="pause-a", expired=True)
    before = dict(event)
    identity = timeline.event_id(event)

    text = timeline._line(event)

    assert text.startswith("expiry recorded: suspend_process")
    assert "ended on time" not in text and "resumed" not in text
    assert event == before and timeline.event_id(event) == identity
