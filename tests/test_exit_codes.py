"""The scheduler counts exit 1 as a run that found something (SuccessExitStatus=1). So an error, including alerts
that could not be sent, an undelivered heartbeat and an unexpected exception, must exit 2, or a broken job looks
healthy."""
from __future__ import annotations

import pytest

from megalodon import cli
from megalodon.config import load_settings
from megalodon.validation import ValidationError

FINDING = dict(rule_id="X_FOUND", severity="HIGH", techniques=["T1000"], subject="s", detail="d", summary="s",
               change="added", category="cron", location="/etc/cron.d/x", technique="T1053.003", log="/var/log/x")


def code(argv):
    try:
        cli.entry(argv)
    except SystemExit as exit_:
        return exit_.code
    return None


@pytest.fixture
def broken_settings(tmp_path):
    settings = tmp_path / "settings.toml"
    settings.write_text("[alerts\nenabled = true\n")      # does not parse
    return settings


@pytest.mark.parametrize("argv, module, function", [
    (["tamper", "check"], "megalodon.tamper", "check"),
    (["persistence", "check"], "megalodon.persistence_watch", "check"),
    (["logwatch", "check"], "megalodon.log_integrity", "check"),
    (["hardening", "check"], "megalodon.hardening_drift", "check"),
    (["packages", "check"], "megalodon.package_sources", "check"),
    (["secrets", "check"], "megalodon.exposed_secrets", "check"),
    (["boot", "check"], "megalodon.boot_integrity", "check"),
    (["ebpf", "check"], "megalodon.ebpf_watch", "check"),
    (["binaries", "check"], "megalodon.binary_integrity", "check"),
    (["vulns", "check"], "megalodon.vuln_check", "check"),
    # Where systemd is missing, the crontab runs these checks in place of the watches.
    (["listeners", "check"], "megalodon.listener_watch", "check"),
    (["webroot", "check"], "megalodon.webroot_watch", "check"),
    (["containers", "check"], "megalodon.container_watch", "check"),
    (["logins", "check"], "megalodon.login_watch", "check"),
    (["rootkit", "check"], "megalodon.rootkit_check", "check"),
])
def test_findings_whose_alert_cannot_be_sent_are_an_error(argv, module, function, broken_settings, monkeypatch,
                                                          capsys):
    import importlib
    monkeypatch.setattr(importlib.import_module(module), function, lambda *a, **k: dict(findings=[FINDING]))
    assert code([*argv, "--alert", "--config", str(broken_settings)]) == 2
    assert "alerts unavailable" in capsys.readouterr().err
    # Without --alert, findings are findings.
    assert code(argv) == 1


def test_a_settings_file_that_does_not_parse_is_a_settings_error(broken_settings):
    with pytest.raises(ValidationError, match="not valid TOML"):
        load_settings(broken_settings)


def test_an_unexpected_error_exits_2_with_its_traceback(monkeypatch, capsys):
    from megalodon import tamper

    def broken(*a, **k):
        raise RuntimeError("something unexpected")
    monkeypatch.setattr(tamper, "check", broken)
    assert code(["tamper", "check"]) == 2
    err = capsys.readouterr().err
    assert "Traceback" in err and "RuntimeError: something unexpected" in err
    with pytest.raises(RuntimeError):            # in-process callers still see the exception
        cli.main(["tamper", "check"])


def test_the_command_and_python_m_megalodon_both_go_through_entry():
    import tomllib
    from pathlib import Path
    root = Path(cli.__file__).resolve().parents[1]
    scripts = tomllib.loads((root / "pyproject.toml").read_text())["project"]["scripts"]
    assert scripts["megalodon"] == "megalodon.cli:entry"
    assert "entry()" in (root / "megalodon/__main__.py").read_text()


def test_a_heartbeat_that_was_not_delivered_is_an_error(monkeypatch, capsys):
    from megalodon import tamper
    monkeypatch.setattr(tamper, "heartbeat", lambda: (dict(url="https://monitor.invalid/ping"),
                                                      dict(sequence=7, findings=[])))
    monkeypatch.setattr(tamper, "destinations", lambda settings: [settings["url"]])

    def refused(settings, body):
        raise OSError("connection refused")
    monkeypatch.setattr(tamper, "send", refused)
    assert code(["heartbeat", "send"]) == 2
    assert "was not delivered" in capsys.readouterr().err
    monkeypatch.setattr(tamper, "destinations", lambda settings: [settings["url"], "https://second.invalid/p"])
    assert code(["heartbeat", "send"]) == 2, "with several destinations too"


def test_an_evidence_digest_whose_alert_cannot_be_sent_is_an_error(broken_settings, tmp_path, monkeypatch, capsys):
    from megalodon import evidence
    monkeypatch.setattr(evidence, "collect", lambda **k: dict(output=str(tmp_path / "bundle"), files=[]))
    assert code(["evidence", "collect", "--output", str(tmp_path / "bundle"), "--alert",
                 "--config", str(broken_settings)]) == 2
    assert "alerts unavailable" in capsys.readouterr().err
