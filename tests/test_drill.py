"""megalodon drill: every layer passes, broken layers are reported, alerts are exercised, nothing is left behind."""
from __future__ import annotations

import json
import socket
import sys
import tempfile
from pathlib import Path

import pytest

from megalodon import drill
from megalodon.alerts import AlertDestination, AlertSettings


def by_name(report):
    return {check["name"]: check for check in report["checks"]}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the ransomware check needs inotify")
def test_every_layer_passes_and_nothing_is_left_behind():
    before = set(Path(tempfile.gettempdir()).glob("megalodon-drill-*"))
    report = drill.run()
    checks = by_name(report)
    for name in ("network", "canary", "ransomware", "persistence", "listeners"):
        assert checks[name]["status"] == "passed", checks[name]
    assert checks["network"]["observed"] == drill.NETWORK_RULES
    assert checks["alerts"]["status"] == "skipped"
    assert (report["passed"], report["failed"], report["skipped"]) == (5, 0, 1)
    assert set(Path(tempfile.gettempdir()).glob("megalodon-drill-*")) == before


def test_a_broken_layer_is_reported_and_the_rest_still_run(monkeypatch):
    def broken(work):
        raise RuntimeError("canary layer unavailable")
    monkeypatch.setattr(drill, "_canary", broken)
    monkeypatch.setattr(drill, "_ransomware", lambda work: (["RANSOMWARE_ENCRYPTION"], "partial"))
    checks = by_name(drill.run())
    assert checks["canary"]["status"] == "failed" and "canary layer unavailable" in checks["canary"]["detail"]
    assert checks["ransomware"]["status"] == "failed" and checks["ransomware"]["missing"] == ["RANSOM_NOTE"]
    assert checks["network"]["status"] == "passed" and checks["persistence"]["status"] == "passed"


def test_alerts_are_exercised_against_each_destination(tmp_path):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(5)
        settings = AlertSettings(destinations=(
            AlertDestination(name="siem", kind="syslog", host="127.0.0.1", port=listener.getsockname()[1]),
            AlertDestination(name="broken", kind="webhook", url_file=str(tmp_path / "missing.url"))))
        checks = by_name(drill.run(alert_settings=settings))
        assert listener.recvfrom(4096)[0].startswith(b"<")
    alerts = checks["alerts"]
    assert alerts["expected"] == ["broken", "siem"] and alerts["observed"] == ["siem"]
    assert alerts["status"] == "failed" and alerts["missing"] == ["broken"]
    assert by_name(drill.run(alert_settings=AlertSettings()))["alerts"]["status"] == "skipped"


def test_cli_exit_codes(monkeypatch, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    monkeypatch.setattr(drill, "_ransomware", lambda work: (["RANSOMWARE_ENCRYPTION", "RANSOM_NOTE"], "stubbed"))
    assert code("drill") == 0
    out = capsys.readouterr()
    assert json.loads(out.out)["failed"] == 0 and "PASSED   network" in out.err
    monkeypatch.setattr(drill, "_canary", lambda work: ([], "nothing reported"))
    assert code("drill") == 1
    assert "FAILED   canary" in capsys.readouterr().err
