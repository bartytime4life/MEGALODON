"""HawkScan preparation cannot promote metadata or configuration into execution."""

import builtins
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
from types import SimpleNamespace

import pytest
import yaml

from megalodon import hawkscan_setup as setup
from megalodon.dashboard_setup import SETUP_HTML


UUID = "11111111-2222-4333-8444-555555555555"


@pytest.fixture
def forbid_effects(monkeypatch):
    def denied(*args, **kwargs):
        pytest.fail("HawkScan preparation attempted content, process, network or database work")
    for module, name in [(builtins, "open"), (Path, "open"), (socket, "socket"),
                         (socket, "create_connection"), (subprocess, "run"),
                         (subprocess, "Popen"), (sqlite3, "connect")]:
        monkeypatch.setattr(module, name, denied)


def test_default_plan_remains_held_without_host_probe(monkeypatch, capsys, forbid_effects):
    monkeypatch.setattr(setup, "_executable_status", lambda *a: pytest.fail("plan probed the host"))
    assert setup.main([]) == 0
    text = capsys.readouterr().out
    value = json.loads(text)
    assert value["schema"] == "megalodon-hawkscan-setup-v1"
    assert value["scan_status"] == "held"
    assert value["action_status"] == "not_attempted"
    assert value["software_class"] == "commercial_service"
    assert all(value[key] is False for key in value if key.endswith("_performed"))
    assert len(text.encode()) <= setup.MAX_OUTPUT_BYTES
    value["next_gates"].clear()
    assert setup.setup_plan()["next_gates"]


def test_presence_never_executes_binary_reads_contents_or_credentials(tmp_path, monkeypatch, capsys):
    binary = tmp_path / "hawk"
    binary.write_text("#!/bin/sh\nexit 99\n")
    binary.chmod(0o700)
    # Permit only the one environment lookup owned by this explicit check.
    class Environment:
        def get(self, key):
            assert key == "PATH"
            return str(tmp_path)
    monkeypatch.setattr(setup, "os", SimpleNamespace(environ=Environment()))
    monkeypatch.setattr(setup, "runtime_platform", lambda: "linux")
    def denied(*args, **kwargs):
        pytest.fail("presence executed a program or read content")
    with monkeypatch.context() as guard:
        guard.setattr(builtins, "open", denied)
        guard.setattr(Path, "open", denied)
        guard.setattr(subprocess, "Popen", denied)
        guard.setattr(subprocess, "run", denied)
        guard.setattr(socket, "socket", denied)
        guard.setattr(sqlite3, "connect", denied)
        assert setup.main(["check"]) == 0
    text = capsys.readouterr().out
    value = json.loads(text)
    assert value["presence"] == "executable_found"
    assert value["scan_status"] == "held"
    assert value["execution_performed"] is False
    assert str(tmp_path) not in text
    assert len(text.encode()) <= setup.MAX_OUTPUT_BYTES


@pytest.mark.parametrize("path", ["", ".", "/bin:", "/bin/../usr/bin", "/bin\n", "/bin:" * 65])
def test_invalid_path_is_unknown_without_probe(path, monkeypatch, capsys, forbid_effects):
    monkeypatch.setenv("PATH", path)
    monkeypatch.setattr(setup, "runtime_platform", lambda: "linux")
    monkeypatch.setattr(setup, "_executable_status", lambda *a: pytest.fail("invalid PATH probed"))
    assert setup.main(["check"]) == 0
    assert json.loads(capsys.readouterr().out)["presence"] == "not_checked"


def test_absence_and_other_platform_are_not_scan_readiness(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setattr(setup, "runtime_platform", lambda: "linux")
    assert setup.main(["check"]) == 0
    assert json.loads(capsys.readouterr().out)["presence"] == "not_found"
    monkeypatch.setattr(setup, "runtime_platform", lambda: "windows")
    monkeypatch.setattr(setup, "_executable_status", lambda *a: pytest.fail("non-Linux probe"))
    assert setup.main(["check"]) == 0
    assert json.loads(capsys.readouterr().out)["presence"] == "not_checked"


@pytest.mark.parametrize("port", [1024, 18080, 65535])
def test_generated_yaml_is_loopback_root_only_with_finite_limits(port, capsys, forbid_effects):
    assert setup.main(["config", "--application-id", UUID.upper(), "--port", str(port)]) == 0
    text = capsys.readouterr().out
    value = yaml.safe_load(text)
    assert set(value) == {"app", "hawk"}
    app, hawk = value["app"], value["hawk"]
    assert app["applicationId"] == UUID
    assert app["host"] == f"http://127.0.0.1:{port}"
    assert app["includePaths"] == ["^/$"]
    assert app["excludePaths"] == ["^/api(?:/|$).*"]
    assert "authentication" not in app
    assert "outboundProxy" not in hawk and "hawkAddOn" not in value
    assert hawk["scan"]["concurrentRequests"] == 1
    assert hawk["scan"]["requestDelayMillis"] == 250
    assert 0 < hawk["scan"]["maxDurationMinutes"] <= 5
    assert hawk["spider"]["ajax"] is False
    assert "custom" not in hawk["spider"]
    assert len(text.encode()) <= setup.MAX_OUTPUT_BYTES


@pytest.mark.parametrize("bad", ["", "0" * 36, "00000000-0000-0000-0000-000000000000",
                               UUID + "\n", UUID + "\n  host: https://example.org", "${API_KEY}", "secret-key-value"])
def test_invalid_application_id_is_refused_without_echo(bad, capsys, forbid_effects):
    assert setup.main(["config", "--application-id", bad]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "HAWKSCAN_SETUP:INVALID_INPUT; no scanner action was attempted.\n"


@pytest.mark.parametrize("port", [0, 1023, 65536, -1, True, "18080"])
def test_invalid_port_is_refused_by_api(port, forbid_effects):
    with pytest.raises(ValueError, match="PORT"):
        setup.render_config(UUID, port)


@pytest.mark.parametrize("arguments", [["scan"], ["install"], ["--apply"],
                                     ["--api-key", "secret-key-value"],
                                     ["config", "--application-id", UUID, "--host", "https://example.org"],
                                     ["config", "--application-id", UUID, "--port", "18080;echo secret-key-value"]])
def test_no_execution_endpoint_or_secret_argument(arguments, capsys, forbid_effects):
    with pytest.raises(SystemExit) as error:
        setup.main(arguments)
    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "secret-key-value" not in output.err and "example.org" not in output.err
    assert "HAWKSCAN_SETUP:INVALID_ARGUMENTS" in output.err


def test_hud_presents_setup_and_hold_without_control_buttons():
    start = SETUP_HTML.index('aria-labelledby="hawkscan-setup-title"')
    card = SETUP_HTML[start:SETUP_HTML.index("</section>", start)]
    assert "Setup available · Scanning held" in card
    assert "python -m megalodon.hawkscan_setup check" in card
    assert "cloud connection" in card
    assert "<button" not in card and "<input" not in card
    assert "Everything runs locally; no companion account" not in SETUP_HTML
