"""Copied package commands keep the dashboard interpreter and quote paths."""

import json
from pathlib import Path
import shlex
import shutil
import subprocess
from unittest.mock import Mock

import pytest

from megalodon import dashboard, dashboard_commands as commands
from megalodon.dashboard_tool_assets import LIFECYCLE_JS


def test_commands_preserve_virtualenv_and_ignore_terminal_directory(monkeypatch):
    # Resolving the executable symlink would lose the selected virtualenv.
    executable = "/private/operator's env $(touch NEVER)/bin/python"
    checkout = Path("/private/reviewed checkout ' $(touch NEVER)")
    monkeypatch.setattr(commands.sys, "platform", "linux")
    monkeypatch.setattr(commands.sys, "executable", executable)
    monkeypatch.setattr(commands, "_source_checkout", lambda: checkout)
    result = commands.local_python_lifecycle()
    for tool, package in (("core", "megalodon-defense"), ("scapy", "scapy")):
        assert shlex.split(result[tool]["verify"]) == [executable, "-m", "pip", "show", package]
        assert shlex.split(result[tool]["uninstall"]) == [executable, "-m", "pip", "uninstall", package]
    assert shlex.split(result["core"]["reinstall"]) == [
        executable, "-m", "pip", "install", "--force-reinstall", "--no-deps",
        "--editable", str(checkout),
    ]
    assert shlex.split(result["scapy"]["reinstall"]) == [
        executable, "-m", "pip", "install", "--force-reinstall", "scapy>=2.5,<3",
    ]


@pytest.mark.parametrize("executable", ["", "python3", "/tmp/bad\npython", "/tmp/bad\x00python", "/" + "x" * 4096])
def test_invalid_interpreter_is_not_copied(monkeypatch, executable):
    monkeypatch.setattr(commands.sys, "platform", "linux")
    monkeypatch.setattr(commands.sys, "executable", executable)
    monkeypatch.setattr(commands, "_source_checkout", lambda: pytest.fail("Unexpected discovery"))
    assert commands.local_python_lifecycle() is None


def test_linux_commands_are_not_offered_on_windows(monkeypatch):
    monkeypatch.setattr(commands.sys, "platform", "win32")
    monkeypatch.setattr(commands, "_source_checkout", lambda: pytest.fail("Unexpected discovery"))
    assert commands.local_python_lifecycle() is None


@pytest.mark.parametrize("content", [
    None, b"invalid TOML", b"project = []", b'[project]\nname = "other-project"',
    b"#" + b"x" * 65536, b"\xff",
])
def test_no_guessed_reinstall_for_unidentified_checkout(tmp_path, monkeypatch, content):
    monkeypatch.setattr(commands, "__file__", str(tmp_path / "megalodon/dashboard_commands.py"))
    monkeypatch.setattr(commands.sys, "platform", "linux")
    monkeypatch.setattr(commands.sys, "executable", "/private/env/bin/python")
    if content is not None:
        (tmp_path / "pyproject.toml").write_bytes(content)
    assert commands._source_checkout() is None
    assert commands.local_python_lifecycle()["core"]["reinstall"] is None


def test_checkout_comes_from_package_location_not_cwd(tmp_path, monkeypatch):
    checkout = tmp_path / "source"
    checkout.mkdir()
    (checkout / "pyproject.toml").write_text('[project]\nname = "megalodon-defense"\n')
    monkeypatch.setattr(commands, "__file__", str(checkout / "megalodon/dashboard_commands.py"))
    monkeypatch.chdir(tmp_path)
    assert commands._source_checkout() == checkout


def test_startup_captures_local_commands_and_shared_assets_remain_generic(monkeypatch):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for emitted command verification")
    snapshots = []
    local = {
        "core": {"verify": "'/private/env/bin/python' -m pip show megalodon-defense", "reinstall": None},
        "scapy": {"verify": "'/private/env/bin/python' -m pip show scapy"},
    }
    def snapshot():
        snapshots.append(1)
        return local
    monkeypatch.setattr(dashboard, "local_python_lifecycle", snapshot)
    server = Mock()
    factory = Mock(return_value=server)
    monkeypatch.setattr(dashboard, "ThreadingHTTPServer", factory)
    dashboard.serve(object(), "127.0.0.1", 8787)
    handler = factory.call_args.args[1]
    script = handler.javascript.decode()
    start = script.index("const localPythonLifecycle = ")
    end = script.index("const readinessToolIds", start)
    harness = script[start:end] + "\nconsole.log(JSON.stringify([resolveLifecycle('core'), resolveLifecycle('scapy'), resolveLifecycle('tshark')]));"
    result = subprocess.run([node, "-e", harness], capture_output=True, text=True, check=True, timeout=5)
    core, scapy, tshark = json.loads(result.stdout)
    assert core["verify"] == local["core"]["verify"]
    assert core["reinstall"] is None
    assert scapy["verify"] == local["scapy"]["verify"]
    assert tshark["verify"] == "test -x /usr/bin/tshark && /usr/bin/tshark --version"
    assert snapshots == [1]
    assert "const localPythonLifecycle = null;" in LIFECYCLE_JS
    assert "/private/env/bin/python" not in LIFECYCLE_JS
    # Served bytes belong to this startup and do not change with later state.
    local["core"]["verify"] = "changed"
    assert handler.javascript.decode() == script


def test_command_asset_route_serves_startup_snapshot(monkeypatch):
    handler = object.__new__(dashboard.DashboardHandler)
    handler.path = "/assets/dashboard.js"
    handler.javascript = b"/* synthetic startup snapshot */"
    monkeypatch.setattr(handler, "_has_expected_host", lambda: True)
    send = Mock()
    monkeypatch.setattr(handler, "_send", send)
    monkeypatch.setattr(dashboard, "local_python_lifecycle", lambda: pytest.fail("Request must not rediscover paths"))
    handler.do_GET()
    send.assert_called_once_with(200, "text/javascript; charset=utf-8", handler.javascript)
