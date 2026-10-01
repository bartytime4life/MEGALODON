"""User login startup points only at the installed, loopback HUD."""

from types import SimpleNamespace
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from megalodon import hud_autostart, hud_reopen, local_install


@pytest.fixture
def installed_launcher(tmp_path):
    home = tmp_path / "operator's home $(touch NEVER_EXECUTE)"
    paths = local_install.install_paths({"HOME": str(home)})
    python = paths.current / "venv/bin/python"
    python.parent.mkdir(parents=True)
    # Observe exact argv without starting a HUD, a tool, or a real service.
    python.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        "if 'megalodon.hud_autostart' in sys.argv:\n"
        "    sys.exit(int(os.environ.get('HUD_TEST_START_EXIT', '0')))\n"
        "print(json.dumps(sys.argv[1:]))\n"
        "sys.exit(int(os.environ.get('HUD_TEST_EXIT', '0')))\n"
    )
    python.chmod(0o700)
    paths.hud_launcher.parent.mkdir(parents=True)
    paths.hud_launcher.write_bytes(local_install._artifact_contents(paths)["hud_launcher"])
    paths.hud_launcher.chmod(0o700)
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    systemctl = bin_dir / "systemctl"
    systemctl.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$HUD_TEST_SERVICE_LOG"\n'
        'exit "$HUD_TEST_SERVICE_EXIT"\n'
    )
    systemctl.chmod(0o700)
    touch = bin_dir / "touch"
    touch.write_text('#!/bin/sh\n: > "$HUD_TEST_INJECTION_MARKER"\n')
    touch.chmod(0o700)
    service_log = tmp_path / "service.log"
    env = {**os.environ, "PATH": str(bin_dir), "HUD_TEST_SERVICE_LOG": str(service_log),
           "HUD_TEST_SERVICE_EXIT": "0", "HUD_TEST_INJECTION_MARKER": str(tmp_path / "injected")}
    return paths, env, service_log


@pytest.mark.parametrize("active", [True, False])
@pytest.mark.parametrize("options", [
    [], ["--help"], ["--no-auto-companions"], ["--require-sign-in"],
    ["--companion-config", "/private/companion's settings.toml"],
    ["--config", "/private/other $(touch NEVER_EXECUTE).toml", "--port", "8798"],
    ["--unsupported-option"],
])
def test_installed_launcher_starts_or_reopens_service_without_options(installed_launcher, active, options):
    paths, env, service_log = installed_launcher
    env["HUD_TEST_SERVICE_EXIT"] = "0" if active else "3"
    result = subprocess.run([str(paths.hud_launcher), *options], env=env,
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    if not options:
        expected = ["-I", "-m", "megalodon.hud_reopen", str(paths.settings)]
    else:
        expected = ["-I", "-m", "megalodon", "hud", "--config", str(paths.settings),
                    "--open-browser", *options]
    assert json.loads(result.stdout) == expected
    if options:
        assert not service_log.exists(), "Explicit options must not consult or change a service"
    else:
        assert service_log.read_text().splitlines() == ["--user is-active --quiet megalodon-hud.service"]
    assert not Path(env["HUD_TEST_INJECTION_MARKER"]).exists()


def test_installed_launcher_falls_back_when_user_service_cannot_start(installed_launcher):
    paths, env, _ = installed_launcher
    env.update(HUD_TEST_SERVICE_EXIT="3", HUD_TEST_START_EXIT="2")
    result = subprocess.run([str(paths.hud_launcher)], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert json.loads(result.stdout) == ["-I", "-m", "megalodon", "hud", "--config", str(paths.settings), "--open-browser"]


@pytest.mark.parametrize("exit_code", [2, 19])
def test_installed_launcher_preserves_explicit_child_failure(installed_launcher, exit_code):
    paths, env, service_log = installed_launcher
    env["HUD_TEST_EXIT"] = str(exit_code)
    result = subprocess.run([str(paths.hud_launcher), "--port", "0"], env=env,
                            capture_output=True, text=True, timeout=5)
    assert result.returncode == exit_code
    assert json.loads(result.stdout)[-2:] == ["--port", "0"]
    assert not service_log.exists()


def test_copied_ui_command_reaches_installed_launcher_literally(installed_launcher):
    from megalodon.dashboard_setup import SETUP_JS

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node required for command builder")
    paths, env, service_log = installed_launcher
    values = {"config": "/private/other ' $(touch NEVER_EXECUTE).toml", "port": "8798"}
    launch = {"mode": "desktop", "command": shlex.join([str(paths.hud_launcher)])}
    start = SETUP_JS.index("function hudLaunchCommand")
    end = SETUP_JS.index("function renderLaunchHelp", start)
    script = ("const localHudLaunch = " + json.dumps(launch) + ";\n" + SETUP_JS[start:end]
              + "\nconsole.log(hudLaunchCommand(" + json.dumps(values) + "));")
    command = subprocess.run([node, "-e", script], capture_output=True, text=True,
                             check=True, timeout=5).stdout.strip()
    # A shell is used only to test the reviewed copied-command quoting boundary.
    result = subprocess.run(["/bin/sh", "-c", command], env=env, capture_output=True,
                            text=True, timeout=5, check=True)
    assert json.loads(result.stdout) == [
        "-I", "-m", "megalodon", "hud", "--config", str(paths.settings), "--open-browser",
        "--config", values["config"], "--port", "8798",
    ]
    assert not service_log.exists()
    assert not Path(env["HUD_TEST_INJECTION_MARKER"]).exists()


def test_user_service_is_reversible_and_uses_the_selected_release(tmp_path, monkeypatch):
    home = tmp_path / "home with % sign"
    home.mkdir(mode=0o700)
    paths = local_install.install_paths({
        "HOME": str(home),
        "XDG_DATA_HOME": str(home / "share"),
        "XDG_CONFIG_HOME": str(home / "config"),
    })
    paths.config.mkdir(parents=True)
    paths.config.parent.chmod(0o700)
    paths.config.chmod(0o700)
    paths.settings.write_text('[dashboard]\nhost="127.0.0.1"\nport=8787\n')
    monkeypatch.setattr(hud_autostart, "install_paths", lambda: paths)
    monkeypatch.setattr(hud_autostart, "status", lambda: (0, {"status": "ready"}))
    calls = []
    monkeypatch.setattr(hud_autostart, "_systemctl", lambda *args: calls.append(args))

    hud_autostart.enable()
    unit = hud_autostart.unit_path()
    raw = unit.read_text()
    assert 'MEGALODON local HUD' in raw
    assert 'megalodon hud --config' in raw
    assert '%% sign' in raw
    assert calls == [("daemon-reload",), ("enable", "megalodon-hud.service")]
    calls.clear()
    hud_autostart.start()
    assert calls == [("daemon-reload",), ("start", "megalodon-hud.service")]
    hud_autostart.enable()
    assert unit.is_file()
    unit.write_text(raw + "# local change\n")
    with pytest.raises(local_install.InstallError, match="differs"):
        hud_autostart.disable()
    unit.write_text(raw)
    hud_autostart.disable()
    assert not unit.exists()
    assert calls[-2:] == [("disable", "--now", "megalodon-hud.service"), ("daemon-reload",)]


def test_autostart_refuses_non_loopback_settings(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    paths = local_install.install_paths({"HOME": str(home)})
    paths.config.mkdir(parents=True)
    paths.settings.write_text('[dashboard]\nhost="0.0.0.0"\n')
    monkeypatch.setattr(hud_autostart, "install_paths", lambda: paths)
    monkeypatch.setattr(hud_autostart, "status", lambda: (0, {"status": "ready"}))
    with pytest.raises(local_install.InstallError, match="loopback"):
        hud_autostart.enable()


def test_application_menu_reopens_running_service_in_browser(monkeypatch):
    opened = []
    monkeypatch.setattr(hud_reopen, "_wait_until_listening", lambda host, port: True)
    monkeypatch.setattr(hud_reopen, "load_settings", lambda _:
                        SimpleNamespace(dashboard=SimpleNamespace(host="127.0.0.1", port=8787)))
    monkeypatch.setattr(hud_reopen.webbrowser, "open_new_tab", lambda url: opened.append(url) or True)
    assert hud_reopen.main(["/private/settings.toml"]) == 0
    assert opened == ["http://127.0.0.1:8787/"]
    monkeypatch.setattr(hud_reopen, "load_settings", lambda _:
                        SimpleNamespace(dashboard=SimpleNamespace(host="0.0.0.0", port=8787)))
    assert hud_reopen.main(["/private/settings.toml"]) == 2
    assert opened == ["http://127.0.0.1:8787/"]


def test_reopen_waits_for_socket_and_reports_failed_start(monkeypatch, capsys):
    from contextlib import nullcontext
    connections = []
    def connect(address, timeout):
        connections.append(address)
        if len(connections) == 1:
            raise ConnectionRefusedError()
        return nullcontext()
    monkeypatch.setattr(hud_reopen.socket, "create_connection", connect)
    monkeypatch.setattr(hud_reopen.time, "sleep", lambda _: None)
    assert hud_reopen._wait_until_listening("::1", 8787)
    assert connections == [("::1", 8787)] * 2
    monkeypatch.setattr(hud_reopen.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    assert not hud_reopen._wait_until_listening("127.0.0.1", 8787, timeout=0)
    monkeypatch.setattr(hud_reopen, "_wait_until_listening", lambda *a: False)
    monkeypatch.setattr(hud_reopen, "load_settings", lambda _: SimpleNamespace(dashboard=SimpleNamespace(host="127.0.0.1", port=8787)))
    monkeypatch.setattr(hud_reopen.webbrowser, "open_new_tab", lambda _: pytest.fail("Do not open a failed service"))
    assert hud_reopen.main(["/private/settings.toml"]) == 2
    assert "not finished starting" in capsys.readouterr().err
