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
    monkeypatch.setattr(hud_autostart, "_service_state", lambda: None, raising=False)

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


@pytest.mark.parametrize("host", ["0.0.0.0", "::1"])
def test_autostart_refuses_non_loopback_settings(tmp_path, monkeypatch, host):
    # ::1 is refused: the HUD server binds IPv4 and upgrades verify an IPv4 listener.
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    paths = local_install.install_paths({"HOME": str(home)})
    paths.config.mkdir(parents=True)
    paths.settings.write_text(f'[dashboard]\nhost="{host}"\n')
    monkeypatch.setattr(hud_autostart, "install_paths", lambda: paths)
    monkeypatch.setattr(hud_autostart, "status", lambda: (0, {"status": "ready"}))
    monkeypatch.setattr(hud_autostart, "_systemctl", lambda *a: pytest.fail("must not change services"))
    with pytest.raises(local_install.InstallError, match="loopback"):
        hud_autostart.enable()
    assert not hud_autostart.unit_path(paths).exists()


def test_application_menu_reopens_running_service_in_browser(monkeypatch):
    opened = []
    monkeypatch.setattr(hud_reopen, "_wait_until_listening", lambda host, port: True)
    monkeypatch.setattr(hud_reopen, "install_paths", lambda: "synthetic paths", raising=False)
    monkeypatch.setattr(hud_reopen, "service_running", lambda paths: paths == "synthetic paths", raising=False)
    monkeypatch.setattr(hud_reopen, "_listener_pid", lambda port, host: 501, raising=False)
    monkeypatch.setattr(hud_reopen, "load_settings", lambda _:
                        SimpleNamespace(dashboard=SimpleNamespace(host="127.0.0.1", port=8787)))
    monkeypatch.setattr(hud_reopen.webbrowser, "open_new_tab", lambda url: opened.append(url) or True)
    assert hud_reopen.main(["/private/settings.toml"]) == 0
    assert opened == ["http://127.0.0.1:8787/"]
    for host in ("0.0.0.0", "::1"):
        monkeypatch.setattr(hud_reopen, "load_settings", lambda _, host=host:
                            SimpleNamespace(dashboard=SimpleNamespace(host=host, port=8787)))
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


def test_reopen_never_opens_a_listener_the_service_does_not_own(tmp_path, monkeypatch, capsys):
    import socket
    from megalodon import install_lifecycle
    squatter = socket.socket()
    squatter.bind(("127.0.0.1", 0))
    squatter.listen()
    port = squatter.getsockname()[1]
    settings = tmp_path / "settings.toml"
    settings.write_text(f'[dashboard]\nhost = "127.0.0.1"\nport = {port}\n')
    # The managed service is not running (MainPID 0); a same-host program owns the port.
    monkeypatch.setattr(hud_reopen, "install_paths", lambda: "synthetic paths", raising=False)
    monkeypatch.setattr(hud_reopen, "service_running", lambda paths: True, raising=False)
    monkeypatch.setattr(install_lifecycle.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="0\n", returncode=0))
    monkeypatch.setattr(hud_reopen.webbrowser, "open_new_tab", lambda _: pytest.fail("Opened another program's page"))
    try:
        assert hud_reopen.main([str(settings)]) == 2
    finally:
        squatter.close()
    assert "not ready" in capsys.readouterr().err


@pytest.fixture
def unit_layout(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    paths = local_install.install_paths({"HOME": str(home)})
    paths.config.mkdir(parents=True)
    paths.settings.write_text('[dashboard]\nhost="127.0.0.1"\nport=8787\n')
    monkeypatch.setattr(hud_autostart, "install_paths", lambda: paths)
    monkeypatch.setattr(hud_autostart, "status", lambda: (0, {"status": "ready"}))
    calls = []
    monkeypatch.setattr(hud_autostart, "_systemctl", lambda *args: calls.append(args))
    monkeypatch.setattr(hud_autostart, "_service_state", lambda: None, raising=False)
    unit = hud_autostart.unit_path(paths)
    unit.parent.mkdir(parents=True)
    return paths, unit, calls


@pytest.mark.parametrize("unit_present", [True, False])
def test_drop_in_override_is_never_treated_as_the_managed_unit(unit_layout, unit_present):
    paths, unit, calls = unit_layout
    if unit_present:
        unit.write_bytes(hud_autostart.unit_contents(paths))
    override = unit.parent / "megalodon-hud.service.d" / "override.conf"
    override.parent.mkdir()
    override.write_text("[Service]\nExecStart=\nExecStart=/synthetic/other\n")
    for action in (hud_autostart.enable, hud_autostart.start):
        with pytest.raises(local_install.InstallError, match="drop-in"):
            action()
    if unit_present:
        with pytest.raises(local_install.InstallError, match="drop-in"):
            hud_autostart.validate_unit(paths)
        with pytest.raises(local_install.InstallError, match="drop-in"):
            hud_autostart.disable(paths)
    assert calls == [] and override.exists() and unit.exists() is unit_present


@pytest.mark.parametrize("unit_present,state,refused", [
    (False, {"FragmentPath": "/other/systemd/user/megalodon-hud.service", "DropInPaths": "", "LoadState": "loaded", "ActiveState": "active"}, True),
    (False, {"FragmentPath": "", "DropInPaths": "", "LoadState": "not-found", "ActiveState": "activating"}, True),
    (True, {"FragmentPath": "/other/systemd/user/megalodon-hud.service", "DropInPaths": "", "LoadState": "loaded", "ActiveState": "inactive"}, True),
    (True, {"FragmentPath": "/dev/null", "DropInPaths": "", "LoadState": "masked", "ActiveState": "inactive"}, True),
    (False, {"FragmentPath": "", "DropInPaths": "", "LoadState": "not-found", "ActiveState": "inactive"}, False),
    (True, {"FragmentPath": "UNIT", "DropInPaths": "", "LoadState": "loaded", "ActiveState": "active"}, False),
    (True, None, False),
])
def test_disable_asks_systemd_which_unit_file_is_loaded(unit_layout, monkeypatch, unit_present, state, refused):
    paths, unit, calls = unit_layout
    if unit_present:
        unit.write_bytes(hud_autostart.unit_contents(paths))
    if state is not None and state["FragmentPath"] == "UNIT":
        state = dict(state, FragmentPath=str(unit))
    monkeypatch.setattr(hud_autostart, "_service_state", lambda: state, raising=False)
    if refused:
        with pytest.raises(local_install.InstallError, match="another unit file"):
            hud_autostart.disable(paths)
        assert calls == [] and unit.exists() is unit_present
    else:
        hud_autostart.disable(paths)
        assert not unit.exists()
        assert calls == ([("disable", "--now", hud_autostart.UNIT), ("daemon-reload",)] if unit_present else [])


def test_only_root_owned_distribution_wide_drop_ins_are_tolerated(tmp_path, monkeypatch):
    vendor = tmp_path / "usr/lib/systemd/user"
    monkeypatch.setattr(hud_autostart, "VENDOR_UNIT_DIRS", (str(vendor),))
    owners = {}
    def lstat(path, real=os.lstat):
        info = real(path)
        uid = owners.get(str(path))
        return info if uid is None else SimpleNamespace(st_mode=info.st_mode, st_uid=uid)
    monkeypatch.setattr(hud_autostart.os, "lstat", lstat)
    def dropin(relative, uid=0, mode=0o644):
        path = vendor / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[Service]\nTimeoutStopFailureMode=abort\n")
        path.chmod(mode)
        owners[str(path)] = uid
        return str(path)
    def state(*paths):
        return {"FragmentPath": "/u/megalodon-hud.service", "DropInPaths": " ".join(paths),
                "LoadState": "loaded", "ActiveState": "active"}
    fedora = dropin("service.d/10-timeout-abort.conf")
    assert not hud_autostart.loaded_dropins(state(fedora))
    # Unit-specific, prefix, writable, non-root or non-vendor drop-ins still need review.
    for path in (dropin("megalodon-hud.service.d/override.conf"), dropin("megalodon-.service.d/p.conf"),
                 dropin("service.d/writable.conf", mode=0o666), dropin("service.d/user.conf", uid=1000),
                 "/etc/systemd/user/service.d/admin.conf", str(vendor / "service.d/missing.conf")):
        assert hud_autostart.loaded_dropins(state(fedora, path)), path


def test_service_state_reads_only_fixed_properties(monkeypatch):
    seen = []
    def run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(returncode=0, stdout="LoadState=loaded\nActiveState=active\nDropInPaths=\n"
                               "FragmentPath=/u/megalodon-hud.service\n")
    monkeypatch.setattr(hud_autostart.subprocess, "run", run)
    state = hud_autostart._service_state()
    assert state == {"FragmentPath": "/u/megalodon-hud.service", "DropInPaths": "", "LoadState": "loaded", "ActiveState": "active"}
    assert not hud_autostart.loaded_dropins(state) and not hud_autostart.loaded_dropins(None)
    assert seen == [["systemctl", "--user", "show", "--property=FragmentPath,DropInPaths,LoadState,ActiveState",
                     hud_autostart.UNIT]]
    monkeypatch.setattr(hud_autostart.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=(
        "FragmentPath=/u/megalodon-hud.service\nLoadState=loaded\nActiveState=active\n"
        "DropInPaths=/etc/systemd/user/megalodon-hud.service.d/a.conf /usr/lib/systemd/user/service.d/b.conf\n")))
    assert hud_autostart.loaded_dropins(hud_autostart._service_state())
    # A manager that omits DropInPaths cannot prove there are none.
    monkeypatch.setattr(hud_autostart.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout="FragmentPath=/u/megalodon-hud.service\nLoadState=loaded\nActiveState=active\n"))
    assert hud_autostart._service_state() is None
    monkeypatch.setattr(hud_autostart.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=1, stdout=""))
    assert hud_autostart._service_state() is None
    monkeypatch.setattr(hud_autostart.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="LoadState=loaded\n"))
    assert hud_autostart._service_state() is None
    def missing(*a, **k):
        raise FileNotFoundError("systemctl")
    monkeypatch.setattr(hud_autostart.subprocess, "run", missing)
    assert hud_autostart._service_state() is None


@pytest.mark.parametrize("unit_present", [True, False])
def test_drop_ins_systemd_loads_from_other_paths_are_refused_like_local_ones(unit_layout, monkeypatch, unit_present):
    paths, unit, calls = unit_layout
    if unit_present:
        unit.write_bytes(hud_autostart.unit_contents(paths))
    # Nothing under XDG_CONFIG_HOME; systemd reports drop-ins from /etc and a type-wide service.d/.
    state = {"FragmentPath": str(unit) if unit_present else "", "LoadState": "loaded" if unit_present else "not-found",
             "ActiveState": "active" if unit_present else "inactive",
             "DropInPaths": "/etc/systemd/user/megalodon-hud.service.d/override.conf /etc/systemd/user/service.d/x.conf"}
    monkeypatch.setattr(hud_autostart, "_service_state", lambda: state, raising=False)
    for action in (hud_autostart.enable, hud_autostart.start):
        with pytest.raises(local_install.InstallError, match="drop-in"):
            action()
    if unit_present:
        with pytest.raises(local_install.InstallError, match="drop-in"):
            hud_autostart.disable(paths)
    else:
        hud_autostart.disable(paths)
    assert calls == [] and unit.exists() is unit_present


@pytest.fixture
def reopen_layout(unit_layout, tmp_path, monkeypatch):
    paths, unit, _ = unit_layout
    unit.write_bytes(hud_autostart.unit_contents(paths))
    settings = tmp_path / "settings.toml"
    settings.write_text('[dashboard]\nhost = "127.0.0.1"\nport = 8787\n')
    monkeypatch.setattr(hud_reopen, "install_paths", lambda: paths, raising=False)
    monkeypatch.setattr(hud_reopen, "_wait_until_listening", lambda host, port: True)
    # The unit's MainPID owns the listener in every case; only its identity varies.
    monkeypatch.setattr(hud_reopen, "_listener_pid", lambda port, host: 501)
    opened = []
    monkeypatch.setattr(hud_reopen.webbrowser, "open_new_tab", lambda url: opened.append(url) or True)
    state = {"FragmentPath": str(unit), "DropInPaths": "", "LoadState": "loaded", "ActiveState": "active"}
    return paths, unit, settings, state, opened


@pytest.mark.parametrize("change", ["other_fragment", "modified", "local_drop_in", "loaded_drop_in", "no_unit", "inactive"])
def test_reopen_opens_only_the_managed_unmodified_unit(reopen_layout, monkeypatch, capsys, change):
    paths, unit, settings, state, opened = reopen_layout
    if change == "other_fragment":
        state["FragmentPath"] = "/other/config/systemd/user/megalodon-hud.service"
    elif change == "modified":
        unit.write_bytes(hud_autostart.unit_contents(paths) + b"ExecStartPre=/synthetic/other\n")
    elif change == "local_drop_in":
        (unit.parent / "megalodon-hud.service.d").mkdir()
    elif change == "loaded_drop_in":
        state["DropInPaths"] = "/etc/systemd/user/megalodon-hud.service.d/override.conf"
    elif change == "no_unit":
        unit.unlink()
    else:
        state["ActiveState"] = "inactive"
    monkeypatch.setattr(hud_autostart, "_service_state", lambda: state, raising=False)
    assert hud_reopen.main([str(settings)]) == 2
    assert opened == [] and "not ready" in capsys.readouterr().err


def test_reopen_opens_the_managed_unit(reopen_layout, monkeypatch):
    paths, unit, settings, state, opened = reopen_layout
    monkeypatch.setattr(hud_autostart, "_service_state", lambda: state, raising=False)
    assert hud_reopen.main([str(settings)]) == 0
    assert opened == ["http://127.0.0.1:8787/"]
