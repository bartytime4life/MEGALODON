"""User login startup points only at the installed, loopback HUD."""

from types import SimpleNamespace

import pytest

from megalodon import hud_autostart, hud_reopen, local_install


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
    monkeypatch.setattr(hud_reopen, "load_settings", lambda _:
                        SimpleNamespace(dashboard=SimpleNamespace(host="127.0.0.1", port=8787)))
    monkeypatch.setattr(hud_reopen.webbrowser, "open_new_tab", lambda url: opened.append(url) or True)
    assert hud_reopen.main(["/private/settings.toml"]) == 0
    assert opened == ["http://127.0.0.1:8787/"]
    monkeypatch.setattr(hud_reopen, "load_settings", lambda _:
                        SimpleNamespace(dashboard=SimpleNamespace(host="0.0.0.0", port=8787)))
    assert hud_reopen.main(["/private/settings.toml"]) == 2
    assert opened == ["http://127.0.0.1:8787/"]
