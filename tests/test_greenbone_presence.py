"""Saved Greenbone deployment configuration cannot attest installation."""
from pathlib import Path

import pytest

from megalodon import tool_heartbeat


@pytest.fixture
def greenbone_host(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    compose = home / "greenbone-community-edition" / "compose.yaml"
    compose.parent.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", str(bin_dir))
    monkeypatch.setattr(tool_heartbeat, "runtime_platform", lambda: "linux")
    monkeypatch.setattr(tool_heartbeat, "PROBES", {
        "greenbone": tool_heartbeat.PROBES["greenbone"],
    })
    starts = {}
    monkeypatch.setattr(tool_heartbeat, "_process_starts", lambda *_: (starts, True))

    def observe():
        return tool_heartbeat.heartbeat_report(tmp_path / "synthetic-proc")["tools"][0]

    return compose, bin_dir, starts, observe


@pytest.mark.parametrize("mode", [0o600, 0o700])
def test_saved_compose_never_establishes_installation(greenbone_host, mode):
    compose, _, _, observe = greenbone_host
    compose.write_text("services: {}\n")
    compose.chmod(mode)
    tool = observe()
    assert tool["installed"] == "unknown"
    assert tool["installed_since"] is None
    assert tool["light"] == "grey"
    assert tool["service"] == "stopped"


@pytest.mark.parametrize("kind", ["absent", "directory", "symlink"])
def test_non_file_config_does_not_establish_installation(greenbone_host, kind):
    compose, _, _, observe = greenbone_host
    if kind == "directory":
        compose.mkdir()
    elif kind == "symlink":
        target = compose.with_name("saved.yaml")
        target.write_text("services: {}\n")
        compose.symlink_to(target)
    tool = observe()
    assert tool["installed"] == "no"
    assert tool["installed_since"] is None
    assert tool["light"] == "red"  # Not found in bounded locations, not absent everywhere.


def test_unreadable_config_remains_unknown(greenbone_host, monkeypatch):
    compose, _, _, observe = greenbone_host
    original_stat = tool_heartbeat.os.stat

    def denied_config(path, *args, **kwargs):
        if Path(path) == compose:
            raise PermissionError("synthetic configuration denial")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(tool_heartbeat.os, "stat", denied_config)
    tool = observe()
    assert tool["installed"] == "unknown"
    assert tool["installed_since"] is None
    assert tool["light"] == "grey"


@pytest.mark.parametrize("with_compose", [False, True])
def test_executable_is_independent_presence_evidence(greenbone_host, with_compose):
    compose, bin_dir, _, observe = greenbone_host
    if with_compose:
        compose.write_text("services: {}\n")
    executable = bin_dir / "gvmd"
    executable.write_text("Synthetic file; must never execute.\n")
    executable.chmod(0o700)
    tool = observe()
    assert tool["installed"] == "yes"
    assert tool["installed_since"] is not None
    assert tool["service"] == "stopped"
    assert tool["light"] == "amber"


@pytest.mark.parametrize("with_compose", [False, True])
def test_process_is_independent_presence_evidence(greenbone_host, with_compose):
    compose, _, starts, observe = greenbone_host
    if with_compose:
        compose.write_text("services: {}\n")
    starts["gvmd"] = 1_700_000_000
    tool = observe()
    assert tool["installed"] == "yes"
    assert tool["installed_since"] is None
    assert tool["service"] == "running"
    assert tool["light"] == "green"
