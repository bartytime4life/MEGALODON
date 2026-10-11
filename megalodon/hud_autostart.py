"""Optional user-scoped systemd startup for an installed local HUD."""

from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys

from .config import load_settings
from .local_install import InstallError, InstallPaths, _atomic_write, _owned_directory, _regular_owned_file, install_paths, status

UNIT = "megalodon-hud.service"
# Distribution-owned user-unit directories. A root-owned type-wide `service.d/`
# drop-in there (for example Fedora's 10-timeout-abort.conf) applies to every
# user service and is not an override of this unit.
VENDOR_UNIT_DIRS = ("/usr/lib/systemd/user", "/lib/systemd/user")


def _unit_arg(value: Path) -> str:
    raw = str(value)
    if not raw.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InstallError("HUD startup path is not a safe absolute path")
    return '"' + raw.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'


def _unit_env(name: str, value: Path) -> str:
    raw = str(value)
    if not raw.startswith("/") or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InstallError("HUD startup environment path is not safe")
    escaped = raw.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    return f'"{name}={escaped}"'


def unit_path(paths: InstallPaths | None = None) -> Path:
    paths = install_paths() if paths is None else paths
    return paths.config.parent / "systemd" / "user" / UNIT


def dropin_path(paths: InstallPaths | None = None) -> Path:
    """`systemctl --user edit` overrides; they can replace ExecStart without touching the unit."""
    return unit_path(paths).with_name(UNIT + ".d")


def unit_contents(paths: InstallPaths | None = None) -> bytes:
    paths = install_paths() if paths is None else paths
    python = paths.current / "venv" / "bin" / "python"
    return (
        "# Managed by MEGALODON hud-autostart.\n"
        "[Unit]\nDescription=MEGALODON local HUD\n"
        "[Service]\nType=simple\n"
        f"ExecStart={_unit_arg(python)} -I -m megalodon hud --config {_unit_arg(paths.settings)}\n"
        "Restart=on-failure\nRestartSec=5\n"
        "Environment=MEGALODON_INSTALL_MODE=desktop\n"
        f"Environment={_unit_env('MEGALODON_LAUNCHER_PATH', paths.hud_launcher)}\n"
        "[Install]\nWantedBy=default.target\n"
    ).encode("utf-8")


def _systemctl(*args: str) -> None:
    try:
        subprocess.run(["systemctl", "--user", *args], check=True, timeout=15)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise InstallError("user service manager could not update HUD startup") from exc


def _service_state() -> dict[str, str] | None:
    """Ask the user manager which unit file it loaded; None when no manager answers."""
    try:
        result = subprocess.run(["systemctl", "--user", "show",
                                 "--property=FragmentPath,DropInPaths,LoadState,ActiveState", UNIT],
                                capture_output=True, encoding="utf-8", errors="surrogateescape", timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    state = dict(line.partition("=")[::2] for line in result.stdout.splitlines())
    if result.returncode or set(state) != {"FragmentPath", "DropInPaths", "LoadState", "ActiveState"}:
        return None
    return state


def _vendor_type_wide(path: str) -> bool:
    candidate = PurePosixPath(path)
    if candidate.parent.name != "service.d" or str(candidate.parent.parent) not in VENDOR_UNIT_DIRS:
        return False
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022


def loaded_dropins(state: dict[str, str] | None) -> bool:
    """systemd also merges drop-ins from /etc, runtime and type-wide `service.d/` paths.

    Only a root-owned, distribution-wide `service.d/` drop-in is tolerated;
    any unit-specific, prefix, admin, runtime or user drop-in needs review.
    """
    return state is not None and any(not _vendor_type_wide(path) for path in state["DropInPaths"].split())


def loaded_elsewhere(state: dict[str, str] | None, unit: Path, managed: bool) -> bool:
    """The unit name is loaded from another file, or running without the managed file."""
    return state is not None and (
        (state["LoadState"] != "not-found" and state["FragmentPath"] != str(unit))
        or (not managed and state["ActiveState"] not in {"inactive", "failed"}))


def _prepare_unit() -> None:
    if status()[0] != 0:
        raise InstallError("install or repair the local HUD before enabling startup")
    # The HUD server binds IPv4 only; upgrade verification proves an IPv4 listener.
    if load_settings(install_paths().settings).dashboard.host != "127.0.0.1":
        raise InstallError("automatic HUD startup requires the IPv4 loopback dashboard host 127.0.0.1")
    unit = unit_path()
    expected = unit_contents()
    _owned_directory(unit.parent, private=False)
    if os.path.lexists(dropin_path()) or loaded_dropins(_service_state()):
        raise InstallError("a HUD startup drop-in override exists; preserve and review it")
    if os.path.lexists(unit):
        existing = _regular_owned_file(unit, maximum=8192)
        if existing != expected:
            raise InstallError("the existing HUD startup unit differs; preserve and review it")
    else:
        _atomic_write(unit, expected, 0o644)
    _systemctl("daemon-reload")


def start() -> None:
    """Start the fixed HUD service without enabling it at login."""
    _prepare_unit()
    _systemctl("start", UNIT)


def enable(*, start: bool = False) -> None:
    _prepare_unit()
    _systemctl("enable", UNIT)
    if start:
        _systemctl("start", UNIT)


def validate_unit(paths: InstallPaths | None = None) -> bool:
    """Read-only identity check shared by removal preview and application."""
    selected = install_paths() if paths is None else paths
    unit = unit_path(selected)
    if not os.path.lexists(unit):
        return False
    existing = _regular_owned_file(unit, maximum=8192)
    if existing != unit_contents(selected):
        raise InstallError("the existing HUD startup unit differs; preserve and review it")
    if os.path.lexists(dropin_path(selected)):
        raise InstallError("the existing HUD startup unit has a drop-in override; preserve and review it")
    return True


def disable(paths: InstallPaths | None = None) -> None:
    selected = install_paths() if paths is None else paths
    unit = unit_path(selected)
    managed = validate_unit(selected)
    # A different XDG_CONFIG_HOME selects a different unit path; ask systemd.
    state = _service_state()
    if loaded_elsewhere(state, unit, managed):
        raise InstallError("the HUD service is loaded from another unit file; stop and disable it there first")
    if managed and loaded_dropins(state):
        raise InstallError("the existing HUD startup unit has a drop-in override; preserve and review it")
    if not managed:
        return
    _systemctl("disable", "--now", UNIT)
    unit.unlink()
    _systemctl("daemon-reload")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage local HUD startup for this Linux user")
    parser.add_argument("action", choices=("start", "enable", "disable"))
    parser.add_argument("--start", action="store_true", help="also start the enabled service now")
    args = parser.parse_args(argv)
    if args.start and args.action != "enable":
        parser.error("--start is only valid with enable")
    try:
        if args.action == "start":
            start()
            print("MEGALODON is running in the background for this user.")
        elif args.action == "enable":
            enable(start=args.start)
            print("MEGALODON will start when this user signs in." + (" It is running now." if args.start else ""))
        else:
            disable()
            print("MEGALODON automatic startup is off.")
    except (InstallError, ValueError, OSError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
