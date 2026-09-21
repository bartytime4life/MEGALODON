"""Display-only Linux package commands captured before dashboard startup."""

from pathlib import Path
import os
import shlex
import sys
import tomllib


def _absolute_command_path(value: str) -> bool:
    return (
        0 < len(value) <= 4096
        and Path(value).is_absolute()
        and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
    )


def _source_checkout() -> Path | None:
    """Offer a source reinstall only when this package is loaded from a checkout."""
    checkout = Path(__file__).absolute().parent.parent
    if not _absolute_command_path(str(checkout)):
        return None
    try:
        with (checkout / "pyproject.toml").open("rb") as handle:
            raw = handle.read(65537)
        if len(raw) > 65536:
            return None
        project = tomllib.loads(raw.decode("utf-8")).get("project", {})
        if not isinstance(project, dict) or project.get("name") != "megalodon-defense":
            return None
    except (OSError, ValueError):
        return None
    return checkout


def local_python_lifecycle() -> dict[str, dict[str, str | None]] | None:
    """Use the actual interpreter, retaining its virtual-environment symlink.

    Nothing is executed. Paths are shown only in the local dashboard's command
    cards; the shared hosted assets and telemetry receipts remain unchanged.
    """
    if sys.platform != "linux" or not _absolute_command_path(sys.executable):
        return None
    python = [sys.executable, "-m", "pip"]
    checkout = _source_checkout()
    return {
        "core": {
            "verify": shlex.join([*python, "show", "megalodon-defense"]),
            "uninstall": shlex.join([*python, "uninstall", "megalodon-defense"]),
            "reinstall": (
                shlex.join([
                    *python, "install", "--force-reinstall", "--no-deps",
                    "--editable", str(checkout),
                ]) if checkout is not None else None
            ),
            "note": (
                "These commands use the Python environment running this dashboard. "
                "They work in a new terminal without activating it. "
                + (
                    "Reinstall names this source checkout explicitly and keeps it editable; "
                    "review the checkout first. Build dependencies may be downloaded. "
                    if checkout is not None else
                    "No source checkout was identified for this installation. "
                    "Reinstall using your original reviewed package source. "
                )
                + "Package metadata does not verify SQLite support or operational acceptance."
            ),
        },
        "scapy": {
            "verify": shlex.join([*python, "show", "scapy"]),
            "uninstall": shlex.join([*python, "uninstall", "scapy"]),
            "reinstall": shlex.join([*python, "install", "--force-reinstall", "scapy>=2.5,<3"]),
            "note": (
                "These commands use the Python environment running this dashboard; "
                "activation is not required in a new terminal. Use its approved package "
                "source. Reinstall may download packages and grants no capture privilege. "
                "The version range is not a pinned artifact."
            ),
        },
    }


def local_hud_launch() -> dict[str, str]:
    """Return one closed relaunch context for the currently serving HUD.

    The desktop installer supplies only a validated absolute launcher path. A
    source or ordinary package launch uses the exact Python interpreter that is
    already serving this dashboard. Nothing here executes a command.
    """
    launcher = os.environ.get("MEGALODON_LAUNCHER_PATH", "")
    if os.environ.get("MEGALODON_INSTALL_MODE") == "desktop" and _absolute_command_path(launcher):
        try:
            candidate = Path(launcher)
            valid_launcher = candidate.is_file() and not candidate.is_symlink()
        except OSError:
            valid_launcher = False
        if valid_launcher:
            return {"mode": "desktop", "command": shlex.join([launcher])}
    if not _absolute_command_path(sys.executable):
        return {"mode": "source", "command": ""}
    return {
        "mode": "source",
        "command": shlex.join([sys.executable, "-m", "megalodon", "hud"]),
    }
