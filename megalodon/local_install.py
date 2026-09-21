"""User-scoped Linux desktop installation for the local MEGALODON HUD.

The installer owns only its private application directories and named desktop
artifacts. It never creates telemetry, starts sensors, enables login startup, or
uses elevated privileges.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
from importlib import resources
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tomllib
from typing import Mapping

from . import __version__
from .config import load_settings


MANIFEST_SCHEMA = "megalodon-local-install-v1"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SETTINGS_BYTES = 64 * 1024
RELEASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
ALLOWED_PIP_ENV = frozenset({
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_NO_INDEX",
    "PIP_TRUSTED_HOST", "PIP_CERT", "PIP_CLIENT_CERT", "PIP_PROXY",
    "PIP_TIMEOUT", "PIP_RETRIES",
})


class InstallError(ValueError):
    """The requested local installation operation was refused safely."""


@dataclass(frozen=True)
class InstallPaths:
    app: Path
    releases: Path
    current: Path
    manifest: Path
    data: Path
    config: Path
    settings: Path
    hud_launcher: Path
    manager_launcher: Path
    desktop_entry: Path
    icon: Path


def _clean_absolute(value: str, name: str) -> Path:
    if not value or len(value) > 4096 or any(ord(char) < 32 for char in value):
        raise InstallError(f"{name} must be a non-empty absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise InstallError(f"{name} must be an absolute path")
    return path


def install_paths(environment: Mapping[str, str] | None = None) -> InstallPaths:
    env = os.environ if environment is None else environment
    home = _clean_absolute(env.get("HOME", str(Path.home())), "HOME")
    data_home = _clean_absolute(
        env.get("XDG_DATA_HOME", str(home / ".local" / "share")),
        "XDG_DATA_HOME",
    )
    config_home = _clean_absolute(
        env.get("XDG_CONFIG_HOME", str(home / ".config")),
        "XDG_CONFIG_HOME",
    )
    app = data_home / "megalodon"
    return InstallPaths(
        app=app,
        releases=app / "releases",
        current=app / "current",
        manifest=app / "install.json",
        data=app / "data",
        config=config_home / "megalodon",
        settings=config_home / "megalodon" / "settings.toml",
        hud_launcher=home / ".local" / "bin" / "megalodon-hud",
        manager_launcher=home / ".local" / "bin" / "megalodon-manage",
        desktop_entry=data_home / "applications" / "megalodon.desktop",
        icon=data_home / "icons" / "hicolor" / "scalable" / "apps" / "megalodon.svg",
    )


def _require_supported_user() -> None:
    if sys.platform != "linux" or os.name != "posix":
        raise InstallError("the desktop installer currently supports Linux only")
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        raise InstallError("run this installer as your ordinary user, not root or sudo")


def _validate_directory_chain(path: Path) -> None:
    """Require trusted, non-substitutable existing ancestors for a write path."""
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not os.path.lexists(current):
            return
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise InstallError(f"installation directory ancestry is unsafe: {current}")
        if info.st_uid not in {0, os.geteuid()}:
            raise InstallError(f"installation directory ancestry has an untrusted owner: {current}")
        writable = stat.S_IMODE(info.st_mode) & 0o022
        if writable and not (info.st_mode & stat.S_ISVTX):
            raise InstallError(f"installation directory ancestry is group- or world-writable: {current}")


def _create_directory_chain(path: Path, final_mode: int) -> None:
    missing: list[Path] = []
    current = path
    while not os.path.lexists(current):
        missing.append(current)
        if current == current.parent:
            break
        current = current.parent
    _validate_directory_chain(current)
    for directory in reversed(missing):
        mode = final_mode if directory == path else 0o755
        try:
            directory.mkdir(mode=mode)
            directory.chmod(mode)
        except FileExistsError:
            pass
        _validate_directory_chain(directory)


def _owned_directory(path: Path, *, private: bool) -> None:
    _validate_directory_chain(path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        _create_directory_chain(path, 0o700 if private else 0o755)
        info = path.lstat()
    _validate_directory_chain(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise InstallError(f"installation directory is not a real directory: {path}")
    if info.st_uid != os.geteuid():
        raise InstallError(f"installation directory is not owned by this user: {path}")
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise InstallError(f"private installation directory has broad permissions: {path}")
    if not private and stat.S_IMODE(info.st_mode) & 0o022:
        raise InstallError(f"public installation directory is group- or world-writable: {path}")


def _regular_owned_file(path: Path, *, maximum: int | None = None) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError(f"required installation file is missing: {path}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
        raise InstallError(f"installation file is unsafe: {path}")
    if info.st_nlink != 1:
        raise InstallError(f"installation file must have one link: {path}")
    if maximum is not None and info.st_size > maximum:
        raise InstallError(f"installation file exceeds its size limit: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise InstallError(f"installation file could not be read: {path}") from exc


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _pairs(values: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in values:
        if key in result:
            raise InstallError("installation manifest contains a duplicate key")
        result[key] = value
    return result


def _artifact_paths(paths: InstallPaths) -> dict[str, Path]:
    return {
        "hud_launcher": paths.hud_launcher,
        "manager_launcher": paths.manager_launcher,
        "desktop_entry": paths.desktop_entry,
        "icon": paths.icon,
    }


def _artifact_modes() -> dict[str, int]:
    return {
        "hud_launcher": 0o755,
        "manager_launcher": 0o755,
        "desktop_entry": 0o644,
        "icon": 0o644,
    }


def _load_manifest(paths: InstallPaths) -> dict[str, object] | None:
    if not os.path.lexists(paths.manifest):
        return None
    raw = _regular_owned_file(paths.manifest, maximum=MAX_MANIFEST_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallError("installation manifest is invalid") from exc
    expected = {
        "schema", "active_release", "previous_release", "version", "installed_at",
        "source", "artifacts", "releases",
    }
    if not isinstance(value, dict) or set(value) != expected or value["schema"] != MANIFEST_SCHEMA:
        raise InstallError("installation manifest has an unsupported shape")
    active = value["active_release"]
    previous = value["previous_release"]
    if not isinstance(active, str) or RELEASE_ID.fullmatch(active) is None:
        raise InstallError("installation manifest has an invalid active release")
    if previous is not None and (not isinstance(previous, str) or RELEASE_ID.fullmatch(previous) is None):
        raise InstallError("installation manifest has an invalid previous release")
    if not isinstance(value["version"], str) or not value["version"]:
        raise InstallError("installation manifest has an invalid version")
    source = value["source"]
    if (
        not isinstance(source, dict)
        or set(source) != {"kind", "pyproject_sha256"}
        or source["kind"] != "local_checkout"
        or not isinstance(source["pyproject_sha256"], str)
        or DIGEST.fullmatch(source["pyproject_sha256"]) is None
    ):
        raise InstallError("installation manifest has an invalid source receipt")
    artifacts = value["artifacts"]
    expected_paths = _artifact_paths(paths)
    if not isinstance(artifacts, dict) or set(artifacts) != set(expected_paths):
        raise InstallError("installation manifest has an invalid artifact set")
    for name, expected_path in expected_paths.items():
        item = artifacts[name]
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "sha256"}
            or item["path"] != str(expected_path)
            or not isinstance(item["sha256"], str)
            or DIGEST.fullmatch(item["sha256"]) is None
        ):
            raise InstallError("installation manifest has invalid artifact metadata")
    releases = value["releases"]
    if not isinstance(releases, list) or not 1 <= len(releases) <= 32:
        raise InstallError("installation manifest has an invalid release list")
    release_ids: set[str] = set()
    for item in releases:
        if not isinstance(item, dict) or set(item) != {"id", "version", "installed_at"}:
            raise InstallError("installation manifest has invalid release metadata")
        release_id = item["id"]
        if (
            not isinstance(release_id, str)
            or RELEASE_ID.fullmatch(release_id) is None
            or release_id in release_ids
            or not isinstance(item["version"], str)
            or not isinstance(item["installed_at"], str)
        ):
            raise InstallError("installation manifest has invalid release metadata")
        release_ids.add(release_id)
    if active not in release_ids or (previous is not None and previous not in release_ids):
        raise InstallError("installation manifest release selection is inconsistent")
    return value


def _atomic_write(path: Path, value: bytes, mode: int) -> None:
    temporary = path.parent / f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _guard_artifact(path: Path, expected_digest: str | None, expected_mode: int) -> bytes | None:
    if not os.path.lexists(path):
        return None
    raw = _regular_owned_file(path, maximum=MAX_MANIFEST_BYTES)
    if expected_digest is None:
        raise InstallError(f"an untracked file already uses an installer path: {path}")
    if _digest(raw) != expected_digest:
        raise InstallError(f"an installed artifact was modified; preserve and review it first: {path}")
    if stat.S_IMODE(path.lstat().st_mode) != expected_mode:
        raise InstallError(f"an installed artifact mode was modified; preserve and review it first: {path}")
    return raw


def _validated_source(source: Path) -> tuple[Path, bytes]:
    try:
        resolved = source.resolve(strict=True)
    except OSError as exc:
        raise InstallError("the reviewed source directory is unavailable") from exc
    if not resolved.is_dir():
        raise InstallError("the reviewed source must be a directory")
    pyproject = resolved / "pyproject.toml"
    raw = _regular_owned_file(pyproject, maximum=MAX_MANIFEST_BYTES)
    try:
        project = tomllib.loads(raw.decode("utf-8")).get("project", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise InstallError("the source pyproject is invalid") from exc
    if not isinstance(project, dict) or project.get("name") != "megalodon-defense":
        raise InstallError("the source is not the MEGALODON package")
    if not (resolved / "megalodon" / "__init__.py").is_file():
        raise InstallError("the source package is incomplete")
    return resolved, raw


def _subprocess_environment(environment: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if environment is None else environment
    clean = {
        key: value for key, value in source.items()
        if not key.startswith("PIP_") or key in ALLOWED_PIP_ENV
    }
    for key in ("PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE", "VIRTUAL_ENV"):
        clean.pop(key, None)
    clean["PIP_CONFIG_FILE"] = os.devnull
    clean["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    clean["PIP_NO_CACHE_DIR"] = "1"
    clean["PYTHONNOUSERSITE"] = "1"
    return clean


def _run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=capture,
            timeout=600,
            env=_subprocess_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("the package installation command could not complete") from exc


def _release_id() -> str:
    version = re.sub(r"[^A-Za-z0-9._-]", "-", __version__)[:32] or "unknown"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{version}-{stamp}-{secrets.token_hex(4)}"


def _create_release(paths: InstallPaths, source: Path) -> tuple[str, dict[str, str]]:
    release_id = _release_id()
    release = paths.releases / release_id
    release.mkdir(mode=0o700)
    try:
        venv = release / "venv"
        if _run([sys.executable, "-I", "-m", "venv", str(venv)]).returncode != 0:
            raise InstallError("Python could not create the private application environment")
        python = venv / "bin" / "python"
        if _run([
            str(python), "-I", "-m", "pip", "install", "--disable-pip-version-check",
            "--no-deps", str(source),
        ]).returncode != 0:
            raise InstallError(
                "MEGALODON could not be installed; review the network and Python build-tool output above"
            )
        smoke = _run([
            str(python), "-I", "-c",
            "import json,megalodon,pathlib,sys;"
            "p=pathlib.Path(megalodon.__file__).resolve();"
            "root=pathlib.Path(sys.prefix).resolve();"
            "print(json.dumps({'version':megalodon.__version__,'inside':p.is_relative_to(root)}))",
        ], capture=True)
        if smoke.returncode != 0:
            raise InstallError("the installed application did not pass its import check")
        try:
            receipt = json.loads(smoke.stdout)
        except json.JSONDecodeError as exc:
            raise InstallError("the installed application returned an invalid import receipt") from exc
        if receipt != {"version": __version__, "inside": True}:
            raise InstallError("the installed package identity did not match this reviewed source")
        return release_id, {
            "id": release_id,
            "version": __version__,
            "installed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    except Exception:
        shutil.rmtree(release, ignore_errors=True)
        raise


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _default_settings(paths: InstallPaths) -> bytes:
    return (
        "# Created by the MEGALODON user installer. Review before editing.\n"
        "[app]\n"
        f"db_path = {_toml_string(str(paths.data / 'megalodon.db'))}\n\n"
        "[blocking]\n"
        "enabled = false\n"
        "dry_run = true\n"
        "auto_block = false\n\n"
        "[dashboard]\n"
        'host = "127.0.0.1"\n'
        "port = 8787\n"
    ).encode("utf-8")


def _ensure_settings(paths: InstallPaths) -> None:
    if not os.path.lexists(paths.settings):
        _atomic_write(paths.settings, _default_settings(paths), 0o600)
    _validate_settings(paths)


def _validate_settings(paths: InstallPaths) -> None:
    raw = _regular_owned_file(paths.settings, maximum=MAX_SETTINGS_BYTES)
    if paths.settings.stat().st_mode & 0o022:
        raise InstallError("installed settings must not be group- or world-writable")
    try:
        load_settings(paths.settings)
    except (OSError, ValueError) as exc:
        raise InstallError("installed settings are invalid; preserve and review them") from exc
    if not raw:
        raise InstallError("installed settings are empty")


def _desktop_exec(path: Path) -> str:
    value = str(path)
    # Desktop Entry strings consume one backslash layer before the Exec parser.
    # The file therefore needs two backslashes before Exec-reserved characters
    # and four for a literal path backslash.
    escaped = value.replace("\\", "\\\\\\\\")
    escaped = escaped.replace('"', '\\\\"').replace("`", "\\\\`").replace("$", "\\\\$")
    escaped = escaped.replace("%", "%%")
    return f'"{escaped}"'


def _artifact_contents(paths: InstallPaths) -> dict[str, bytes]:
    python = paths.current / "venv" / "bin" / "python"
    hud = (
        "#!/bin/sh\nset -eu\n"
        "export MEGALODON_INSTALL_MODE=desktop\n"
        f"export MEGALODON_LAUNCHER_PATH={shlex.quote(str(paths.hud_launcher))}\n"
        f"exec {shlex.quote(str(python))} -I -m megalodon hud --config "
        f"{shlex.quote(str(paths.settings))} --open-browser \"$@\"\n"
    ).encode("utf-8")
    manager = (
        "#!/bin/sh\nset -eu\n"
        f"exec {shlex.quote(str(python))} -I -m megalodon.local_install \"$@\"\n"
    ).encode("utf-8")
    desktop = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Version=1.0\n"
        "Name=MEGALODON\n"
        "GenericName=Local network evidence viewer\n"
        "Comment=Open the local, read-only MEGALODON control room\n"
        f"Exec={_desktop_exec(paths.hud_launcher)}\n"
        "Icon=megalodon\n"
        "Terminal=true\n"
        "Categories=System;Security;\n"
        "Keywords=network;security;evidence;local;\n"
        "StartupNotify=false\n"
    ).encode("utf-8")
    icon = resources.files("megalodon.assets").joinpath("megalodon.svg").read_bytes()
    return {
        "hud_launcher": hud,
        "manager_launcher": manager,
        "desktop_entry": desktop,
        "icon": icon,
    }


def _prepare_directories(paths: InstallPaths) -> None:
    _owned_directory(paths.app, private=True)
    _owned_directory(paths.releases, private=True)
    _owned_directory(paths.data, private=True)
    _owned_directory(paths.config, private=True)
    for parent in {
        paths.hud_launcher.parent,
        paths.desktop_entry.parent,
        paths.icon.parent,
    }:
        _owned_directory(parent, private=False)


@contextmanager
def _mutation_lock(paths: InstallPaths):
    lock_path = paths.app / ".install.lock"
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise InstallError("the installation maintenance lock is unavailable") from exc
    locked = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise InstallError("the installation maintenance lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallError("another installation maintenance action is already running") from exc
        locked = True
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _current_target(paths: InstallPaths) -> Path | None:
    if not os.path.lexists(paths.current):
        return None
    try:
        info = paths.current.lstat()
        if not stat.S_ISLNK(info.st_mode):
            raise InstallError("the active-release selector is not an installer symlink")
        target = Path(os.readlink(paths.current))
    except OSError as exc:
        raise InstallError("the active-release selector could not be read") from exc
    if not target.is_absolute():
        target = paths.current.parent / target
    return target


def _expected_release(paths: InstallPaths, release_id: str) -> Path:
    if RELEASE_ID.fullmatch(release_id) is None:
        raise InstallError("release identity is invalid")
    return paths.releases / release_id


def _activate(paths: InstallPaths, release_id: str, manifest: dict[str, object] | None) -> Path | None:
    old = _current_target(paths)
    if manifest is None:
        if old is not None:
            raise InstallError("an untracked active-release selector already exists")
    elif old != _expected_release(paths, str(manifest["active_release"])):
        raise InstallError("the active-release selector does not match the manifest")
    temporary = paths.app / f".current.tmp-{os.getpid()}-{secrets.token_hex(4)}"
    os.symlink(_expected_release(paths, release_id), temporary)
    try:
        os.replace(temporary, paths.current)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return old


def _restore_active(paths: InstallPaths, old: Path | None) -> None:
    temporary = paths.app / f".current.restore-{os.getpid()}-{secrets.token_hex(4)}"
    if old is None:
        try:
            paths.current.unlink()
        except FileNotFoundError:
            pass
        return
    os.symlink(old, temporary)
    try:
        os.replace(temporary, paths.current)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def install(source: Path, paths: InstallPaths | None = None) -> dict[str, object]:
    _require_supported_user()
    selected = install_paths() if paths is None else paths
    source, pyproject = _validated_source(source)
    _prepare_directories(selected)
    with _mutation_lock(selected):
        return _install_selected(source, pyproject, selected)


def _install_selected(source: Path, pyproject: bytes, selected: InstallPaths) -> dict[str, object]:
    existing = _load_manifest(selected)
    if existing is not None and len(existing["releases"]) >= 32:
        raise InstallError("the install history is full; uninstall the managed code before reinstalling")
    previous_bytes: dict[str, bytes | None] = {}
    modes = _artifact_modes()
    for name, path in _artifact_paths(selected).items():
        expected = None if existing is None else str(existing["artifacts"][name]["sha256"])
        previous_bytes[name] = _guard_artifact(path, expected, modes[name])
    _ensure_settings(selected)
    release_id, release = _create_release(selected, source)
    contents = _artifact_contents(selected)
    old_target: Path | None = None
    activated = False
    try:
        for name, path in _artifact_paths(selected).items():
            _atomic_write(path, contents[name], modes[name])
        old_target = _activate(selected, release_id, existing)
        activated = True
        releases = [] if existing is None else list(existing["releases"])
        releases.append(release)
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "active_release": release_id,
            "previous_release": None if existing is None else existing["active_release"],
            "version": __version__,
            "installed_at": release["installed_at"],
            "source": {"kind": "local_checkout", "pyproject_sha256": _digest(pyproject)},
            "artifacts": {
                name: {"path": str(path), "sha256": _digest(contents[name])}
                for name, path in _artifact_paths(selected).items()
            },
            "releases": releases,
        }
        _atomic_write(
            selected.manifest,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
            0o600,
        )
        return manifest
    except Exception:
        if activated:
            _restore_active(selected, old_target)
        for name, path in _artifact_paths(selected).items():
            prior = previous_bytes[name]
            if prior is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                _atomic_write(path, prior, modes[name])
        shutil.rmtree(_expected_release(selected, release_id), ignore_errors=True)
        raise


def _artifact_health(paths: InstallPaths, manifest: dict[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    modes = _artifact_modes()
    for name, path in _artifact_paths(paths).items():
        if not os.path.lexists(path):
            result[name] = "missing"
            continue
        try:
            raw = _regular_owned_file(path, maximum=MAX_MANIFEST_BYTES)
        except InstallError:
            result[name] = "unsafe"
            continue
        result[name] = "ready" if (
            _digest(raw) == manifest["artifacts"][name]["sha256"]
            and stat.S_IMODE(path.lstat().st_mode) == modes[name]
        ) else "modified"
    return result


def status(paths: InstallPaths | None = None) -> tuple[int, dict[str, object]]:
    _require_supported_user()
    selected = install_paths() if paths is None else paths
    manifest = _load_manifest(selected)
    if manifest is None:
        return 1, {"schema": "megalodon-local-status-v1", "status": "not_installed"}
    artifacts = _artifact_health(selected, manifest)
    expected = _expected_release(selected, str(manifest["active_release"]))
    try:
        current = _current_target(selected)
    except InstallError:
        current = None
    python = expected / "venv" / "bin" / "python"
    release_ready = current == expected and python.is_file() and os.access(python, os.X_OK)
    settings_ready = False
    try:
        _validate_settings(selected)
        settings_ready = True
    except InstallError:
        pass
    ready = release_ready and settings_ready and set(artifacts.values()) == {"ready"}
    receipt = {
        "schema": "megalodon-local-status-v1",
        "status": "ready" if ready else "needs_repair",
        "version": manifest["version"],
        "release": "ready" if release_ready else "needs_attention",
        "settings": "ready" if settings_ready else "needs_attention",
        "artifacts": artifacts,
        "data": "preserved" if selected.data.is_dir() else "needs_attention",
    }
    return (0 if ready else 2), receipt


def repair(paths: InstallPaths | None = None) -> dict[str, object]:
    _require_supported_user()
    selected = install_paths() if paths is None else paths
    _prepare_directories(selected)
    with _mutation_lock(selected):
        return _repair_selected(selected)


def _repair_selected(selected: InstallPaths) -> dict[str, object]:
    manifest = _load_manifest(selected)
    if manifest is None:
        raise InstallError("MEGALODON is not installed for this user")
    expected = _expected_release(selected, str(manifest["active_release"]))
    python = expected / "venv" / "bin" / "python"
    if not python.is_file() or not os.access(python, os.X_OK):
        raise InstallError("the active application release is incomplete; reinstall from a reviewed checkout")
    current = _current_target(selected)
    if current is not None and current != expected:
        raise InstallError("the active-release selector was modified")
    health = _artifact_health(selected, manifest)
    if any(value in {"modified", "unsafe"} for value in health.values()):
        raise InstallError("an installed artifact was modified; preserve and review it before repair")
    contents = _artifact_contents(selected)
    for name in _artifact_paths(selected):
        if _digest(contents[name]) != manifest["artifacts"][name]["sha256"]:
            raise InstallError("this manager version cannot safely rewrite the installed artifacts")
    _ensure_settings(selected)
    for name, path in _artifact_paths(selected).items():
        if health[name] == "missing":
            _atomic_write(path, contents[name], _artifact_modes()[name])
    if current is None:
        _activate(selected, str(manifest["active_release"]), None)
    code, receipt = status(selected)
    if code != 0:
        raise InstallError("the installation still needs attention after repair")
    return receipt


def uninstall(paths: InstallPaths | None = None) -> dict[str, object]:
    _require_supported_user()
    selected = install_paths() if paths is None else paths
    if not os.path.lexists(selected.manifest):
        return {"schema": "megalodon-local-uninstall-v1", "status": "not_installed", "data": "preserved"}
    _owned_directory(selected.app, private=True)
    with _mutation_lock(selected):
        return _uninstall_selected(selected)


def _uninstall_selected(selected: InstallPaths) -> dict[str, object]:
    manifest = _load_manifest(selected)
    if manifest is None:
        return {"schema": "megalodon-local-uninstall-v1", "status": "not_installed", "data": "preserved"}
    health = _artifact_health(selected, manifest)
    if any(value not in {"ready", "missing"} for value in health.values()):
        raise InstallError("an installed artifact was modified; preserve and review it before uninstall")
    expected = _expected_release(selected, str(manifest["active_release"]))
    if _current_target(selected) != expected:
        raise InstallError("the active-release selector does not match the installed manifest")
    release_paths = [_expected_release(selected, str(item["id"])) for item in manifest["releases"]]
    existing_releases: list[Path] = []
    for release in release_paths:
        if os.path.lexists(release):
            info = release.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise InstallError("an installed release directory is unsafe")
            existing_releases.append(release)
    for name, path in _artifact_paths(selected).items():
        if health[name] == "ready":
            path.unlink()
    selected.current.unlink()
    for release in existing_releases:
        shutil.rmtree(release)
    selected.manifest.unlink()
    try:
        selected.releases.rmdir()
    except OSError:
        pass
    return {"schema": "megalodon-local-uninstall-v1", "status": "removed", "data": "preserved"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="megalodon-local-install",
        description="Install and maintain the local MEGALODON desktop launcher for this user.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install", help="install or upgrade from a reviewed checkout")
    install_parser.add_argument("--source", type=Path, required=True)
    status_parser = commands.add_parser("status", help="check the installed release and desktop artifacts")
    status_parser.add_argument("--json", action="store_true", help="print the bounded status receipt as JSON")
    commands.add_parser("repair", help="restore missing managed launchers without changing data")
    commands.add_parser("uninstall", help="remove managed code and launchers while preserving data and settings")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "install":
            result = install(args.source)
            print(f"MEGALODON {result['version']} is installed for this user.")
            print("Open MEGALODON from your application menu, or run megalodon-hud.")
            print("Use ~/.local/bin/megalodon-manage status to check the installation.")
            return 0
        if args.command == "status":
            code, result = status()
            if args.json:
                print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            elif result["status"] == "not_installed":
                print("MEGALODON is not installed for this user.")
            else:
                print(f"MEGALODON desktop installation: {result['status']}")
                print(f"Version: {result['version']}")
                print(f"Application release: {result['release']}; settings: {result['settings']}")
            return code
        if args.command == "repair":
            repair()
            print("MEGALODON launchers are ready. Data and settings were preserved.")
            return 0
        result = uninstall()
        if result["status"] == "not_installed":
            print("MEGALODON was not installed for this user. Data and settings were unchanged.")
        else:
            print("MEGALODON code and launchers were removed. Local data and settings were preserved.")
        return 0
    except InstallError as exc:
        print(f"megalodon installer: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
