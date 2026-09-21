"""User installation owns bounded artifacts and preserves local data."""

from __future__ import annotations

from pathlib import Path
import os
import shutil
import subprocess

import pytest

from megalodon import __version__, local_install


@pytest.fixture
def layout(tmp_path, monkeypatch):
    home = tmp_path / "home with % sign"
    home.mkdir()
    home.chmod(0o700)
    paths = local_install.install_paths({
        "HOME": str(home),
        "XDG_DATA_HOME": str(home / "share"),
        "XDG_CONFIG_HOME": str(home / "config"),
    })
    monkeypatch.setattr(local_install, "_require_supported_user", lambda: None)
    return paths


@pytest.fixture
def source(tmp_path):
    checkout = tmp_path / "reviewed checkout"
    package = checkout / "megalodon"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(f'__version__ = "{__version__}"\n')
    (checkout / "pyproject.toml").write_text(
        '[build-system]\nrequires=["setuptools>=77"]\nbuild-backend="setuptools.build_meta"\n'
        '[project]\nname="megalodon-defense"\nversion="0.0.0"\n'
    )
    return checkout


def release_factory(paths, ids):
    def create(_paths, _source):
        release_id = next(ids)
        release = paths.releases / release_id
        python = release / "venv" / "bin" / "python"
        python.parent.mkdir(parents=True)
        python.write_text("synthetic interpreter")
        python.chmod(0o755)
        return release_id, {
            "id": release_id,
            "version": __version__,
            "installed_at": "2026-09-20T12:00:00Z",
        }
    return create


def test_paths_require_absolute_xdg_values(tmp_path):
    with pytest.raises(local_install.InstallError, match="XDG_DATA_HOME"):
        local_install.install_paths({"HOME": str(tmp_path), "XDG_DATA_HOME": "relative"})


def test_shell_entry_ignores_python_environment_overrides():
    source = (Path(__file__).parents[1] / "scripts" / "install-local.sh").read_text()
    assert '"$1" -I -c' in source
    assert 'exec "$local_python" -E -s -m megalodon.local_install install' in source
    assert 'exec "$local_python" -E -s -m megalodon.local_install "$@"' in source


def test_installation_directories_reject_symlinked_ancestors_and_writable_public_leaf(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)
    with pytest.raises(local_install.InstallError, match="ancestry is unsafe"):
        local_install._owned_directory(linked / "app", private=True)

    public = tmp_path / "public"
    public.mkdir()
    public.chmod(0o777)
    with pytest.raises(local_install.InstallError, match="group- or world-writable"):
        local_install._owned_directory(public, private=False)

    unsafe_parent = tmp_path / "unsafe-parent"
    unsafe_parent.mkdir()
    unsafe_parent.chmod(0o777)
    safe_leaf = unsafe_parent / "bin"
    safe_leaf.mkdir()
    safe_leaf.chmod(0o755)
    with pytest.raises(local_install.InstallError, match="ancestry is group- or world-writable"):
        local_install._owned_directory(safe_leaf, private=False)


def test_desktop_exec_quotes_spaces_dollars_and_field_codes():
    encoded = local_install._desktop_exec(Path('/home/a b/$tools/100%/app"name\\dir'))
    assert encoded == r'"/home/a b/\\$tools/100%%/app\\"name\\\\dir"'


def test_subprocess_environment_blocks_destination_and_python_import_overrides():
    clean = local_install._subprocess_environment({
        "PATH": "/usr/bin",
        "PIP_TARGET": "/tmp/escape-target",
        "PIP_PREFIX": "/tmp/escape-prefix",
        "PIP_USER": "1",
        "PIP_CONFIG_FILE": "/tmp/escape-config",
        "PIP_INDEX_URL": "https://packages.example/simple",
        "PYTHONPATH": "/tmp/import-escape",
        "PYTHONUSERBASE": "/tmp/userbase-escape",
    })
    assert clean["PATH"] == "/usr/bin"
    assert clean["PIP_INDEX_URL"] == "https://packages.example/simple"
    assert clean["PIP_CONFIG_FILE"] == os.devnull
    assert clean["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    assert clean["PIP_NO_CACHE_DIR"] == "1"
    assert clean["PYTHONNOUSERSITE"] == "1"
    for key in ("PIP_TARGET", "PIP_PREFIX", "PIP_USER", "PYTHONPATH", "PYTHONUSERBASE"):
        assert key not in clean


def test_install_repair_status_and_uninstall_preserve_data_and_settings(
    layout, source, monkeypatch
):
    monkeypatch.setattr(
        local_install,
        "_create_release",
        release_factory(layout, iter(["1.0-20260920T120000Z-a1b2c3d4"])),
    )
    manifest = local_install.install(source, layout)
    assert manifest["schema"] == local_install.MANIFEST_SCHEMA
    assert layout.current.is_symlink()
    assert Path(layout.current.readlink()) == layout.releases / manifest["active_release"]
    assert layout.hud_launcher.stat().st_mode & 0o111
    assert " -I -m megalodon hud " in layout.hud_launcher.read_text()
    assert "--open-browser" in layout.hud_launcher.read_text()
    assert "MEGALODON_INSTALL_MODE=desktop" in layout.hud_launcher.read_text()
    assert " -I -m megalodon.local_install " in layout.manager_launcher.read_text()
    assert "Terminal=true" in layout.desktop_entry.read_text()
    assert "Exec=" + local_install._desktop_exec(layout.hud_launcher) in layout.desktop_entry.read_text()
    assert layout.icon.read_text().startswith("<svg")

    marker = layout.data / "keep.db"
    marker.write_bytes(b"operator data")
    settings_before = layout.settings.read_bytes()
    code, receipt = local_install.status(layout)
    assert code == 0
    assert receipt["status"] == "ready"
    assert set(receipt["artifacts"].values()) == {"ready"}

    layout.desktop_entry.unlink()
    repaired = local_install.repair(layout)
    assert repaired["status"] == "ready"
    assert marker.read_bytes() == b"operator data"
    assert layout.settings.read_bytes() == settings_before

    removed = local_install.uninstall(layout)
    assert removed == {
        "schema": "megalodon-local-uninstall-v1",
        "status": "removed",
        "data": "preserved",
    }
    assert not layout.hud_launcher.exists()
    assert not layout.manager_launcher.exists()
    assert not layout.desktop_entry.exists()
    assert marker.read_bytes() == b"operator data"
    assert layout.settings.read_bytes() == settings_before


def test_upgrade_rolls_back_selection_and_artifacts_if_manifest_write_fails(
    layout, source, monkeypatch
):
    ids = iter([
        "1.0-20260920T120000Z-a1b2c3d4",
        "1.0-20260920T120100Z-e5f6a7b8",
    ])
    monkeypatch.setattr(local_install, "_create_release", release_factory(layout, ids))
    first = local_install.install(source, layout)
    first_manifest = layout.manifest.read_bytes()
    first_launcher = layout.hud_launcher.read_bytes()
    real_write = local_install._atomic_write

    def fail_manifest(path, value, mode):
        if path == layout.manifest:
            raise OSError("synthetic manifest failure")
        return real_write(path, value, mode)

    monkeypatch.setattr(local_install, "_atomic_write", fail_manifest)
    with pytest.raises(OSError, match="synthetic"):
        local_install.install(source, layout)
    assert layout.manifest.read_bytes() == first_manifest
    assert layout.hud_launcher.read_bytes() == first_launcher
    assert Path(layout.current.readlink()) == layout.releases / first["active_release"]
    assert not (layout.releases / "1.0-20260920T120100Z-e5f6a7b8").exists()


def test_modified_managed_file_blocks_repair_and_uninstall(layout, source, monkeypatch):
    monkeypatch.setattr(
        local_install,
        "_create_release",
        release_factory(layout, iter(["1.0-20260920T120000Z-a1b2c3d4"])),
    )
    local_install.install(source, layout)
    layout.hud_launcher.write_text("user replacement")
    with pytest.raises(local_install.InstallError, match="modified"):
        local_install.repair(layout)
    with pytest.raises(local_install.InstallError, match="modified"):
        local_install.uninstall(layout)
    assert layout.manifest.exists()
    assert layout.current.is_symlink()


def test_changed_launcher_mode_is_not_reported_ready_or_silently_repaired(
    layout, source, monkeypatch
):
    monkeypatch.setattr(
        local_install,
        "_create_release",
        release_factory(layout, iter(["1.0-20260920T120000Z-a1b2c3d4"])),
    )
    local_install.install(source, layout)
    layout.hud_launcher.chmod(0o644)
    code, receipt = local_install.status(layout)
    assert code == 2
    assert receipt["artifacts"]["hud_launcher"] == "modified"
    with pytest.raises(local_install.InstallError, match="modified"):
        local_install.repair(layout)
    with pytest.raises(local_install.InstallError, match="modified"):
        local_install.uninstall(layout)


def test_non_executable_release_interpreter_needs_reinstall(layout, source, monkeypatch):
    monkeypatch.setattr(
        local_install,
        "_create_release",
        release_factory(layout, iter(["1.0-20260920T120000Z-a1b2c3d4"])),
    )
    manifest = local_install.install(source, layout)
    python = layout.releases / manifest["active_release"] / "venv" / "bin" / "python"
    python.chmod(0o644)
    code, receipt = local_install.status(layout)
    assert code == 2
    assert receipt["release"] == "needs_attention"
    with pytest.raises(local_install.InstallError, match="release is incomplete"):
        local_install.repair(layout)


def test_repair_checks_all_generated_hashes_before_restoring_a_missing_file(
    layout, source, monkeypatch
):
    monkeypatch.setattr(
        local_install,
        "_create_release",
        release_factory(layout, iter(["1.0-20260920T120000Z-a1b2c3d4"])),
    )
    local_install.install(source, layout)
    layout.desktop_entry.unlink()
    original = local_install._artifact_contents

    def changed(paths):
        values = original(paths)
        values["desktop_entry"] += b"X-Changed=true\n"
        return values

    monkeypatch.setattr(local_install, "_artifact_contents", changed)
    with pytest.raises(local_install.InstallError, match="cannot safely rewrite"):
        local_install.repair(layout)
    assert not layout.desktop_entry.exists()


def test_untracked_destination_refuses_before_release_creation(layout, source, monkeypatch):
    local_install._owned_directory(layout.hud_launcher.parent, private=False)
    layout.hud_launcher.write_text("unrelated")
    monkeypatch.setattr(
        local_install,
        "_create_release",
        lambda *_: pytest.fail("release must not be created"),
    )
    with pytest.raises(local_install.InstallError, match="untracked file"):
        local_install.install(source, layout)
    assert layout.hud_launcher.read_text() == "unrelated"


@pytest.mark.parametrize("release_id", [".", "..", "../outside", "/absolute", "-leading"])
def test_release_identity_cannot_escape_the_release_directory(layout, release_id):
    with pytest.raises(local_install.InstallError, match="release identity"):
        local_install._expected_release(layout, release_id)


def test_status_without_manifest_is_read_only(layout):
    code, receipt = local_install.status(layout)
    assert code == 1
    assert receipt["status"] == "not_installed"
    assert not layout.app.exists()
    assert not layout.config.exists()


def test_uninstall_completes_when_a_manifest_release_is_already_missing(
    layout, source, monkeypatch
):
    ids = iter([
        "1.0-20260920T120000Z-a1b2c3d4",
        "1.0-20260920T120100Z-e5f6a7b8",
    ])
    monkeypatch.setattr(local_install, "_create_release", release_factory(layout, ids))
    first = local_install.install(source, layout)
    second = local_install.install(source, layout)
    shutil.rmtree(layout.releases / first["active_release"])
    shutil.rmtree(layout.releases / second["active_release"])
    marker = layout.data / "keep.db"
    marker.write_bytes(b"operator data")

    assert local_install.uninstall(layout)["status"] == "removed"
    assert marker.read_bytes() == b"operator data"
    assert not layout.manifest.exists()


def test_mutating_actions_refuse_an_overlapping_maintenance_lock(layout):
    local_install._prepare_directories(layout)
    with local_install._mutation_lock(layout):
        with pytest.raises(local_install.InstallError, match="already running"):
            local_install.repair(layout)


def test_root_install_is_refused(monkeypatch, source):
    monkeypatch.setattr(local_install.os, "geteuid", lambda: 0)
    with pytest.raises(local_install.InstallError, match="not root"):
        local_install.install(source)


def test_release_creation_uses_private_venv_and_installed_import(layout, source, monkeypatch):
    local_install._prepare_directories(layout)
    calls = []

    def run(command, *, capture=False):
        calls.append(command)
        if command[1:4] == ["-I", "-m", "venv"]:
            python = Path(command[-1]) / "bin" / "python"
            python.parent.mkdir(parents=True)
            python.write_text("synthetic")
            return subprocess.CompletedProcess(command, 0, "", "")
        if capture:
            return subprocess.CompletedProcess(
                command, 0, f'{{"version":"{__version__}","inside":true}}\n', ""
            )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(local_install, "_run", run)
    monkeypatch.setattr(
        local_install,
        "_release_id",
        lambda: "1.0-20260920T120000Z-a1b2c3d4",
    )
    release_id, receipt = local_install._create_release(layout, source)
    assert release_id == receipt["id"]
    assert calls[0][1:4] == ["-I", "-m", "venv"]
    assert calls[1][1:4] == ["-I", "-m", "pip"]
    assert calls[1][-2:] == ["--no-deps", str(source)]
    assert calls[2][1:3] == ["-I", "-c"]
    assert (layout.releases / release_id / "venv" / "bin" / "python").exists()
