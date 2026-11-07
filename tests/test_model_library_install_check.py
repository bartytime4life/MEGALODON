"""Synthetic installed-package observations; no installation, imports or sockets."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux installed-source observation")


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("model_library_install_check", ROOT / "tools/check_model_library_install.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


@pytest.fixture
def package(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    data = {"first.py": b"inert first source", "second.py": b"inert second source"}
    for name, raw in data.items():
        (package / name).write_bytes(raw)
    # Must not import this untrusted installed package to locate/check it.
    (package / "__init__.py").write_text("raise RuntimeError('installed package executed')")
    monkeypatch.setattr(check, "EXPECTED", {name: sha256(raw).hexdigest() for name, raw in data.items()})
    return package


def test_pins_match_the_merged_package_source():
    assert len(check.EXPECTED) == 6
    assert all(sha256((ROOT / "megalodon" / name).read_bytes()).hexdigest() == value
               for name, value in check.EXPECTED.items())


def test_source_check_has_no_write_network_process_or_installed_import(package, monkeypatch):
    def forbidden(*_a, **_kw): pytest.fail("source check caused an unexpected effect")
    original_open = os.open
    def read_only(path, flags, *args, **kw):
        assert flags & os.O_ACCMODE == os.O_RDONLY
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return original_open(path, flags, *args, **kw)
    monkeypatch.setattr(os, "open", read_only)
    for owner, names in [(os, ["write", "mkdir", "unlink", "replace", "chmod", "system"]),
                         (socket, ["socket", "getaddrinfo", "create_connection"]),
                         (subprocess, ["Popen", "run"])]:
        for name in names: monkeypatch.setattr(owner, name, forbidden)
    result = check.observe(package)
    assert result["state"] == "SOURCE_FILES_MATCH"
    assert not any(result["authority"].values())
    assert result["runtime_acceptance"] == "NOT_EVALUATED"
    assert str(package) not in json.dumps(result)


@pytest.mark.parametrize("kind,state", [("missing", "MISSING"), ("modified", "MISMATCH"),
    ("symlink", "UNAVAILABLE"), ("fifo", "UNSAFE_OR_OVERSIZED"), ("oversized", "UNSAFE_OR_OVERSIZED")])
def test_bad_source_never_matches_or_runs_installed_code(package, kind, state):
    file = package / "first.py"
    if kind == "modified": file.write_bytes(b"modified")
    else:
        file.unlink()
        if kind == "symlink": file.symlink_to(package / "second.py")
        elif kind == "fifo": os.mkfifo(file)
        elif kind == "oversized":
            with file.open("wb") as out: out.truncate(check.MAX_FILE_BYTES + 1)
    result = check.observe(package)
    assert result["state"] == "SOURCE_FILES_DO_NOT_MATCH"
    assert result["files"][0]["state"] == state


def test_source_change_after_its_read_invalidates_the_whole_observation(package, monkeypatch):
    original = check.file_observation
    def read(parent, name, expected):
        result = original(parent, name, expected)
        if name == "second.py": (package / "first.py").write_bytes(b"changed after first read")
        return result
    monkeypatch.setattr(check, "file_observation", read)
    result = check.observe(package)
    assert result["state"] == "UNAVAILABLE" and result["files"] == []
    assert result["error_code"] == "SOURCE_FILES_CHANGED"


def test_parent_symlink_refuses(package, tmp_path):
    link = tmp_path / "linked"
    link.symlink_to(package, target_is_directory=True)
    result = check.observe(link)
    assert result["state"] == "UNAVAILABLE" and result["files"] == []


def test_directory_replacement_refuses(package, monkeypatch):
    original = check.file_observation
    def read(parent, name, expected):
        result = original(parent, name, expected)
        if name == "second.py":
            package.rename(package.with_name("previous"))
            package.mkdir()
        return result
    monkeypatch.setattr(check, "file_observation", read)
    result = check.observe(package)
    assert result["state"] == "UNAVAILABLE" and result["files"] == []


@pytest.mark.parametrize("path", ["relative/package", "/tmp/../private", "//host/package"])
def test_ambiguous_paths_refuse_before_open(path, monkeypatch):
    monkeypatch.setattr(os, "open", lambda *_a, **_kw: pytest.fail("invalid path opened"))
    result = check.observe(Path(path))
    assert result["state"] == "UNAVAILABLE" and result["error_code"] == "ABSOLUTE_PACKAGE_DIRECTORY_REQUIRED"


def test_managed_discovery_is_bounded_and_does_not_import_a_package(tmp_path):
    app = tmp_path / ".local/share/megalodon"
    release = app / "releases/synthetic"
    package = release / "venv/lib/python3.11/site-packages/megalodon"
    package.mkdir(parents=True)
    (app / "current").symlink_to(release, target_is_directory=True)
    assert check.managed_package(home=tmp_path) == package
    (release / "venv/lib/python3.12/site-packages/megalodon").mkdir(parents=True)
    with pytest.raises(check.CheckError, match="AMBIGUOUS_INSTALLATION"):
        check.managed_package(home=tmp_path)


def test_managed_discovery_rejects_a_selector_outside_releases(tmp_path):
    app = tmp_path / ".local/share/megalodon"
    (app / "releases").mkdir(parents=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (app / "current").symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(check.CheckError, match="INSTALLATION_UNAVAILABLE"):
        check.managed_package(home=tmp_path)


def test_cli_output_is_path_free_and_exit_code_does_not_claim_acceptance(package, capsys):
    assert check.main(["--package-dir", str(package)]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["runtime_acceptance"] == "NOT_EVALUATED"
    assert str(package) not in json.dumps(receipt)
    (package / "first.py").unlink()
    assert check.main(["--package-dir", str(package)]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "SOURCE_FILES_DO_NOT_MATCH"


def managed_fixture(home, package, name="selected"):
    app = home / ".local/share/megalodon"
    release = app / "releases" / name
    target = release / "venv/lib/python3.11/site-packages/megalodon"
    target.parent.mkdir(parents=True)
    import shutil
    shutil.copytree(package, target)
    return app, release, target


@pytest.mark.parametrize("relative", [False, True])
def test_managed_cli_accepts_standard_selector_without_installed_import(package, tmp_path, monkeypatch, capsys, relative):
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(Path("releases/selected") if relative else release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    assert check.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "SOURCE_FILES_MATCH"
    assert str(tmp_path) not in json.dumps(result)


@pytest.mark.parametrize("replacement", ["different_release", "same_target_new_link"])
def test_managed_cli_refuses_selector_change_during_observation(package, tmp_path, monkeypatch, capsys, replacement):
    app, release, target = managed_fixture(tmp_path, package)
    _, other_release, other = managed_fixture(tmp_path, package, "other")
    (other / "first.py").write_bytes(b"different selected files")
    current = app / "current"
    current.symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    original = check.observe
    def observe(selected):
        current.unlink()
        current.symlink_to(other_release if replacement == "different_release" else release)
        return original(selected)
    monkeypatch.setattr(check, "observe", observe)
    assert check.main([]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNAVAILABLE"
    assert result["error_code"] == "INSTALLATION_CHANGED"
    assert result.get("files", []) == []
    assert str(tmp_path) not in json.dumps(result)


@pytest.mark.parametrize("linked", ["app", "releases", "release", "venv", "python"])
def test_managed_cli_refuses_symlinked_ancestry_before_reading_sources(package, tmp_path, monkeypatch, capsys, linked):
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(release)
    selected = {"app": app, "releases": app / "releases", "release": release,
                "venv": release / "venv", "python": release / "venv/lib/python3.11"}[linked]
    outside = tmp_path / "outside"
    selected.rename(outside)
    selected.symlink_to(outside)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    def forbidden(*_a, **_kw):
        pytest.fail("linked managed ancestry reached source-file reads")
    monkeypatch.setattr(check, "file_observation", forbidden)
    assert check.main([]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNAVAILABLE"
    assert str(tmp_path) not in json.dumps(result)


def test_managed_cli_refuses_replaced_releases_directory_after_source_read(package, tmp_path, monkeypatch, capsys):
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    original = check.observe
    def observe(selected):
        result = original(selected)
        (app / "releases").rename(app / "previous-releases")
        (app / "releases").mkdir()
        return result
    monkeypatch.setattr(check, "observe", observe)
    assert check.main([]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNAVAILABLE"
    assert result["error_code"] == "INSTALLATION_CHANGED"


def test_managed_cli_refuses_relative_xdg_before_source_reads(package, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", ".local/share")
    monkeypatch.setattr(check, "file_observation", lambda *_a, **_kw: pytest.fail("relative XDG reached source reads"))
    assert check.main([]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "UNAVAILABLE"


def test_managed_cli_has_no_write_network_process_or_installed_import(package, tmp_path, monkeypatch, capsys):
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    def forbidden(*_a, **_kw):
        pytest.fail("managed observation caused an unexpected effect")
    original_open = os.open
    def read_only(path, flags, *args, **kw):
        assert flags & os.O_ACCMODE == os.O_RDONLY
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return original_open(path, flags, *args, **kw)
    monkeypatch.setattr(os, "open", read_only)
    for owner, names in [(os, ["write", "mkdir", "unlink", "replace", "chmod", "system"]),
                         (socket, ["socket", "getaddrinfo", "create_connection"]),
                         (subprocess, ["Popen", "run"])]:
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)
    assert check.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "SOURCE_FILES_MATCH"
    assert not any(result["authority"].values())
    assert str(tmp_path) not in json.dumps(result)


def test_managed_cli_refuses_package_replacement_after_discovery(package, tmp_path, monkeypatch, capsys):
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    original = check.observe
    def observe(selected):
        import shutil
        target.rename(target.with_name("previous"))
        shutil.copytree(target.with_name("previous"), target)
        return original(selected)
    monkeypatch.setattr(check, "observe", observe)
    assert check.main([]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNAVAILABLE"
    assert result["error_code"] == "INSTALLATION_CHANGED"


def test_managed_cli_refuses_nested_release_selector(package, tmp_path, monkeypatch, capsys):
    app, release, target = managed_fixture(tmp_path, package, "nested/selected")
    (app / "current").symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    monkeypatch.setattr(check, "file_observation", lambda *_a, **_kw: pytest.fail("nonstandard release reached source reads"))
    assert check.main([]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "UNAVAILABLE"


def test_managed_cli_refuses_new_package_version_during_observation(package, tmp_path, monkeypatch, capsys):
    app, release, target = managed_fixture(tmp_path, package)
    (app / "current").symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    original = check.observe
    def observe(selected):
        result = original(selected)
        (release / "venv/lib/python3.12/site-packages/megalodon").mkdir(parents=True)
        return result
    monkeypatch.setattr(check, "observe", observe)
    assert check.main([]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNAVAILABLE"
    assert result["error_code"] == "INSTALLATION_CHANGED"


def test_managed_cli_checks_selector_after_directory_revalidation(package, tmp_path, monkeypatch, capsys):
    from contextlib import contextmanager
    app, release, target = managed_fixture(tmp_path, package)
    _, other_release, _ = managed_fixture(tmp_path, package, "other")
    current = app / "current"
    current.symlink_to(release)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / ".local/share"))
    original_observe, original_directory = check.observe, check.directory
    state = dict(read_complete=False, switched=False)
    def observe(selected):
        result = original_observe(selected)
        state["read_complete"] = True
        return result
    @contextmanager
    def directory(path):
        with original_directory(path) as fd:
            if Path(path) == app and state["read_complete"] and not state["switched"]:
                current.unlink()
                current.symlink_to(other_release)
                state["switched"] = True
            yield fd
    monkeypatch.setattr(check, "observe", observe)
    monkeypatch.setattr(check, "directory", directory)
    assert check.main([]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "UNAVAILABLE"
    assert result["error_code"] == "INSTALLATION_CHANGED"
