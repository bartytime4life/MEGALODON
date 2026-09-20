"""Manual launch and preflight must preserve data and the reader's refusals."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from megalodon import local_setup
from megalodon.storage import Store


def test_preflight_missing_data_does_not_create_it(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(local_setup.sys, "platform", "linux")
    assert local_setup.main() == 0
    output = capsys.readouterr().out
    assert "not configured" in output
    # An installed wheel has no checkout script: its next command must work too.
    assert shlex.join([sys.executable, "-m", "megalodon", "hud"]) in output
    assert not (tmp_path / "data").exists()


def test_preflight_reads_existing_store_without_changing_it(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "data" / "megalodon.db"
    with Store(path):
        pass
    before = path.read_bytes()
    assert local_setup.main() == 0
    assert "bounded read-only check" in capsys.readouterr().out
    assert path.read_bytes() == before


def test_preflight_refuses_invalid_store(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "data" / "megalodon.db"
    path.parent.mkdir(mode=0o700)
    path.write_bytes(b"not a database")
    path.chmod(0o600)
    assert local_setup.main() == 2
    assert "refused" in capsys.readouterr().err
    assert path.read_bytes() == b"not a database"


def test_preflight_does_not_claim_unsupported_platform(monkeypatch, capsys):
    monkeypatch.setattr(local_setup.sys, "platform", "win32")
    assert local_setup.main() == 2
    assert "Linux only" in capsys.readouterr().err


@pytest.fixture
def launcher(tmp_path):
    if os.name != "posix" or shutil.which("bash") is None:
        pytest.skip("Bash checkout launcher requires POSIX")
    checkout = tmp_path / "checkout with spaces"
    script = checkout / "scripts" / "start-local.sh"
    script.parent.mkdir(parents=True)
    source = Path(__file__).resolve().parents[1] / "scripts" / "start-local.sh"
    shutil.copy2(source, script)
    package = checkout / "megalodon"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "__main__.py").write_text(
        "import os, sys, json\nprint(json.dumps([os.getcwd(), sys.argv[1:]]))\n"
    )
    return script


def test_launcher_works_outside_checkout_and_keeps_arguments_literal(launcher, tmp_path):
    argument = "/tmp/one ' $(touch NEVER_EXECUTE)"
    result = subprocess.run(
        ["bash", str(launcher), "--offline-run", argument], cwd=tmp_path,
        env={**os.environ, "MEGALODON_PYTHON": sys.executable},
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout.splitlines()[-1]) == [
        str(launcher.parent.parent), ["hud", "--offline-run", argument]
    ]
    assert not (launcher.parent.parent / "NEVER_EXECUTE").exists()


def test_launcher_skips_incompatible_environment(launcher):
    checkout = launcher.parent.parent
    old_python = checkout / ".venv312" / "bin" / "python"
    old_python.parent.mkdir(parents=True)
    old_python.write_text("#!/bin/sh\nexit 1\n")
    old_python.chmod(0o755)
    current = checkout / ".venv" / "bin" / "python"
    current.parent.mkdir(parents=True)
    current.symlink_to(sys.executable)
    env = {k: v for k, v in os.environ.items() if k != "MEGALODON_PYTHON"}
    result = subprocess.run(["bash", str(launcher)], env=env, text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert str(current) in result.stdout


def test_launcher_explicit_invalid_python_fails_without_fallback(launcher):
    result = subprocess.run(
        ["bash", str(launcher)],
        env={**os.environ, "MEGALODON_PYTHON": "/not/an/interpreter"},
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 2
    assert "MEGALODON_PYTHON" in result.stderr


def test_launcher_rejects_check_options_instead_of_ignoring_them(launcher):
    result = subprocess.run(
        ["bash", str(launcher), "--check", "--config", "/tmp/other.toml"],
        env={**os.environ, "MEGALODON_PYTHON": sys.executable},
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 2
    assert "accepts no HUD options" in result.stderr
