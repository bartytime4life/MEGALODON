from __future__ import annotations

from pathlib import Path
import tomllib

from megalodon import __version__


ROOT = Path(__file__).resolve().parents[1]


def test_package_version_has_one_authoritative_source():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    setuptools = config["tool"]["setuptools"]

    assert "version" not in project
    assert project["dynamic"] == ["version"]
    assert setuptools["dynamic"]["version"] == {"attr": "megalodon.__version__"}
    assert __version__
