"""Fail closed if the owner license decision and package metadata diverge."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
APACHE_2_0_SHA256 = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"


def _bytes(path: str) -> bytes:
    return (ROOT / path).read_bytes()


def _text(path: str) -> str:
    return _bytes(path).decode("utf-8")


def test_license_file_matches_the_approved_apache_2_0_text() -> None:
    document = _bytes("LICENSE")

    assert hashlib.sha256(document).hexdigest() == APACHE_2_0_SHA256
    assert b"Copyright [yyyy] [name of copyright owner]" in document


def test_pyproject_declares_pep_639_license_metadata() -> None:
    data = tomllib.loads(_text("pyproject.toml"))
    project = data["project"]
    build_system = data["build-system"]

    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE"]
    assert build_system["requires"] == ["setuptools>=77"]
    assert (ROOT / "LICENSE").is_file()


def test_documentation_and_contribution_surfaces_link_the_decision() -> None:
    readme = _text("README.md")
    decision = _text("docs/license-decision-2026-09-20.md")

    assert "[Apache License, Version 2.0](LICENSE)" in readme
    assert "docs/license-decision-2026-09-20.md" in readme
    assert "Selection | Apache License, Version 2.0 (`Apache-2.0`)" in decision
    assert "issue #255" in decision
    assert "not legal advice" in decision
    contributing_path = ROOT / "CONTRIBUTING.md"
    if contributing_path.is_file():
        assert "[Apache License, Version 2.0](LICENSE)" in _text("CONTRIBUTING.md")


def test_manifest_explicitly_includes_license() -> None:
    assert "include LICENSE" in _text("MANIFEST.in").splitlines()


def test_optional_scapy_boundary_remains_explicit() -> None:
    project = tomllib.loads(_text("pyproject.toml"))["project"]

    assert project["dependencies"] == []
    assert project["optional-dependencies"]["capture"] == ["scapy>=2.5,<3"]
    capture = _text("megalodon/capture.py")
    assert "def iter_scapy(" in capture
    assert capture.index("def iter_scapy(") < capture.index("from scapy.all import")


def _artifact_paths() -> tuple[Path, Path] | None:
    wheel_value = os.environ.get("MEGALODON_TEST_WHEEL")
    sdist_value = os.environ.get("MEGALODON_TEST_SDIST")
    if wheel_value is None and sdist_value is None:
        return None
    assert wheel_value is not None and sdist_value is not None
    wheel = Path(wheel_value)
    sdist = Path(sdist_value)
    assert wheel.is_file()
    assert sdist.is_file()
    return wheel, sdist


def test_built_distributions_carry_license_metadata() -> None:
    artifacts = _artifact_paths()
    if artifacts is None:
        return
    wheel, sdist = artifacts

    with zipfile.ZipFile(wheel) as archive:
        metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
        license_name = next(name for name in archive.namelist() if name.endswith(".dist-info/licenses/LICENSE"))
        metadata = archive.read(metadata_name).decode("utf-8")
        wheel_license = archive.read(license_name)
    assert "License-Expression: Apache-2.0\n" in metadata
    assert "License-File: LICENSE\n" in metadata
    assert wheel_license == _bytes("LICENSE")

    with tarfile.open(sdist, "r:gz") as archive:
        license_member = next(member for member in archive.getmembers() if member.name.endswith("/LICENSE"))
        extracted = archive.extractfile(license_member)
        assert extracted is not None
        assert extracted.read() == _bytes("LICENSE")
