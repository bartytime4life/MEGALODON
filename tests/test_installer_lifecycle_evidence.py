"""Fail-closed boundaries for the separate real installer qualification."""
import copy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("installer_lifecycle_evidence", ROOT / "tools/installer_lifecycle_evidence.py")
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
COMMIT, TREE = "a" * 40, "b" * 40


@pytest.fixture
def receipt():
    lock, wheels = tool.locked_wheels(ROOT)
    return {
        "schema": "native-installer-lifecycle-v1", "status": "same_source_rehearsal_passed",
        "source": {"commit": COMMIT, "tree": TREE, "working_tree_dirty": False},
        "platform": {"os": "linux", "architecture": "x86_64", "python": "3.12.3", "non_root": True},
        "build_inputs": {"lock_sha256": lock, "wheels": [
            {"filename": name, "sha256": sha256, "size_bytes": 1000}
            for name, sha256 in sorted(wheels.items())]},
        "package": tool.source_package_identity(ROOT),
        "checks": copy.deepcopy(tool.CHECKS), "exclusions": list(tool.EXCLUSIONS),
    }


def test_receipt_requires_exact_external_commit_tree_and_canonical_bytes(receipt):
    raw = tool.canonical(receipt)
    assert tool.verify(raw, ROOT, COMMIT, TREE) == receipt
    for commit, tree in (("c" * 40, TREE), (COMMIT, "c" * 40), ("main", TREE)):
        with pytest.raises(tool.EvidenceError):
            tool.verify(raw, ROOT, commit, tree)
    for changed in (raw + b"\n", raw + b" " * tool.MAX_RECEIPT,
                    raw.replace(b'"status":', b'"status":"forged","status":')):
        with pytest.raises(tool.EvidenceError):
            tool.verify(changed, ROOT, COMMIT, TREE)


@pytest.mark.parametrize("section,key,value", [
    (None, "hostname", "private-host"),
    (None, "status", "cross_version_upgrade_accepted"),
    (None, "exclusions", []),
    ("source", "working_tree_dirty", 0),
    ("platform", "non_root", False),
    ("platform", "python", "3.11.9"),
    ("platform", "os", "windows"),
    ("platform", "uid", 1000),
    ("package", "origin", "/private/path"),
    ("package", "source_package_sha256", "bad"),
    ("package", "source_package_sha256", "sha256:" + "0" * 64),
    ("package", "version", "9.9.9"),
    ("build_inputs", "lock_sha256", "sha256:" + "0" * 64),
    ("checks", "rollback", "not_run"),
    ("checks", "host_acceptance", True),
])
def test_receipt_refuses_claim_escalation_and_private_details(receipt, section, key, value):
    target = receipt if section is None else receipt[section]
    target[key] = value
    with pytest.raises(tool.EvidenceError):
        tool.verify(tool.canonical(receipt), ROOT, COMMIT, TREE)


@pytest.mark.parametrize("key,value", [
    ("filename", "unlocked.whl"), ("sha256", "sha256:" + "0" * 64),
    ("size_bytes", True), ("size_bytes", 0), ("size_bytes", tool._common.MAX_FILE + 1),
    ("path", "/private/wheelhouse"),
])
def test_receipt_requires_exact_locked_wheel_set(receipt, key, value):
    receipt["build_inputs"]["wheels"][0][key] = value
    with pytest.raises(tool.EvidenceError):
        tool.verify(tool.canonical(receipt), ROOT, COMMIT, TREE)


def test_wheelhouse_refuses_changed_bytes_extra_files_and_symlinks(tmp_path, monkeypatch):
    wheels = tmp_path / "wheels"
    wheels.mkdir()
    wheel = wheels / "setuptools-84.0.0-py3-none-any.whl"
    original = b"test wheel"
    wheel.write_bytes(original)
    monkeypatch.setattr(tool, "locked_wheels", lambda _: ("sha256:" + "a" * 64,
                                                         {wheel.name: tool.digest(original)}))
    assert tool.wheelhouse_identity(ROOT, wheels)["wheels"][0]["size_bytes"] == len(original)
    wheel.write_bytes(b"changed")
    with pytest.raises(tool.EvidenceError, match="WHEELHOUSE_DIGEST"):
        tool.wheelhouse_identity(ROOT, wheels)
    wheel.write_bytes(original)
    extra = wheels / "unlocked.whl"
    extra.write_bytes(b"extra")
    with pytest.raises(tool.EvidenceError, match="WHEELHOUSE_SET"):
        tool.wheelhouse_identity(ROOT, wheels)
    extra.unlink()
    target = tmp_path / "outside.whl"
    target.write_bytes(original)
    wheel.unlink()
    wheel.symlink_to(target)
    with pytest.raises(OSError):
        tool.wheelhouse_identity(ROOT, wheels)


def test_all_installer_paths_stay_under_explicit_disposable_root(tmp_path, monkeypatch):
    from megalodon import local_install

    def forbid_host_paths(*args):
        pytest.fail("native rehearsal must not select host installation paths")

    monkeypatch.setattr(local_install, "install_paths", forbid_host_paths)
    paths = tool.temporary_paths(tmp_path, local_install)
    assert all(path.is_relative_to(tmp_path) for path in vars(paths).values())
    assert len(set(vars(paths).values())) == len(vars(paths))


def test_installed_probe_rejects_checkout_imports(tmp_path):
    """The probe must require a private venv and an installed origin, not PYTHONPATH."""
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-I", "-c", tool.PROBE, str(ROOT)],
                            cwd=tmp_path, capture_output=True, timeout=30, check=False)
    # The ordinary test environment is not an installer-created private release.
    # A source checkout, editable install or absent distribution must all refuse.
    assert result.returncode != 0
    assert not result.stdout
