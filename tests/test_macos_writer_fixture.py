"""The native writer probe chooses a real fixture path without relaxing admission."""

import ast
import os
from pathlib import Path
import tempfile

import pytest
import yaml

from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage
from megalodon.local_install import InstallError


pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX ancestry contract")
WORKFLOW = Path(__file__).parents[1] / ".github/workflows/macos-m1-synthetic.yml"


def writer_probe():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    step = next(step for step in workflow["jobs"]["macos-m1-sample"]["steps"]
                if step.get("name") == "Write AI receipts and an evidence segment natively")
    script = step["run"].split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    return ast.parse(script)


def writer_fixture_root(temporary_root):
    """Execute the workflow's actual setup before it creates its first child."""
    fixture = next(node for node in writer_probe().body if isinstance(node, ast.With))
    setup = []
    for node in fixture.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "private" for target in node.targets
        ):
            break
        setup.append(node)
    assert setup
    scope = {"Path": Path, "root": str(temporary_root), "results": {}}
    exec(compile(ast.Module(body=setup, type_ignores=[]), str(WORKFLOW), "exec"), scope)
    return scope["root"]


@pytest.mark.parametrize("aliased", [False, True])
def test_writer_fixture_accepts_real_and_aliased_temporary_parents(tmp_path, aliased):
    real = tmp_path.resolve(strict=True) / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "var"
    alias.symlink_to(real, target_is_directory=True)
    temporary = (alias if aliased else real) / "new-fixture"
    temporary.mkdir(mode=0o700)
    root = writer_fixture_root(temporary)
    assert root == real / "new-fixture"


@pytest.mark.parametrize("aliased", [False, True])
def test_complete_writer_fixture_and_readback(tmp_path, monkeypatch, aliased):
    real = tmp_path.resolve(strict=True) / "real"
    real.mkdir(mode=0o700)
    alias = tmp_path / "var"
    alias.symlink_to(real, target_is_directory=True)
    monkeypatch.setattr(tempfile, "tempdir", str(alias if aliased else real))
    tree = writer_probe()
    # Exercise the actual synthetic body on this native runtime. Its top-level
    # Darwin-only guard belongs to hosted qualification; do not emulate Darwin
    # or replace any production storage/platform guard here.
    body = [node for node in tree.body if not isinstance(node, ast.If)]
    scope = {}
    exec(compile(ast.Module(body=body, type_ignores=[]), str(WORKFLOW), "exec"), scope)
    assert scope["results"] == {
        "temporary_ancestor_symlink": aliased,
        "receipt_store": "written",
        "receipt_store_symlink": "refused",
        "evidence_home_symlink": "refused",
        "evidence_segment_writer": "written",
    }


@pytest.mark.parametrize("damage", ["symlink", "writable", "file"])
def test_canonical_fixture_still_refuses_unsafe_descendants(tmp_path, damage):
    root = writer_fixture_root(tmp_path)
    home = root / "home"
    home.mkdir(mode=0o700)
    outside = root / "outside"
    outside.mkdir(mode=0o700)
    if damage == "symlink":
        (home / ".local").symlink_to(outside, target_is_directory=True)
    elif damage == "writable":
        home.chmod(0o777)
    else:
        (home / ".local").write_text("sentinel", encoding="utf-8")
    try:
        with pytest.raises(InstallError, match="ancestry is"):
            EvidenceStorage(Settings(db_path=home / "old.db"), home=home)
        assert not (outside / "share").exists()
        assert not (home / ".local/share/megalodon/evidence").exists()
    finally:
        home.chmod(0o700)
