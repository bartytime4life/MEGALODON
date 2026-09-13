"""Contract tests for the bounded, source-only build-input inventory."""

import ast
import importlib.util
import json
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools/build_input_inventory.py"


def load_inventory_tool():
    spec = importlib.util.spec_from_file_location("build_input_inventory", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


inventory_tool = load_inventory_tool()


def fixture_source_tree(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    root.mkdir()
    source_paths = [Path("pyproject.toml")]
    source_paths.extend(Path(str(profile["path"])) for profile in inventory_tool.PROFILE_SPECS)
    for relative_path in source_paths:
        destination = root / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / relative_path).read_bytes())
    return root


def test_committed_inventory_exactly_matches_current_source(capsys):
    expected = (ROOT / inventory_tool.INVENTORY_RELATIVE_PATH).read_text(encoding="utf-8")
    assert inventory_tool.render_inventory(ROOT) == expected
    assert inventory_tool.main(["--check"], root=ROOT) == 0
    assert capsys.readouterr().out == "BUILD_INPUT_INVENTORY:OK\n"

    document = json.loads(expected)
    assert document["schema"] == inventory_tool.SCHEMA
    assert document["scope"] == "committed-source-build-inputs"
    assert "not a release artifact SBOM" in document["limitations"][0]
    assert len(document["profiles"]) == 4


def test_default_check_refuses_a_stale_or_missing_artifact(tmp_path, capsys):
    root = fixture_source_tree(tmp_path)
    assert inventory_tool.main([], root=root) == 1
    assert not (root / inventory_tool.INVENTORY_RELATIVE_PATH).exists()
    assert capsys.readouterr().err == "BUILD_INPUT_INVENTORY:STALE\n"


def test_explicit_output_is_deterministic_and_then_checks(tmp_path, capsys):
    root = fixture_source_tree(tmp_path)
    output = root / inventory_tool.INVENTORY_RELATIVE_PATH
    assert inventory_tool.main(["--output", str(output)], root=root) == 0
    assert capsys.readouterr().out == "BUILD_INPUT_INVENTORY:WROTE\n"
    assert output.read_text(encoding="utf-8") == inventory_tool.render_inventory(root)
    assert inventory_tool.main(["--check"], root=root) == 0


@pytest.mark.parametrize(
    ("relative_path", "mutate"),
    [
        (
            "constraints/build-linux-cp312.txt",
            lambda text: text + "https://example.invalid/unreviewed.whl\n",
        ),
        (
            "constraints/build-linux-cp312.txt",
            lambda text: text.replace(
                "build==1.6.0 --hash=sha256:f7aaf1ebbb79178a02ba248bb524f2176b256017e17e8e4bd4289c7b38cc2bad",
                "build==1.6.0",
            ),
        ),
        (
            "constraints/build-linux-cp312.txt",
            lambda text: text
            + "build==1.6.0 --hash=sha256:f7aaf1ebbb79178a02ba248bb524f2176b256017e17e8e4bd4289c7b38cc2bad\n",
        ),
        (
            "constraints/build-linux-cp312.txt",
            lambda text: text + "-r unexpected.txt\n",
        ),
        (
            "constraints/build-linux-cp312.txt",
            lambda text: text
            + "unexpected==1.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        ),
        (
            "constraints/browser-linux-cp311.txt",
            lambda text: text.replace("-r test-linux-cp311.txt", "-r outside.txt"),
        ),
    ],
)
def test_unreviewed_lock_forms_are_rejected(tmp_path, relative_path, mutate):
    root = fixture_source_tree(tmp_path)
    path = root / relative_path
    path.write_text(mutate(path.read_text(encoding="utf-8")), encoding="utf-8")
    with pytest.raises(inventory_tool.InventoryError):
        inventory_tool.build_inventory(root)


def test_source_metadata_change_makes_inventory_stale(tmp_path):
    root = fixture_source_tree(tmp_path)
    artifact = root / inventory_tool.INVENTORY_RELATIVE_PATH
    artifact.parent.mkdir(parents=True)
    artifact.write_text(inventory_tool.render_inventory(root), encoding="utf-8")
    project = root / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            'dependencies = []', 'dependencies = ["example-package==1.0"]'
        ),
        encoding="utf-8",
    )
    assert not inventory_tool.inventory_matches(root)


def test_oversized_committed_artifact_is_stale_without_parsing_it(tmp_path):
    root = fixture_source_tree(tmp_path)
    artifact = root / inventory_tool.INVENTORY_RELATIVE_PATH
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"x" * (inventory_tool.MAX_INPUT_BYTES + 1))
    assert not inventory_tool.inventory_matches(root)


def test_tool_has_only_the_reviewed_standard_library_imports():
    tree = ast.parse(TOOL_PATH.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.partition(".")[0])
    assert imported == {
        "__future__",
        "argparse",
        "hashlib",
        "json",
        "pathlib",
        "re",
        "sys",
        "tomllib",
    }


def test_contract_and_documentation_remain_packaged_and_bounded():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    documentation = (ROOT / "docs/build-input-inventory.md").read_text(encoding="utf-8")
    assert "recursive-include contracts *" in manifest
    assert "not an\nartifact SBOM" in documentation
    assert "no network access, package resolution, package\ninstallation, or subprocess execution" in documentation
