"""Build and verify the bounded MEGALODON source build-input inventory.

The inventory deliberately reads only committed source files.  It performs no
network access, package resolution, subprocess execution, or runtime-package
imports, so it must not be presented as an artifact SBOM or provenance receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib


PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_RELATIVE_PATH = Path("contracts/build-inputs/v1/inventory.json")
MAX_INPUT_BYTES = 64 * 1024
SCHEMA = "megalodon-build-input-inventory-v1"
REQUIREMENT_LINE = re.compile(
    r"(?P<name>[a-z0-9][a-z0-9_.-]*)=="
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*) "
    r"--hash=sha256:(?P<digest>[0-9a-f]{64})"
)
INCLUDE_LINE = re.compile(r"-r (?P<target>[a-z0-9][a-z0-9_.-]*\.txt)")

# This is intentionally a small, reviewed allowlist rather than a generic
# requirements parser. Adding a profile or package requires a conscious
# inventory-schema review alongside the corresponding CI-lock change.
PROFILE_SPECS = (
    {
        "id": "build-linux-cp312",
        "path": "constraints/build-linux-cp312.txt",
        "role": "wheel-smoke build tools",
        "platform": "linux-x86_64",
        "python": "3.12",
        "includes": (),
        "packages": frozenset({"build", "packaging", "pyproject-hooks", "setuptools"}),
    },
    {
        "id": "test-linux-cp311",
        "path": "constraints/test-linux-cp311.txt",
        "role": "required test job",
        "platform": "linux-glibc-x86_64",
        "python": "3.11",
        "includes": (),
        "packages": frozenset(
            {
                "attrs",
                "iniconfig",
                "jsonschema",
                "jsonschema-specifications",
                "packaging",
                "pluggy",
                "pygments",
                "pytest",
                "referencing",
                "rpds-py",
                "setuptools",
                "typing-extensions",
            }
        ),
    },
    {
        "id": "test-linux-cp312",
        "path": "constraints/test-linux-cp312.txt",
        "role": "wheel-smoke tests",
        "platform": "linux-glibc-x86_64",
        "python": "3.12",
        "includes": (),
        "packages": frozenset(
            {
                "attrs",
                "iniconfig",
                "jsonschema",
                "jsonschema-specifications",
                "packaging",
                "pluggy",
                "pygments",
                "pytest",
                "referencing",
                "rpds-py",
                "typing-extensions",
            }
        ),
    },
    {
        "id": "browser-linux-cp311",
        "path": "constraints/browser-linux-cp311.txt",
        "role": "browser acceptance additions",
        "platform": "linux-glibc-x86_64",
        "python": "3.11",
        "includes": ("test-linux-cp311.txt",),
        "packages": frozenset({"greenlet", "playwright", "pyee"}),
    },
)


class InventoryError(ValueError):
    """An input violates the deliberately narrow source-inventory contract."""


def _error(code: str) -> InventoryError:
    return InventoryError(f"BUILD_INPUT_INVENTORY:{code}")


def _source_path(root: Path, relative_path: Path) -> Path:
    root = root.resolve()
    path = (root / relative_path).resolve()
    if not path.is_relative_to(root):
        raise _error("PATH_OUTSIDE_ROOT")
    return path


def _read_source(root: Path, relative_path: Path) -> bytes:
    try:
        data = _source_path(root, relative_path).read_bytes()
    except OSError as error:
        raise _error("SOURCE_UNAVAILABLE") from error
    if not data or len(data) > MAX_INPUT_BYTES or b"\x00" in data:
        raise _error("SOURCE_SIZE_OR_ENCODING")
    return data


def _read_text(root: Path, relative_path: Path) -> str:
    try:
        return _read_source(root, relative_path).decode("utf-8")
    except UnicodeDecodeError as error:
        raise _error("SOURCE_SIZE_OR_ENCODING") from error


def _normalise_package_name(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def _parse_lock(root: Path, profile: dict[str, object]) -> dict[str, object]:
    relative_path = Path(str(profile["path"]))
    source = _read_source(root, relative_path)
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _error("SOURCE_SIZE_OR_ENCODING") from error

    includes: list[str] = []
    direct_packages: list[dict[str, str]] = []
    seen_packages: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        include = INCLUDE_LINE.fullmatch(line)
        if include is not None:
            includes.append(include.group("target"))
            continue
        requirement = REQUIREMENT_LINE.fullmatch(line)
        if requirement is None:
            raise _error("INVALID_LOCK_ENTRY")
        name = _normalise_package_name(requirement.group("name"))
        if name in seen_packages:
            raise _error("DUPLICATE_PACKAGE")
        seen_packages.add(name)
        direct_packages.append(
            {
                "declared_sha256": f"sha256:{requirement.group('digest')}",
                "name": name,
                "version": requirement.group("version"),
            }
        )

    expected_includes = tuple(profile["includes"])
    if tuple(includes) != expected_includes:
        raise _error("UNEXPECTED_INCLUDE")
    expected_packages = profile["packages"]
    if seen_packages != expected_packages:
        raise _error("UNEXPECTED_PACKAGE_SET")

    return {
        "direct_packages": sorted(direct_packages, key=lambda package: package["name"]),
        "id": profile["id"],
        "includes": [f"constraints/{include}" for include in includes],
        "path": relative_path.as_posix(),
        "platform": profile["platform"],
        "python": profile["python"],
        "role": profile["role"],
        "source_sha256": hashlib.sha256(source).hexdigest(),
    }


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _error("INVALID_PROJECT_METADATA")
    return list(value)


def _project_metadata(root: Path) -> dict[str, object]:
    try:
        document = tomllib.loads(_read_text(root, Path("pyproject.toml")))
    except tomllib.TOMLDecodeError as error:
        raise _error("INVALID_PROJECT_METADATA") from error
    project = document.get("project")
    build_system = document.get("build-system")
    if not isinstance(project, dict) or not isinstance(build_system, dict):
        raise _error("INVALID_PROJECT_METADATA")

    name = project.get("name")
    requires_python = project.get("requires-python")
    dependencies = project.get("dependencies")
    backend = build_system.get("build-backend")
    build_requires = build_system.get("requires")
    optional_dependencies = project.get("optional-dependencies", {})
    if (
        not isinstance(name, str)
        or not isinstance(requires_python, str)
        or not isinstance(backend, str)
        or not isinstance(optional_dependencies, dict)
    ):
        raise _error("INVALID_PROJECT_METADATA")

    optional: dict[str, list[str]] = {}
    for extra, requirements in sorted(optional_dependencies.items()):
        if not isinstance(extra, str):
            raise _error("INVALID_PROJECT_METADATA")
        optional[extra] = _string_list(requirements)

    return {
        "build_system": {
            "backend": backend,
            "requires": _string_list(build_requires),
        },
        "project": {
            "name": name,
            "optional_dependencies": optional,
            "requires_python": requires_python,
            "runtime_dependencies": _string_list(dependencies),
        },
    }


def build_inventory(root: Path = PROJECT_ROOT) -> dict[str, object]:
    """Return the deterministic inventory for a source tree without side effects."""
    metadata = _project_metadata(root)
    return {
        "limitations": [
            "This is not a release artifact SBOM, signed provenance, or a reproducible-build attestation.",
            "It does not identify downloaded artifact bytes, source archives, publisher identity or signatures, indexes, bootstrap tools, runners, operating systems, browsers, or undeclared runtime inputs.",
        ],
        "profiles": [_parse_lock(root, profile) for profile in PROFILE_SPECS],
        "schema": SCHEMA,
        "scope": "committed-source-build-inputs",
        **metadata,
    }


def render_inventory(root: Path = PROJECT_ROOT) -> str:
    return json.dumps(build_inventory(root), indent=2, sort_keys=True) + "\n"


def inventory_matches(root: Path = PROJECT_ROOT) -> bool:
    try:
        actual = _source_path(root, INVENTORY_RELATIVE_PATH).read_bytes()
    except OSError:
        return False
    if not actual or len(actual) > MAX_INPUT_BYTES:
        return False
    return actual == render_inventory(root).encode("utf-8")


def main(argv: list[str] | None = None, *, root: Path = PROJECT_ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify the committed inventory")
    mode.add_argument("--output", type=Path, help="write an explicitly requested inventory file")
    args = parser.parse_args(argv)

    try:
        if args.output is not None:
            output = args.output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(render_inventory(root), encoding="utf-8")
            print("BUILD_INPUT_INVENTORY:WROTE")
            return 0
        if inventory_matches(root):
            print("BUILD_INPUT_INVENTORY:OK")
            return 0
        print("BUILD_INPUT_INVENTORY:STALE", file=sys.stderr)
        return 1
    except (InventoryError, OSError) as error:
        if isinstance(error, InventoryError):
            print(error, file=sys.stderr)
        else:
            print("BUILD_INPUT_INVENTORY:WRITE_FAILED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
