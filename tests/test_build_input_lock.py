"""One packaging profile: hashed build/test inputs and offline pip refusals.

Not a generic requirements/YAML parser, publisher verifier, or whole-CI lock.
The pip probes download only local metadata-only wheels; they install nothing.
"""
from hashlib import sha256
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = "constraints/build-linux-cp312.txt"
NAMES = {"build", "packaging", "pyproject-hooks", "setuptools"}
TEST_LOCK = "constraints/test-linux-cp312.txt"
TEST_NAMES = {"attrs", "iniconfig", "jsonschema", "jsonschema-specifications",
              "packaging", "pluggy", "pygments", "pytest", "referencing",
              "rpds-py", "typing-extensions"}
PROFILES = ((LOCK, NAMES), (TEST_LOCK, TEST_NAMES))
ENTRY = re.compile(r"([a-z][a-z0-9-]*)==([0-9]+(?:\.[0-9]+)+) --hash=sha256:([0-9a-f]{64})")


def read_lock(text, names=NAMES):
    entries = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = ENTRY.fullmatch(line)
        assert match is not None, "closed hashed wheel pin required"
        name, version, digest = match.groups()
        assert name not in entries, "duplicate build input"
        entries[name] = (version, digest)
    assert entries.keys() == names, "exact reviewed closure required"
    return entries


def assert_build_wiring(text):
    # Exact commands protect this reviewed layout; this is not a YAML analyzer.
    assert text.count("\n  wheel-smoke:\n") == 1
    section = text.split("\n  wheel-smoke:\n")[1]
    lines = [" ".join(line.split()) for line in section.replace("\\\n", "").splitlines()]
    required = [
        'raise SystemExit("BUILD_INPUT_PROFILE:UNSUPPORTED")',
        'mkdir "$RUNNER_TEMP/test-wheelhouse"',
        f'python -m pip download --require-hashes --only-binary=:all: --no-cache-dir --dest "$RUNNER_TEMP/test-wheelhouse" -r {TEST_LOCK}',
        '[ "${#test_wheels[@]}" -eq 11 ]',
        f'sha256sum {TEST_LOCK} "${{test_wheels[@]}}"',
        f'python -m pip install -c constraints/ci.txt --no-index --find-links "$RUNNER_TEMP/test-wheelhouse" --require-hashes --only-binary=:all: --no-cache-dir --force-reinstall -r {TEST_LOCK}',
        'mkdir "$RUNNER_TEMP/build-wheelhouse"',
        f'python -m pip download --require-hashes --only-binary=:all: --no-cache-dir --dest "$RUNNER_TEMP/build-wheelhouse" -r {LOCK}',
        '[ "${#build_wheels[@]}" -eq 4 ]',
        f'sha256sum {LOCK} "${{build_wheels[@]}}"',
        f'python -m pip install --no-index --find-links "$RUNNER_TEMP/build-wheelhouse" --require-hashes --only-binary=:all: --no-cache-dir --force-reinstall -r {LOCK}',
        'PIP_NO_INDEX=1 PIP_FIND_LINKS="$RUNNER_TEMP/build-wheelhouse" PIP_ONLY_BINARY=:all: python -m build --sdist --wheel --outdir "$RUNNER_TEMP/distributions"',
        f'cmp {LOCK} "${{sdist_roots[0]}}/{LOCK}"',
        f'cmp {TEST_LOCK} "${{sdist_roots[0]}}/{TEST_LOCK}"',
    ]
    positions = []
    for command in required:
        assert lines.count(command) == 1, "required build boundary changed"
        positions.append(lines.index(command))
    assert positions == sorted(positions), "verify before use"
    for predicate in ('sys.implementation.name != "cpython"',
                      'sys.version_info[:2] != (3, 12)', 'sys.platform != "linux"',
                      'platform.machine() != "x86_64"'):
        assert predicate in section, "profile guard required"


@pytest.mark.parametrize("path,names", PROFILES)
def test_lock_closure_matches_existing_versions_and_sdist_manifest(path, names):
    entries = read_lock((ROOT / path).read_text(), names)
    constraints = dict(re.findall(r"^([a-z][a-z0-9-]*)==([0-9.]+)$",
                                  (ROOT / "constraints/ci.txt").read_text(), re.M))
    assert all(version == constraints[name] for name, (version, _) in entries.items())
    assert f"include {path}\n" in (ROOT / "MANIFEST.in").read_text()


@pytest.mark.parametrize("path,names", PROFILES)
@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unhashed", "url", "extra", "weak-hash"])
def test_lock_shape_weakenings_fail(path, names, mutation):
    text = (ROOT / path).read_text()
    entry = next(line for line in text.splitlines() if line and not line.startswith("#"))
    replacement = {
        "missing": "", "duplicate": entry + "\n" + entry,
        "unhashed": entry.split(" --hash=")[0], "url": "build @ https://invalid.example/build.whl",
        "extra": entry + "\nother==1.0 --hash=sha256:" + "0" * 64,
        "weak-hash": entry.replace("sha256:", "md5:"),
    }[mutation]
    with pytest.raises(AssertionError):
        read_lock(text.replace(entry, replacement, 1), names)


def test_workflow_acquires_verifies_then_builds_from_local_wheels():
    assert_build_wiring((ROOT / ".github/workflows/ci.yml").read_text())


@pytest.mark.parametrize("before,after", [
    ("--require-hashes", "--no-require-hashes"),
    ("--only-binary=:all:", ""), ("--force-reinstall", ""),
    ("PIP_NO_INDEX=1", "PIP_NO_INDEX=0"),
    ("PIP_FIND_LINKS=\"$RUNNER_TEMP/build-wheelhouse\"", "PIP_FIND_LINKS=other"),
    (' -r ' + LOCK, ' -r other.txt'),
    ('sys.version_info[:2] != (3, 12)', 'False'),
    (' -eq 4 ]', ' -eq 3 ]'),
    (f'cmp {LOCK}', 'echo'),
    (f'-r {LOCK}\n', f'-r {LOCK} || true\n'),
])
def test_workflow_weakenings_fail(before, after):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert_build_wiring(text)
    damaged = text.replace(before, after)
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_build_wiring(damaged)


def test_overlapping_locks_have_identical_versions_and_artifacts():
    build = read_lock((ROOT / LOCK).read_text())
    tests = read_lock((ROOT / TEST_LOCK).read_text(), TEST_NAMES)
    assert build.keys() & tests.keys() == {"packaging"}
    assert build["packaging"] == tests["packaging"]


@pytest.mark.parametrize("before,after", [
    ("--require-hashes", "--no-require-hashes"),
    ("--only-binary=:all:", ""), ("--force-reinstall", ""),
    ("--no-index", ""), (' -eq 11 ]', ' -eq 10 ]'),
    (' -r ' + TEST_LOCK, ' -r other.txt'),
    ('sha256sum ' + TEST_LOCK, 'echo'),
    (f'-r {TEST_LOCK}\n', f'-r {TEST_LOCK} || true\n'),
])
def test_test_input_weakenings_fail_without_changing_build_policy(before, after):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    start = text.index('          mkdir "$RUNNER_TEMP/test-wheelhouse"')
    end = text.index('          mkdir "$RUNNER_TEMP/build-wheelhouse"')
    block = text[start:end]
    damaged = text[:start] + block.replace(before, after) + text[end:]
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_build_wiring(damaged)


def test_packaged_test_lock_comparison_cannot_be_omitted():
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    with pytest.raises(AssertionError):
        assert_build_wiring(text.replace(f'cmp {TEST_LOCK}', 'echo'))


def make_wheel(directory, name, *, dependency=False):
    stem = name.replace("-", "_")
    path = directory / f"{stem}-1.0-py3-none-any.whl"
    dist = f"{stem}-1.0.dist-info"
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n"
    if dependency:
        metadata += "Requires-Dist: megalodon-lock-dependency==1.0\n"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(f"{dist}/METADATA", metadata + "\n")
        archive.writestr(f"{dist}/WHEEL", "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(f"{dist}/RECORD", "")
    return path


@pytest.mark.parametrize("case", ["valid", "hashed-dependency", "corrupt", "missing-hash", "unhashed-dependency"])
def test_real_pip_hash_enforcement_offline(tmp_path, case):
    source = tmp_path / "source"
    source.mkdir()
    has_dependency = case in ("hashed-dependency", "unhashed-dependency")
    wheel = make_wheel(source, "megalodon-lock-fixture", dependency=has_dependency)
    digest = sha256(wheel.read_bytes()).hexdigest()
    if case == "corrupt":
        # A valid ZIP with altered bytes, not an archive parser-error shortcut.
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("changed.txt", "synthetic change\n")
    if has_dependency:
        dependency = make_wheel(source, "megalodon-lock-dependency")
    requirement = "megalodon-lock-fixture==1.0"
    if case != "missing-hash":
        requirement += f" --hash=sha256:{digest}"
    if case == "hashed-dependency":
        dependency_hash = sha256(dependency.read_bytes()).hexdigest()
        requirement += f"\nmegalodon-lock-dependency==1.0 --hash=sha256:{dependency_hash}"
    lock = tmp_path / "fixture.txt"
    lock.write_text(requirement + "\n")
    destination = tmp_path / "download"
    # Do not inherit CI constraints or user pip config into this synthetic probe.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("PIP_") and key not in ("PYTHONPATH", "PYTHONHOME")}
    environment.update(PIP_CONFIG_FILE=os.devnull, PIP_NO_INDEX="1",
                       PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
    result = subprocess.run(
        [sys.executable, "-I", "-m", "pip", "download", "--no-index", "--no-cache-dir",
         "--find-links", str(source), "--require-hashes", "--only-binary=:all:",
         "--dest", str(destination), "-r", str(lock)],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=20,
    )
    if case in ("valid", "hashed-dependency"):
        assert result.returncode == 0, "offline hashed fixture must succeed"
        assert (destination / wheel.name).read_bytes() == wheel.read_bytes()
        if has_dependency:
            assert (destination / dependency.name).read_bytes() == dependency.read_bytes()
        assert len(list(destination.glob("*.whl"))) == (2 if has_dependency else 1)
    else:
        assert result.returncode != 0, "hash-policy refusal must fail"
        diagnostic = result.stdout + result.stderr
        assert "HASHES" in diagnostic.upper(), "must fail for hash policy, not environment"
        # pip may leave a verified prefix when a later dependency fails. The
        # nonzero result must stop the workflow before any install/build.
