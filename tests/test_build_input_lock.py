"""One build profile: static wiring plus real pip refusals using offline fixtures.

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
ENTRY = re.compile(r"([a-z][a-z0-9-]*)==([0-9]+(?:\.[0-9]+)+) --hash=sha256:([0-9a-f]{64})")


def read_lock(text):
    entries = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = ENTRY.fullmatch(line)
        assert match is not None, "closed hashed wheel pin required"
        name, version, digest = match.groups()
        assert name not in entries, "duplicate build input"
        entries[name] = (version, digest)
    assert entries.keys() == NAMES, "exact reviewed closure required"
    return entries


def assert_build_wiring(text):
    # Exact commands protect this reviewed layout; this is not a YAML analyzer.
    assert text.count("\n  wheel-smoke:\n") == 1
    section = text.split("\n  wheel-smoke:\n")[1]
    lines = [" ".join(line.split()) for line in section.replace("\\\n", "").splitlines()]
    required = [
        'raise SystemExit("BUILD_INPUT_PROFILE:UNSUPPORTED")',
        'python -m pip install -c constraints/ci.txt pytest jsonschema',
        'mkdir "$RUNNER_TEMP/build-wheelhouse"',
        f'python -m pip download --require-hashes --only-binary=:all: --no-cache-dir --dest "$RUNNER_TEMP/build-wheelhouse" -r {LOCK}',
        '[ "${#build_wheels[@]}" -eq 4 ]',
        f'sha256sum {LOCK} "${{build_wheels[@]}}"',
        f'python -m pip install --no-index --find-links "$RUNNER_TEMP/build-wheelhouse" --require-hashes --only-binary=:all: --no-cache-dir --force-reinstall -r {LOCK}',
        'PIP_NO_INDEX=1 PIP_FIND_LINKS="$RUNNER_TEMP/build-wheelhouse" PIP_ONLY_BINARY=:all: python -m build --sdist --wheel --outdir "$RUNNER_TEMP/distributions"',
        f'cmp {LOCK} "${{sdist_roots[0]}}/{LOCK}"',
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


def test_lock_closure_matches_existing_versions_and_sdist_manifest():
    entries = read_lock((ROOT / LOCK).read_text())
    constraints = dict(re.findall(r"^([a-z][a-z0-9-]*)==([0-9.]+)$",
                                  (ROOT / "constraints/ci.txt").read_text(), re.M))
    assert all(version == constraints[name] for name, (version, _) in entries.items())
    assert f"include {LOCK}\n" in (ROOT / "MANIFEST.in").read_text()


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "unhashed", "url", "extra", "weak-hash"])
def test_lock_shape_weakenings_fail(mutation):
    text = (ROOT / LOCK).read_text()
    entry = next(line for line in text.splitlines() if line.startswith("build=="))
    replacement = {
        "missing": "", "duplicate": entry + "\n" + entry,
        "unhashed": "build==1.6.0", "url": "build @ https://invalid.example/build.whl",
        "extra": entry + "\nother==1.0 --hash=sha256:" + "0" * 64,
        "weak-hash": entry.replace("sha256:", "md5:"),
    }[mutation]
    with pytest.raises(AssertionError):
        read_lock(text.replace(entry, replacement, 1))


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


@pytest.mark.parametrize("case", ["valid", "corrupt", "missing-hash", "unhashed-dependency"])
def test_real_pip_hash_enforcement_offline(tmp_path, case):
    source = tmp_path / "source"
    source.mkdir()
    wheel = make_wheel(source, "megalodon-lock-fixture", dependency=case == "unhashed-dependency")
    digest = sha256(wheel.read_bytes()).hexdigest()
    if case == "corrupt":
        # A valid ZIP with altered bytes, not an archive parser-error shortcut.
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("changed.txt", "synthetic change\n")
    if case == "unhashed-dependency":
        make_wheel(source, "megalodon-lock-dependency")
    requirement = "megalodon-lock-fixture==1.0"
    if case != "missing-hash":
        requirement += f" --hash=sha256:{digest}"
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
    if case == "valid":
        assert result.returncode == 0, "offline hashed fixture must succeed"
        assert (destination / wheel.name).read_bytes() == wheel.read_bytes()
    else:
        assert result.returncode != 0, "hash-policy refusal must fail"
        diagnostic = result.stdout + result.stderr
        assert "HASHES" in diagnostic.upper(), "must fail for hash policy, not environment"
        # pip may leave a verified prefix when a later dependency fails. The
        # nonzero result must stop the workflow before any install/build.
