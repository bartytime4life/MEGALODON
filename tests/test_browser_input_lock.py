"""Closed browser-input policy and offline pip include/hash refusal controls.

Static checks cover the reviewed workflow shape, not arbitrary YAML execution.
The pip probes use synthetic local wheels and never install a package.
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
LOCK = "constraints/browser-linux-cp311.txt"
INCLUDE = "-r test-linux-cp311.txt"
ENTRY = re.compile(r"([a-z][a-z0-9-]*)==([0-9.]+) --hash=sha256:([0-9a-f]{64})")
BROWSER_PINS = {
    "greenlet": ("3.5.5", "74cc6df89ec5302337adc9cf096221cbed2510fd444b0e0f1586cf0470740864"),
    "playwright": ("1.62.0", "ba33bae6a13b3d9d354c751cb618af357d20fe1d57767cbcce52079bbef17ad3"),
    "pyee": ("13.0.1", "af2f8fede4171ef667dfded53f96e2ed0d6e6bd7ee3bb46437f77e3b57689228"),
}


def assert_composition(text):
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert lines[0] == INCLUDE, "only the reviewed local include is allowed"
    matches = [ENTRY.fullmatch(line) for line in lines[1:]]
    assert len(matches) == 3 and all(matches), "three closed hashed browser pins"
    assert {m[1]: (m[2], m[3]) for m in matches} == BROWSER_PINS
    inherited = [ENTRY.fullmatch(line) for line in
                 (ROOT / "constraints/test-linux-cp311.txt").read_text().splitlines()
                 if line and not line.startswith("#")]
    assert len(inherited) == 12 and all(inherited)
    assert len({m[1] for m in inherited} | BROWSER_PINS.keys()) == 15


def assert_wiring(text):
    # Scope the checks to the installation step, not matching another job.
    setup = text.split("      - name: Install test environment only\n", 1)[1].split(
        "      - name: Exercise real CLI SQLite HTTP and browser\n", 1)[0]
    required = [
        'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1"',
        "set -euo pipefail",
        "python -m pip --version",
        "python -m pip install --help | grep -F -- '--build-constraint'\n",
        'sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 11)',
        'or sys.platform != "linux" or platform.machine() != "x86_64"',
        'or platform.libc_ver()[0] != "glibc"',
        'raise SystemExit("BROWSER_INPUT_PROFILE:UNSUPPORTED")',
        'mkdir "$RUNNER_TEMP/browser-cp311-wheelhouse"\n',
        'python -m pip download --require-hashes --only-binary=:all: --no-cache-dir \\\n'
        '            --dest "$RUNNER_TEMP/browser-cp311-wheelhouse" -r ' + LOCK + '\n',
        '[ "${#browser_wheels[@]}" -eq 15 ]\n',
        'sha256sum ' + LOCK + ' constraints/test-linux-cp311.txt "${browser_wheels[@]}"\n',
        'python -m pip install -c constraints/ci.txt --no-index \\\n'
        '            --find-links "$RUNNER_TEMP/browser-cp311-wheelhouse" --require-hashes \\\n'
        '            --only-binary=:all: --no-cache-dir --force-reinstall \\\n'
        '            -r ' + LOCK + '\n',
        'python -m pip check\n',
        'PIP_NO_INDEX=1 PIP_FIND_LINKS="$RUNNER_TEMP/browser-cp311-wheelhouse" \\\n'
        '            PIP_ONLY_BINARY=:all: python -m pip install -c constraints/ci.txt \\\n'
        '            --no-cache-dir --verbose -e ".[test]"\n',
        'python -m pip check\n',
        'python -m compileall -q megalodon tests\n',
    ]
    cursor = 0
    for fragment in required:
        at = setup.find(fragment, cursor)
        assert at >= 0, "verified acquisition/install/editable order required"
        cursor = at + len(fragment)
    assert not any(flag in setup for flag in
                   ("--no-deps", "--no-build-isolation", "|| true", "continue-on-error"))
    assert "python tests/browser_native_profile.py'\n" in text


def test_browser_profile_and_source_packaging():
    assert_composition((ROOT / LOCK).read_text())
    manifest = (ROOT / "MANIFEST.in").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    for path in (LOCK, "constraints/test-linux-cp311.txt"):
        assert f"include {path}\n" in manifest
        assert f'cmp {path} "${{sdist_roots[0]}}/{path}"\n' in ci


def test_browser_workflow_verifies_inputs_before_acceptance():
    assert_wiring((ROOT / ".github/workflows/browser-acceptance.yml").read_text())


@pytest.mark.parametrize("old,new", [
    (INCLUDE, "-r test-linux-cp312.txt"),
    (INCLUDE, "-r https://invalid.example/inputs.txt"),
    (INCLUDE, ""),
    ("playwright==1.62.0", "playwright>=1.62.0"),
    (" --hash=sha256:" + BROWSER_PINS["pyee"][1], ""),
    (BROWSER_PINS["greenlet"][1], "0" * 64),
])
def test_composition_weakenings_fail(old, new):
    original = (ROOT / LOCK).read_text()
    assert_composition(original)
    damaged = original.replace(old, new, 1)
    assert damaged != original
    with pytest.raises(AssertionError):
        assert_composition(damaged)


@pytest.mark.parametrize("old,new", [
    ('PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1"', 'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "0"'),
    ("set -euo pipefail", "set -uo pipefail"),
    ("grep -F -- '--build-constraint'", "grep -F -- '--build-constraint' || true"),
    ("!= (3, 11)", "!= (3, 12)"),
    ('or platform.libc_ver()[0] != "glibc"', ""),
    ("pip download --require-hashes", "pip download"),
    ("--only-binary=:all:", "--prefer-binary"),
    ('-eq 15 ]', '-eq 3 ]'),
    ("sha256sum constraints/browser-linux-cp311.txt", "echo constraints/browser-linux-cp311.txt"),
    ("--find-links \"$RUNNER_TEMP/browser-cp311-wheelhouse\" --require-hashes",
     "--find-links \"$RUNNER_TEMP/browser-cp311-wheelhouse\""),
    ("--force-reinstall", "--no-deps"),
    ("PIP_NO_INDEX=1", "PIP_NO_INDEX=0"),
    ('PIP_FIND_LINKS="$RUNNER_TEMP/browser-cp311-wheelhouse"', 'PIP_FIND_LINKS="relative"'),
    ('--no-cache-dir --verbose -e', '--no-build-isolation --verbose -e'),
])
def test_browser_only_workflow_weakenings_fail(old, new):
    original = (ROOT / ".github/workflows/browser-acceptance.yml").read_text()
    assert_wiring(original)
    # Restrict replacement so earlier display-manager shell text is unaffected.
    prefix, setup = original.split("      - name: Install test environment only\n", 1)
    damaged = setup.replace(old, new, 1)
    assert damaged != setup
    with pytest.raises(AssertionError):
        assert_wiring(prefix + "      - name: Install test environment only\n" + damaged)


@pytest.mark.parametrize("case", ["valid", "missing-include", "missing-hash", "changed-wheel"])
def test_real_pip_relative_include_and_hash_refusal(tmp_path, case):
    source = tmp_path / "wheels"
    source.mkdir()
    wheel = source / "megalodon_browser_lock_fixture-1.0-py3-none-any.whl"
    info = "megalodon_browser_lock_fixture-1.0.dist-info"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(info + "/METADATA", "Metadata-Version: 2.1\n"
                         "Name: megalodon-browser-lock-fixture\nVersion: 1.0\n")
        archive.writestr(info + "/WHEEL", "Wheel-Version: 1.0\nGenerator: synthetic\n"
                         "Root-Is-Purelib: true\nTag: py3-none-any\n")
        archive.writestr(info + "/RECORD", "")
    digest = sha256(wheel.read_bytes()).hexdigest()
    if case == "changed-wheel":
        with zipfile.ZipFile(wheel, "a") as archive:
            archive.writestr("changed.txt", "synthetic changed bytes\n")
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    parent = requirements / "browser.txt"
    parent.write_text("-r child.txt\n")
    if case != "missing-include":
        pin = "megalodon-browser-lock-fixture==1.0"
        if case != "missing-hash":
            pin += f" --hash=sha256:{digest}"
        (requirements / "child.txt").write_text(pin + "\n")
    cwd = tmp_path / "other-directory"
    cwd.mkdir()
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("PIP_") and k not in ("PYTHONPATH", "PYTHONHOME")}
    env.update(PIP_CONFIG_FILE=os.devnull, PIP_NO_INDEX="1",
               PIP_DISABLE_PIP_VERSION_CHECK="1", PIP_NO_INPUT="1")
    destination = tmp_path / "download"
    result = subprocess.run(
        [sys.executable, "-I", "-m", "pip", "download", "--no-index", "--no-cache-dir",
         "--find-links", str(source), "--require-hashes", "--only-binary=:all:",
         "--dest", str(destination), "-r", str(parent)],
        cwd=cwd, env=env, capture_output=True, text=True, timeout=20,
    )
    if case == "valid":
        assert result.returncode == 0, "relative hashed include must succeed"
        assert (destination / wheel.name).read_bytes() == wheel.read_bytes()
    else:
        assert result.returncode != 0, "include/hash failure must remain nonzero"
        expected = "requirements file" if case == "missing-include" else "hashes"
        assert expected in (result.stdout + result.stderr).lower()
