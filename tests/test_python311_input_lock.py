"""Closed Python 3.11 CI profile guards; no install, network, or subprocess.

These tests protect reviewed configuration, not arbitrary YAML or publisher
identity. Actual pip hash refusals remain in test_build_input_lock.py.
"""
import ast
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOCK = "constraints/test-linux-cp311.txt"
NAMES = {"attrs", "iniconfig", "jsonschema", "jsonschema-specifications",
         "packaging", "pluggy", "pygments", "pytest", "referencing", "rpds-py",
         "setuptools", "typing-extensions"}
ENTRY = re.compile(r"([a-z][a-z0-9-]*)==([0-9]+(?:\.[0-9]+)+) --hash=sha256:([0-9a-f]{64})")


def read_pins(text, names):
    pins = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = ENTRY.fullmatch(line)
        assert match is not None, "closed hashed wheel pin required"
        name, version, digest = match.groups()
        assert name not in pins, "duplicate wheel pin"
        pins[name] = (version, digest)
    assert pins.keys() == names, "exact test and backend closure required"
    return pins


def assert_profile(text):
    pins = read_pins(text, NAMES)
    test = read_pins((ROOT / "constraints/test-linux-cp312.txt").read_text(), NAMES - {"setuptools"})
    build = read_pins((ROOT / "constraints/build-linux-cp312.txt").read_text(),
                      {"build", "packaging", "pyproject-hooks", "setuptools"})
    constraints = dict(re.findall(r"^([a-z][a-z0-9-]*)==([0-9.]+)$",
                                  (ROOT / "constraints/ci.txt").read_text(), re.M))
    assert all(version == constraints[name] for name, (version, _) in pins.items())
    assert all(pins[name] == test[name] for name in NAMES - {"setuptools", "rpds-py"})
    assert pins["setuptools"] == build["setuptools"], "same reviewed backend wheel"
    assert pins["rpds-py"][1] != test["rpds-py"][1], "CPython artifacts differ"
    filename = (f"rpds_py-{pins['rpds-py'][0]}-cp311-cp311-"
                "manylinux_2_17_x86_64.manylinux2014_x86_64.whl")
    assert f"# {filename} — https://pypi.org/project/rpds-py/" in text


def assert_wiring(text):
    # Restrict the assertion to the test job; packaging's controls cannot satisfy it.
    assert text.count("\n  test:\n") == text.count("\n  wheel-smoke:\n") == 1
    section = text.split("\n  test:\n")[1].split("\n  wheel-smoke:\n")[0]
    lines = [" ".join(line.split()) for line in section.replace("\\\n", "").splitlines()]
    required = [
        "python -m pip install --help | grep -F -- '--build-constraint'",
        'raise SystemExit("TEST_INPUT_PROFILE:UNSUPPORTED")',
        'mkdir "$RUNNER_TEMP/test-cp311-wheelhouse"',
        f'python -m pip download --require-hashes --only-binary=:all: --no-cache-dir --dest "$RUNNER_TEMP/test-cp311-wheelhouse" -r {LOCK}',
        '[ "${#test_wheels[@]}" -eq 12 ]',
        f'sha256sum {LOCK} "${{test_wheels[@]}}"',
        f'python -m pip install -c constraints/ci.txt --no-index --find-links "$RUNNER_TEMP/test-cp311-wheelhouse" --require-hashes --only-binary=:all: --no-cache-dir --force-reinstall -r {LOCK}',
        'PIP_NO_INDEX=1 PIP_FIND_LINKS="$RUNNER_TEMP/test-cp311-wheelhouse" PIP_ONLY_BINARY=:all: python -m pip install -c constraints/ci.txt --no-cache-dir --verbose -e ".[test]"',
    ]
    positions = []
    for command in required:
        assert lines.count(command) == 1, "required test boundary changed"
        positions.append(lines.index(command))
    assert positions == sorted(positions), "verify before editable preparation"
    checks = [i for i, line in enumerate(lines) if line == "python -m pip check"]
    assert len(checks) == 2 and positions[-2] < checks[0] < positions[-1] < checks[1]
    for predicate in ('sys.implementation.name != "cpython"',
                      'sys.version_info[:2] != (3, 11)', 'sys.platform != "linux"',
                      'platform.machine() != "x86_64"', 'platform.libc_ver()[0] != "glibc"'):
        assert predicate in section, "profile guard required"
    assert f'          cmp {LOCK} "${{sdist_roots[0]}}/{LOCK}"\n' in text


def test_profile_parity_and_source_distribution_inclusion():
    assert_profile((ROOT / LOCK).read_text())
    assert f"include {LOCK}\n" in (ROOT / "MANIFEST.in").read_text()


@pytest.mark.parametrize("mutation", ["missing-backend", "duplicate", "unhashed", "extra",
                                     "weak-hash", "version", "shared-hash", "wrong-abi"])
def test_profile_weakenings_fail(mutation):
    text = (ROOT / LOCK).read_text()
    backend = next(line for line in text.splitlines() if line.startswith("setuptools=="))
    if mutation == "wrong-abi":
        old = next(line for line in text.splitlines() if line.startswith("rpds-py=="))
        other = next(line for line in (ROOT / "constraints/test-linux-cp312.txt").read_text().splitlines()
                     if line.startswith("rpds-py=="))
        damaged = text.replace(old, other)
    else:
        replacement = {
            "missing-backend": "", "duplicate": backend + "\n" + backend,
            "unhashed": backend.split(" --hash=")[0],
            "extra": backend + "\nother==1.0 --hash=sha256:" + "0" * 64,
            "weak-hash": backend.replace("sha256:", "md5:"),
            "version": backend.replace("==80.9.0", "==80.9.1"),
            "shared-hash": backend.split("sha256:")[0] + "sha256:" + "0" * 64,
        }[mutation]
        damaged = text.replace(backend, replacement, 1)
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_profile(damaged)


def test_required_job_verifies_before_isolated_editable_install():
    assert_wiring((ROOT / ".github/workflows/ci.yml").read_text())


@pytest.mark.parametrize("before,after", [
    ("--require-hashes", "--no-require-hashes"),
    ("--only-binary=:all:", ""), ("--force-reinstall", ""),
    ("pip download --require-hashes", "pip download --no-deps --require-hashes"),
    ("PIP_NO_INDEX=1", "PIP_NO_INDEX=0"),
    ('PIP_FIND_LINKS="$RUNNER_TEMP/test-cp311-wheelhouse"', "PIP_FIND_LINKS=other"),
    ('--verbose -e ".[test]"', '--verbose --no-build-isolation -e ".[test]"'),
    ("sys.version_info[:2] != (3, 11)", "False"),
    ('platform.libc_ver()[0] != "glibc"', "False"),
    (' -eq 12 ]', ' -eq 11 ]'),
    (f"-r {LOCK}\n", f"-r {LOCK} || true\n"),
    (f"cmp {LOCK}", "echo"),
    ('--no-cache-dir --verbose -e ".[test]"', '--no-cache-dir --verbose -e ".[test]" || true'),
])
def test_job_weakenings_fail_with_packaging_controls_intact(before, after):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert_wiring(text)
    prefix, packaging = text.split("\n  wheel-smoke:\n")
    # The sdist assertion belongs to packaging; every other mutation is test-only.
    if before.startswith("cmp "):
        damaged = prefix + "\n  wheel-smoke:\n" + packaging.replace(before, after)
    else:
        damaged = prefix.replace(before, after) + "\n  wheel-smoke:\n" + packaging
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_wiring(damaged)


@pytest.mark.parametrize("field,value,refused", [
    ("version", (3, 11), False), ("version", (3, 12), True),
    ("implementation", "pypy", True), ("os", "win32", True),
    ("machine", "aarch64", True), ("libc", "musl", True), ("libc", "", True),
])
def test_actual_profile_predicate(field, value, refused):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    snippet = text.split("python - <<'PYTESTPROFILE'\n", 1)[1].split("          PYTESTPROFILE\n", 1)[0]
    source = "\n".join(line[10:] if line.startswith("          ") else line for line in snippet.splitlines())
    condition = next(node.test for node in ast.parse(source).body if isinstance(node, ast.If))
    profile = dict(version=(3, 11), implementation="cpython", os="linux", machine="x86_64", libc="glibc")
    profile[field] = value
    scope = {
        "sys": SimpleNamespace(version_info=profile["version"], platform=profile["os"],
                               implementation=SimpleNamespace(name=profile["implementation"])),
        "platform": SimpleNamespace(machine=lambda: profile["machine"],
                                    libc_ver=lambda: (profile["libc"], "2.39")),
    }
    # Evaluate only the repository's guard expression with inert profile stubs.
    result = eval(compile(ast.Expression(condition), "<profile-guard>", "eval"),
                  {"__builtins__": {}}, scope)
    assert result is refused


def test_verification_cannot_move_after_editable_preparation():
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert_wiring(text)
    digest = f'          sha256sum {LOCK} "${{test_wheels[@]}}"\n'
    marker = '          python -m pip check\n      - name: Compile Python sources\n'
    assert text.count(digest) == text.count(marker) == 1
    damaged = text.replace(digest, "").replace(marker, digest + marker)
    with pytest.raises(AssertionError):
        assert_wiring(damaged)
