"""Closed workflow checks and synthetic venv probes; no package acquisition."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import venv

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "tools/check_sdist_environment.py"
CREATE = 'python -m venv "$RUNNER_TEMP/sdist-venv"'
INSTALL = (
    '"$RUNNER_TEMP/sdist-venv/bin/python" -I -m pip install --no-index '
    '--find-links "$RUNNER_TEMP/test-wheelhouse" --find-links "$RUNNER_TEMP/build-wheelhouse" '
    '--require-hashes --only-binary=:all: --no-cache-dir --force-reinstall '
    '-r constraints/test-linux-cp312.txt -r constraints/build-linux-cp312.txt'
)
CHECK = '"$RUNNER_TEMP/sdist-venv/bin/python" -I tools/check_sdist_environment.py'
PROJECT = ('"$RUNNER_TEMP/sdist-venv/bin/python" -I -m pip install '
           '--no-index --no-deps --no-build-isolation --no-cache-dir "${sdists[0]}"')


def assert_sdist_wiring(text):
    section = text.split("\n  wheel-smoke:\n")[1]
    build, smoke = section.split("      - name: Run installed default outside checkout\n")
    lines = [" ".join(line.split()) for line in build.replace("\\\n", "").splitlines()]
    required = [
        'unset PYTHONPATH PYTHONHOME', 'export PYTHONNOUSERSITE=1',
        'test ! -e "$RUNNER_TEMP/sdist-venv"', 'test ! -L "$RUNNER_TEMP/sdist-venv"',
        CREATE, '"$RUNNER_TEMP/sdist-venv/bin/python" -I -m pip --version', INSTALL,
        'cmp tools/check_sdist_environment.py "${sdist_roots[0]}/tools/check_sdist_environment.py"',
        CHECK, PROJECT, '"$RUNNER_TEMP/sdist-venv/bin/python" -m pytest -ra',
    ]
    positions = []
    for command in required:
        assert lines.count(command) == 1, "reviewed sdist boundary changed"
        positions.append(lines.index(command))
    assert positions == sorted(positions), "provision/check before project and tests"
    assert "--system-site-packages" not in build
    assert lines.count('"$RUNNER_TEMP/sdist-venv/bin/python" -I -m pip check') == 2
    assert '          unset PYTHONPATH PYTHONHOME\n' in smoke
    assert '          export PYTHONNOUSERSITE=1\n' in smoke
    assert '"$RUNNER_TEMP/sdist-venv/bin/python" -I - <<\'PYINSTALLED\'' in smoke
    assert 'raise SystemExit("SDIST_ENV:PROJECT_OUTSIDE_VENV")' in smoke
    assert smoke.index('PYINSTALLED\n') < smoke.index('bin/megalodon" --help')


def test_workflow_provisions_sdist_without_runner_packages():
    assert_sdist_wiring((ROOT / ".github/workflows/ci.yml").read_text())


@pytest.mark.parametrize("case", ["inherited", "hash", "source", "index", "wrong-python",
                                 "test-lock", "build-lock", "reuse", "symlink", "helper",
                                 "order", "path", "user-site", "installed-origin"])
def test_sdist_policy_weakenings_fail(case):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    assert_sdist_wiring(text)
    if case == "inherited":
        damaged = text.replace(CREATE, CREATE.replace("venv ", "venv --system-site-packages "))
    elif case in {"hash", "source", "index", "wrong-python", "test-lock", "build-lock"}:
        # Change only the new install, leaving all earlier hash checks intact.
        joined = text.replace("\\\n", "")
        line = next(line for line in joined.splitlines()
                    if " ".join(line.split()) == INSTALL)
        before, after = {
            "hash": ("--require-hashes", ""), "source": ("--only-binary=:all:", ""),
            "index": ("--no-index", ""), "wrong-python": ('"$RUNNER_TEMP/sdist-venv/bin/python"', "python"),
            "test-lock": ("-r constraints/test-linux-cp312.txt", ""),
            "build-lock": ("-r constraints/build-linux-cp312.txt", ""),
        }[case]
        damaged = joined.replace(line, line.replace(before, after), 1)
    elif case in {"reuse", "symlink", "helper", "path", "user-site"}:
        command = {"reuse": 'test ! -e "$RUNNER_TEMP/sdist-venv"',
                   "symlink": 'test ! -L "$RUNNER_TEMP/sdist-venv"', "helper": CHECK,
                   "path": "unset PYTHONPATH PYTHONHOME", "user-site": "export PYTHONNOUSERSITE=1"}[case]
        damaged = text.replace("          " + command + "\n", "", 1)
    elif case == "order":
        damaged = text.replace("          " + CHECK + "\n", "")
        damaged = damaged.replace("          " + PROJECT + "\n", "          " + PROJECT + "\n          " + CHECK + "\n")
    else:
        damaged = text.replace('raise SystemExit("SDIST_ENV:PROJECT_OUTSIDE_VENV")', "pass")
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_sdist_wiring(damaged)


@pytest.fixture
def checker(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("sdist_environment_probe", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    prefix = tmp_path / "venv"
    prefix.mkdir()
    (prefix / "pyvenv.cfg").write_text("include-system-site-packages = false\n")
    monkeypatch.setattr(module, "sys", SimpleNamespace(
        prefix=str(prefix), base_prefix=str(tmp_path), flags=SimpleNamespace(isolated=1)))
    monkeypatch.setattr(module, "site", SimpleNamespace(ENABLE_USER_SITE=False))
    monkeypatch.setattr(module, "distribution", lambda name: SimpleNamespace(locate_file=lambda path: prefix))
    return module, prefix


def test_expected_dependency_origin_receipt(checker):
    module, _ = checker
    receipt = module.check_environment()
    assert receipt == {"schema": "sdist-environment-v1", "status": "passed",
                       "dependency_count": 14, "system_site_packages": False, "user_site_enabled": False}
    assert len(set(module.DEPENDENCIES)) == 14


@pytest.mark.parametrize("case,code", [
    ("base", "NOT_ISOLATED"), ("flags", "NOT_ISOLATED"), ("user", "USER_SITE_ENABLED"),
    ("system", "SYSTEM_SITE_ENABLED"), ("duplicate", "SYSTEM_SITE_ENABLED"),
    ("missing-config", "CONFIG_UNAVAILABLE"), ("oversize", "CONFIG_UNAVAILABLE"),
    ("missing-dependency", "MISSING_DEPENDENCY"), ("external", "EXTERNAL_DEPENDENCY"),
])
def test_invalid_environment_is_refused(checker, monkeypatch, case, code):
    module, prefix = checker
    config = prefix / "pyvenv.cfg"
    if case == "base":
        module.sys.prefix = module.sys.base_prefix
    elif case == "flags":
        module.sys.flags.isolated = 0
    elif case == "user":
        module.site.ENABLE_USER_SITE = True
    elif case == "system":
        config.write_text("include-system-site-packages = true\n")
    elif case == "duplicate":
        config.write_text("include-system-site-packages = false\n" * 2)
    elif case == "missing-config":
        config.unlink()
    elif case == "oversize":
        config.write_bytes(b"x" * 8193)
    elif case == "missing-dependency":
        def missing(name):
            raise module.PackageNotFoundError(name)
        monkeypatch.setattr(module, "distribution", missing)
    else:
        monkeypatch.setattr(module, "distribution", lambda name: SimpleNamespace(
            locate_file=lambda path: prefix.with_name("venv-other")))
    with pytest.raises(module.EnvironmentCheckError, match="^SDIST_ENV:" + code + "$"):
        module.check_environment()


@pytest.mark.parametrize("case", ["valid", "missing", "external"])
def test_actual_venv_origin_check_with_inert_metadata(tmp_path, case):
    prefix = tmp_path / "env"
    venv.EnvBuilder(with_pip=False).create(prefix)
    python = prefix / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    library = prefix / ("Lib/site-packages" if os.name == "nt" else
                        f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")
    spec = importlib.util.spec_from_file_location("sdist_environment_real_probe", HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in module.DEPENDENCIES:
        if name == "pytest" and case == "missing":
            continue
        target = (tmp_path / "external") if name == "pytest" and case == "external" else library
        metadata = target / (name.replace("-", "_") + "-1.0.dist-info")
        metadata.mkdir(parents=True)
        (metadata / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n")
    # Only metadata is synthesized; no sitecustomize, plugin or package code is imported.
    script = "import runpy, sys; "
    if case == "external":
        script += f"sys.path.insert(0, {str(tmp_path / 'external')!r}); "
    script += f"runpy.run_path({str(HELPER)!r}, run_name='__main__')"
    result = subprocess.run([str(python), "-I", "-c", script], cwd=tmp_path,
                            capture_output=True, text=True, timeout=15, check=False)
    if case == "valid":
        assert result.returncode == 0, result.stderr
        receipt = json.loads(result.stdout.split(" ", 1)[1])
        assert receipt["dependency_count"] == 14 and receipt["status"] == "passed"
    else:
        assert result.returncode == 1
        code = "MISSING_DEPENDENCY" if case == "missing" else "EXTERNAL_DEPENDENCY"
        assert result.stderr.strip() == "SDIST_ENV:" + code
        assert not result.stdout
