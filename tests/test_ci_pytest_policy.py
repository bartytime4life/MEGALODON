"""Closed CI launch policy plus real pytest probes; no installation or network.

The child uses actual pytest plugin loading with one synthetic distribution.
This is not a general YAML security scanner or a sandbox for a malicious runner.
"""
from pathlib import Path
import os
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICY = {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_PLUGINS": "", "PYTEST_ADDOPTS": ""}
LAUNCHES = (
    "        run: python -m pytest -ra",
    '            "$RUNNER_TEMP/sdist-venv/bin/python" -m pytest -ra',
)


def workflow_policy(text: str) -> dict[str, str]:
    header, _ = text.split("\njobs:\n")
    # Deliberately exact for this reviewed file. Reorganization needs review,
    # rather than a permissive partial YAML parser guessing the policy scope.
    assert header.count("\nenv:\n") == 1, "workflow environment required"
    found = re.findall(r'^\s*(PYTEST_[A-Z_]+):\s*"([^"\n]*)"\s*$', text, re.M)
    assert found == list(POLICY.items()), "exact policy; no narrower overrides"
    for name, value in POLICY.items():
        assert header.count(f'\n  {name}: "{value}"\n') == 1, "workflow-wide policy required"
    launches = tuple(line for line in text.splitlines() if "-m pytest" in line)
    assert launches == LAUNCHES, "full test runs with nonpassing summaries required"
    return dict(found)


def test_ci_uses_reviewed_plugin_and_report_policy():
    assert workflow_policy((ROOT / ".github/workflows/ci.yml").read_text()) == POLICY


@pytest.mark.parametrize("mutation", ["autoload", "plugins", "options", "step-only",
                                     "override", "test-report", "sdist-report", "ignore-failure"])
def test_weakened_workflow_is_rejected(mutation):
    text = (ROOT / ".github/workflows/ci.yml").read_text()
    workflow_policy(text)
    if mutation in {"autoload", "plugins", "options"}:
        key = {"autoload": "PYTEST_DISABLE_PLUGIN_AUTOLOAD", "plugins": "PYTEST_PLUGINS",
               "options": "PYTEST_ADDOPTS"}[mutation]
        damaged = text.replace(f'  {key}: "{POLICY[key]}"\n', "", 1)
    elif mutation == "step-only":
        damaged = text.replace('  PYTEST_DISABLE_PLUGIN_AUTOLOAD: "1"\n', "", 1)
        damaged += '\n        env:\n          PYTEST_DISABLE_PLUGIN_AUTOLOAD: "1"\n'
    elif mutation == "override":
        damaged = text + '\n        env:\n          PYTEST_DISABLE_PLUGIN_AUTOLOAD: ""\n'
    elif mutation in {"test-report", "sdist-report"}:
        launch = LAUNCHES[mutation == "sdist-report"]
        damaged = text.replace(launch + "\n", launch.replace(" -ra", "") + "\n", 1)
    else:
        damaged = text.replace(LAUNCHES[0] + "\n", LAUNCHES[0] + " || true\n", 1)
    assert text != damaged
    with pytest.raises(AssertionError):
        workflow_policy(damaged)


@pytest.fixture
def probe(tmp_path):
    metadata = tmp_path / "megalodon_ci_tripwire-0.0.0.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text("Metadata-Version: 2.1\nName: megalodon-ci-tripwire\nVersion: 0.0.0\n")
    (metadata / "entry_points.txt").write_text("[pytest11]\nmegalodon_ci_tripwire = ci_tripwire\n")
    (tmp_path / "ci_tripwire.py").write_text(
        "from pathlib import Path\n"
        "Path('plugin-imported').write_text('synthetic-only')\n"
        "raise RuntimeError('SYNTHETIC_PLUGIN_IMPORTED')\n"
    )
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    (tmp_path / "test_probe.py").write_text(
        "import pytest\n"
        "def test_builtin_fixtures(tmp_path, monkeypatch):\n"
        "    monkeypatch.setenv('SYNTHETIC_FIXTURE', 'yes')\n"
        "    assert tmp_path.is_dir()\n"
        "@pytest.mark.skip(reason='SYNTHETIC_SKIP_REASON')\n"
        "def test_known_skip():\n"
        "    raise AssertionError('not reached')\n"
    )
    return tmp_path


CHILD = """
from importlib import metadata
import pytest
# Restrict discovery to the fixture; do not execute unrelated local plugins
# even in the deliberate autoload-enabled negative control.
distribution = metadata.Distribution.at('megalodon_ci_tripwire-0.0.0.dist-info')
metadata.distributions = lambda **kwargs: iter([distribution])
raise SystemExit(pytest.main(['-q', '-ra', '-p', 'no:cacheprovider', 'test_probe.py']))
"""


def run_probe(probe: Path, environment: dict[str, str]):
    clean = {key: value for key, value in os.environ.items() if not key.startswith("PYTEST_")}
    clean.update(PYTHONPATH=str(probe), PYTHONNOUSERSITE="1", PY_COLORS="0")
    return subprocess.run([sys.executable, "-c", CHILD], cwd=probe,
                          env={**clean, **environment}, timeout=15,
                          capture_output=True, text=True, check=False)


@pytest.mark.parametrize("contamination", ["autoload", "plugins", "options"])
def test_real_pytest_policy_blocks_ambient_inputs_and_reports_skip(probe, contamination):
    policy = workflow_policy((ROOT / ".github/workflows/ci.yml").read_text())
    inherited = {
        "autoload": {},
        "plugins": {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_PLUGINS": "ci_tripwire"},
        "options": {"PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "--synthetic-invalid-option"},
    }[contamination]
    baseline = run_probe(probe, inherited)
    assert baseline.returncode != 0
    if contamination == "options":
        assert "--synthetic-invalid-option" in baseline.stderr
    else:
        assert (probe / "plugin-imported").read_text() == "synthetic-only"
        assert "SYNTHETIC_PLUGIN_IMPORTED" in baseline.stderr + baseline.stdout
        (probe / "plugin-imported").unlink()
    candidate = run_probe(probe, {**inherited, **policy})
    assert candidate.returncode == 0, candidate.stdout + candidate.stderr
    assert not (probe / "plugin-imported").exists()
    assert "1 passed, 1 skipped" in candidate.stdout
    assert "SYNTHETIC_SKIP_REASON" in candidate.stdout


def test_real_test_failure_is_not_hidden_by_policy(probe):
    (probe / "test_probe.py").write_text("def test_failure():\n    assert False, 'SYNTHETIC_TEST_FAILURE'\n")
    result = run_probe(probe, workflow_policy((ROOT / ".github/workflows/ci.yml").read_text()))
    assert result.returncode == 1
    assert "SYNTHETIC_TEST_FAILURE" in result.stdout
    assert "1 failed" in result.stdout
    assert not (probe / "plugin-imported").exists()
