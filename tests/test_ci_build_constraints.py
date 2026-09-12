"""Static guards for the two reviewed workflows, not a general YAML validator.

These tests perform no install, build, subprocess, or network operation. Hosted
build logs must separately prove the isolated resolver used the expected pin.
"""
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = (
    "env:\n"
    "  PIP_CONSTRAINT: ${{ github.workspace }}/constraints/ci.txt\n"
    "  PIP_BUILD_CONSTRAINT: ${{ github.workspace }}/constraints/ci.txt\n"
)
SUPPORT_CHECK = "python -m pip install --help | grep -F -- '--build-constraint'"
WORKFLOWS = (("ci.yml", ("test", "wheel-smoke")),
             ("browser-acceptance.yml", ("browser-acceptance",)))


def assert_constraint_wiring(text: str, jobs: tuple[str, ...]) -> None:
    # Exact reviewed shape: deliberately fail if a workflow is reorganized, so
    # policy scope must be reconsidered instead of guessed by a partial parser.
    assert text.count("\njobs:\n") == 1
    header, body = text.split("\njobs:\n")
    assert header.count(ENVIRONMENT) == 1, "workflow-wide absolute constraints required"
    assert re.findall(r"^\s*(PIP_(?:BUILD_)?CONSTRAINT):", text, re.M) == [
        "PIP_CONSTRAINT", "PIP_BUILD_CONSTRAINT"
    ], "no job/step constraint override"
    for job in jobs:
        match = re.search(rf"^  {re.escape(job)}:\n(.*?)(?=^  [\w-]+:\n|\Z)",
                          body, re.M | re.S)
        assert match is not None, "reviewed job missing"
        section = match.group(1)
        assert f"          {SUPPORT_CHECK}\n" in section, "pip prerequisite required"
        assert section.index(SUPPORT_CHECK) < section.index(
            "python -m pip install -c constraints/ci.txt"
        ), "pip prerequisite must precede installation"
        assert "python -m pip --version\n" in section


@pytest.mark.parametrize("name,jobs", WORKFLOWS)
def test_deterministic_workflows_constrain_both_resolvers(name, jobs):
    assert_constraint_wiring((ROOT / ".github/workflows" / name).read_text(), jobs)


@pytest.mark.parametrize("name,jobs", WORKFLOWS)
@pytest.mark.parametrize("mutation", ["no-ordinary", "no-build", "relative",
                                     "step-only", "override", "no-prerequisite",
                                     "ignored-prerequisite"])
def test_policy_weakenings_are_rejected(name, jobs, mutation):
    text = (ROOT / ".github/workflows" / name).read_text()
    assert_constraint_wiring(text, jobs)
    if mutation == "no-ordinary":
        damaged = text.replace(ENVIRONMENT.splitlines(keepends=True)[1], "", 1)
    elif mutation == "no-build":
        damaged = text.replace(ENVIRONMENT.splitlines(keepends=True)[2], "", 1)
    elif mutation == "relative":
        damaged = text.replace("${{ github.workspace }}/constraints/ci.txt", "constraints/ci.txt")
    elif mutation == "step-only":
        indented = "".join("        " + line + "\n" for line in ENVIRONMENT.splitlines())
        damaged = text.replace(ENVIRONMENT, "").replace("    steps:\n", "    steps:\n" + indented, 1)
    elif mutation == "override":
        damaged = text + "\n        env:\n          PIP_BUILD_CONSTRAINT: other.txt\n"
    elif mutation == "no-prerequisite":
        damaged = text.replace("          " + SUPPORT_CHECK + "\n", "", 1)
    else:
        damaged = text.replace(SUPPORT_CHECK + "\n", SUPPORT_CHECK + " || true\n", 1)
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_constraint_wiring(damaged, jobs)


def test_compatibility_discovery_remains_unconstrained():
    text = (ROOT / ".github/workflows/compatibility-drift.yml").read_text()
    assert "PIP_CONSTRAINT" not in text and "PIP_BUILD_CONSTRAINT" not in text
    assert "constraints/ci.txt" not in text
    assert "python -m build --sdist --wheel" in text
