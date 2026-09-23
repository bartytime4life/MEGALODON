"""Repository-local safeguards for generated evidence and CI credentials."""

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def _check_ignore(paths: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "git",
            "-c",
            f"core.excludesFile={os.devnull}",
            "check-ignore",
            "--no-index",
            "--stdin",
        ],
        cwd=ROOT,
        input="\n".join(paths) + "\n",
        text=True,
        capture_output=True,
        check=False,
    )


def test_sensitive_runtime_and_build_artifacts_are_ignored():
    entries = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required = {
        "__pycache__/",
        ".pytest_cache/",
        ".venv/",
        "build/",
        "dist/",
        "*.egg-info/",
        ".coverage",
        "htmlcov/",
        "/data/",
        "*.db",
        "*.db-*",
        "*.db.*",
        "*.pcap",
        "*.pcap.*",
        "*.pcapng",
        "*.log",
        "eve.json",
        "/reports/",
        ".env",
        ".env.*",
        ".secrets/",
        "credentials*.json",
        ".netrc",
        ".pypirc",
        "*.key",
        "*.pem",
    }
    assert required <= entries

    ignored = (
        "data/megalodon.db",
        "case/megalodon.db-wal",
        "case/megalodon.db-shm",
        "case/megalodon.db.pre-v3.bak",
        "capture.pcap",
        "capture.pcapng.gz",
        "conn.log",
        "eve.json",
        "reports/run/manifest.json",
        ".env.local",
        ".secrets/operator.pem",
        "credentials-production.json",
        "dist/megalodon.whl",
        ".coverage",
        ".venv/bin/python",
        ".venv312/bin/python",
        "megalodon/__pycache__/models.pyc",
    )
    result = _check_ignore(ignored)
    assert result.returncode == 0, result.stderr
    assert tuple(result.stdout.splitlines()) == ignored

    trackable = _check_ignore(
        (".env.example", "megalodon/new_module.py", "tests/new_test.py")
    )
    assert trackable.returncode == 1, trackable.stderr
    assert trackable.stdout == ""


def _assert_workflow_credentials(workflow):
    action_refs = re.findall(
        r"^\s+(?:- )?uses:\s+([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE,
    )
    has_uses_directive = bool(re.search(r"(?m)^\s*(?:- )?uses:\s", workflow))
    if has_uses_directive:
        assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in action_refs)

    # This guard supports the repository's block-style, six-space step layout.
    # Count all checkout references so unsupported layouts fail rather than skip.
    steps = re.findall(r"(?ms)^      - .*?(?=^      - |^  [^ \n]|\Z)", workflow)
    checkout_steps = [
        step for step in steps
        if re.search(r"^\s+(?:- )?uses:\s+actions/checkout@", step, re.MULTILINE)
    ]
    checkout_refs = [name for name, _ in action_refs if name == "actions/checkout"]
    # A workflow that uses no actions at all (e.g. a read-only, API-only gate)
    # has no checkout and no credential-persistence surface to guard.
    if action_refs:
        assert len(checkout_steps) == len(checkout_refs) > 0
    for step in checkout_steps:
        inputs = re.findall(r"(?m)^        with:\n((?:^          [^\n]*\n?)*)", step)
        assert len(inputs) == 1
        persistence = re.findall(r"(?m)^          persist-credentials:\s*([^\n]+)", inputs[0])
        assert persistence == ["false"]


def test_actions_are_sha_pinned_and_checkouts_do_not_persist_credentials():
    workflow_paths = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflow_paths

    for path in workflow_paths:
        workflow = path.read_text(encoding="utf-8")
        _assert_workflow_credentials(workflow)


@pytest.mark.parametrize("label", ["Check out source", "Check out exact candidate verifier", "Arbitrary label", None])
def test_checkout_guard_uses_action_identity_not_display_name(label):
    action = "actions/checkout@" + "a" * 40
    start = f"      - name: {label}\n        uses: {action}\n" if label else f"      - uses: {action}\n"
    _assert_workflow_credentials(start + "        with:\n          persist-credentials: false\n")


@pytest.mark.parametrize("unsafe", [
    "",
    "        with:\n          persist-credentials: true\n",
    "        with:\n          # persist-credentials: false\n",
    "        with:\n          persist-credentials: false\n          persist-credentials: true\n",
    "        run: |\n          persist-credentials: false\n",
])
def test_checkout_guard_cannot_borrow_safe_setting_from_another_step_or_job(unsafe):
    checkout = "      - name: Different checkout label\n        uses: actions/checkout@" + "a" * 40 + "\n"
    safe_step = "      - name: Other action\n        uses: actions/setup-python@" + "b" * 40 + "\n        with:\n          persist-credentials: false\n"
    for separator in ("", "  another-job:\n    steps:\n"):
        with pytest.raises(AssertionError):
            _assert_workflow_credentials(checkout + unsafe + separator + safe_step)


def test_checkout_guard_still_rejects_unpinned_actions():
    with pytest.raises(AssertionError):
        _assert_workflow_credentials("      - uses: actions/checkout@main\n        with:\n          persist-credentials: false\n")


def test_ci_constraints_are_exact_and_the_drift_lane_stays_separate():
    constraints = ROOT / "constraints" / "ci.txt"
    entries = {
        line.strip()
        for line in constraints.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected = {
        "attrs==26.1.0",
        "build==1.6.0",
        "iniconfig==2.3.0",
        "jsonschema==4.26.0",
        "jsonschema-specifications==2025.9.1",
        "packaging==26.3",
        "pluggy==1.6.0",
        "pygments==2.21.0",
        "pyproject-hooks==1.3.3",
        "pytest==9.1.1",
        "referencing==0.37.0",
        "rpds-py==2026.6.3",
        "setuptools==84.0.0",
        "typing-extensions==4.16.0",
    }
    assert entries == expected
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+==[^#]+", entry) for entry in entries)

    drift = (ROOT / ".github" / "workflows" / "compatibility-drift.yml").read_text(
        encoding="utf-8"
    )
    assert "schedule:" in drift
    assert "workflow_dispatch:" in drift
    assert "constraints/ci.txt" not in drift


def test_dependabot_only_opens_bounded_review_prs():
    policy = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert policy == """version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    target-branch: "main"
    schedule:
      interval: "weekly"
      day: "tuesday"
      time: "04:17"
      timezone: "Etc/UTC"
    open-pull-requests-limit: 3
    rebase-strategy: "disabled"
    versioning-strategy: "increase-if-necessary"
    commit-message:
      prefix: "deps"
      include: "scope"

  - package-ecosystem: "github-actions"
    directory: "/"
    target-branch: "main"
    schedule:
      interval: "weekly"
      day: "wednesday"
      time: "04:17"
      timezone: "Etc/UTC"
    open-pull-requests-limit: 3
    rebase-strategy: "disabled"
    commit-message:
      prefix: "deps"
      include: "scope"
"""
    assert "registries:" not in policy
    assert "insecure-external-code-execution:" not in policy
    assert "allow:" not in policy
    assert "ignore:" not in policy
    manifest_entries = {
        line.strip()
        for line in (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert "include .github/dependabot.yml" in manifest_entries


def test_codeql_scans_python_source_with_only_required_permissions():
    workflow = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(
        encoding="utf-8"
    )
    codeql_revision = "1c5b675653bb5c22dbe9b12b556ec555138e09fd"

    assert "name: CodeQL\n" in workflow
    assert "push:\n    branches: [main]" in workflow
    assert "pull_request:\n    branches: [main]" in workflow
    workflow_permissions = re.search(
        r"(?m)^permissions:\n(?P<body>(?:  [^\n]+\n)+)(?:\n)*(?=^[^\s]|\Z)",
        workflow,
    )
    assert workflow_permissions is not None
    assert workflow_permissions.group("body") == (
        "  contents: read\n"
        "  security-events: write\n"
    )
    jobs = workflow.split("\njobs:\n", 1)[1]
    assert not re.findall(r"(?m)^ +permissions:\s*", jobs)
    assert "persist-credentials: false" in workflow
    assert workflow.count(codeql_revision) == 2
    assert f"github/codeql-action/init@{codeql_revision}" in workflow
    assert f"github/codeql-action/analyze@{codeql_revision}" in workflow
    assert "languages: python" in workflow
    assert "build-mode: none" in workflow
    assert "run:" not in workflow
