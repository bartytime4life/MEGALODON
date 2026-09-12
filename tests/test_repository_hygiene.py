"""Repository-local safeguards for generated evidence and CI credentials."""

import os
import re
import subprocess
from pathlib import Path


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


def test_actions_are_sha_pinned_and_checkouts_do_not_persist_credentials():
    workflow_paths = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflow_paths

    for path in workflow_paths:
        workflow = path.read_text(encoding="utf-8")
        action_refs = re.findall(
            r"^\s+uses:\s+([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE
        )
        assert action_refs, path
        assert all(
            re.fullmatch(r"[0-9a-f]{40}", revision)
            for _, revision in action_refs
        ), path

        checkout_steps = re.findall(
            r"(?ms)^      - name: Check out source\n(.*?)(?=^      - name:|\Z)",
            workflow,
        )
        checkout_refs = [name for name, _ in action_refs if name == "actions/checkout"]
        assert len(checkout_steps) == len(checkout_refs) > 0, path
        assert all("persist-credentials: false" in step for step in checkout_steps), path


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
        "pyproject-hooks==1.2.0",
        "pytest==8.4.2",
        "referencing==0.37.0",
        "rpds-py==2026.6.3",
        "setuptools==80.9.0",
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
    codeql_revision = "b96794f015dfd88f77b49b1c93e0fa7110f94c63"

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
