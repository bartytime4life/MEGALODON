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
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    action_refs = re.findall(r"^\s+uses:\s+([^@\s]+)@([^\s#]+)", workflow, re.MULTILINE)
    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", revision) for _, revision in action_refs)

    checkout_steps = re.findall(
        r"(?ms)^      - name: Check out source\n(.*?)(?=^      - name:|\Z)", workflow
    )
    checkout_refs = [name for name, _ in action_refs if name == "actions/checkout"]
    assert len(checkout_steps) == len(checkout_refs) > 0
    assert all("persist-credentials: false" in step for step in checkout_steps)
