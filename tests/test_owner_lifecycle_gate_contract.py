from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "owner-lifecycle-gate.yml"


def test_owner_lifecycle_workflow_is_read_only_and_exact_head_bound() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "contents: read" not in text
    assert "issues: read" in text
    assert "pull-requests: read" in text
    # The only write: the verdict as a commit status on the verified head.
    assert "statuses: write" in text
    assert text.count(": write") == 1
    assert 'STATUS_CONTEXT = "owner-lifecycle-gate/exact-head"' in text
    assert "actions/checkout" not in text
    assert "MEGALODON-OWNER-AUTHORIZATION-V1" in text
    assert 'fields.get("head") != head' in text
    assert 'author_association") != "OWNER"' in text
    assert 'if comment["via_app"] and state != "revoked":' in text
    # Statuses are per commit, so success also requires no other open PR on the head.
    assert text.count("shared_head_hold(") == 3
    assert 'state not in {"authorized", "revoked"}' in text
    assert "release, deployment, installation" in text


def test_only_trusted_events_can_reach_the_status_writer() -> None:
    # BaseLoader retains the YAML `on` key rather than treating it as a boolean.
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert set(workflow["on"]) == {"pull_request_target", "issue_comment"}
    assert workflow["on"]["pull_request_target"] == {
        "branches": ["main"],
        "types": ["opened", "synchronize", "reopened", "ready_for_review", "converted_to_draft", "edited"],
    }
    assert workflow["on"]["issue_comment"]["types"] == ["created", "edited", "deleted"]
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == {"exact-head-owner-authorization"}
    job = workflow["jobs"]["exact-head-owner-authorization"]
    assert job["permissions"] == {"issues": "read", "pull-requests": "read", "statuses": "write"}
    assert "uses" not in job
    assert len(job["steps"]) == 1
    step = job["steps"][0]
    assert set(step) == {"name", "env", "shell", "run"}
    # No checkout, cache, artifact, PR-derived expression, action or script loader.
    assert "${{" not in step["run"]
    assert "python -I - <<'PY'" in step["run"]
    assert step["shell"] == "bash"
    assert step["env"] == {
        "GH_TOKEN": "${{ github.token }}", "GH_API_URL": "${{ github.api_url }}",
        "GH_REPOSITORY": "${{ github.repository }}",
        "GH_REPOSITORY_OWNER": "${{ github.repository_owner }}",
        "GH_EVENT_NAME": "${{ github.event_name }}",
    }
