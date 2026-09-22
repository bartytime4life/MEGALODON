from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "owner-lifecycle-gate.yml"


def test_owner_lifecycle_workflow_is_read_only_and_exact_head_bound() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "contents: read" in text
    assert "issues: read" in text
    assert "pull-requests: read" in text
    assert "actions/checkout" not in text
    assert "MEGALODON-OWNER-AUTHORIZATION-V1" in text
    assert 'fields.get("head") != head' in text
    assert 'author_association") != "OWNER"' in text
    assert 'state not in {"authorized", "revoked"}' in text
    assert "release, deployment, installation" in text
