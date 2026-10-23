from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "owner-lifecycle-gate.yml"

# Advisory-derived regression boundary, not a vulnerability claim about MEGALODON:
# https://securitylab.github.com/advisories/GHSL-2026-229_ipdxco_unified-github-workflows/
# https://securitylab.github.com/advisories/GHSL-2026-207_kptdev_kpt_repository/
# These events can deliver contributor-controlled data to base-repository code.
# New consumers need an explicit trust-boundary review and their own contract.
PRIVILEGED_EVENTS = frozenset({'pull_request_target', 'issue_comment', 'workflow_run'})
REVIEWED_ENTRY_POINTS = {
    'owner-lifecycle-gate.yml': frozenset({'pull_request_target', 'issue_comment'}),
}


def assert_reviewed_entry_points(directory: Path) -> None:
    observed = {}
    for path in sorted(directory.iterdir()):
        if path.suffix not in {'.yml', '.yaml'}:
            continue
        workflow = yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
        assert isinstance(workflow, dict), f'{path.name}: invalid workflow'
        events = workflow.get('on')
        assert isinstance(events, (str, list, dict)), f'{path.name}: invalid triggers'
        names = {events} if isinstance(events, str) else set(events)
        privileged = names & PRIVILEGED_EVENTS
        if privileged:
            observed[path.name] = frozenset(privileged)
    assert observed == REVIEWED_ENTRY_POINTS, (
        'Privileged workflow entry points changed; review the data-to-code boundary '
        f'and add a dedicated contract before updating this inventory: {observed}'
    )


def test_all_privileged_workflow_entry_points_are_reviewed() -> None:
    # Enumerating both extensions prevents a new workflow from silently escaping
    # the owner gate's otherwise file-specific structural and behavior tests.
    assert_reviewed_entry_points(WORKFLOW.parent)


@pytest.mark.parametrize('event', sorted(PRIVILEGED_EVENTS))
@pytest.mark.parametrize('form', ['scalar', 'list', 'mapping'])
@pytest.mark.parametrize('extension', ['yml', 'yaml'])
def test_new_privileged_workflow_is_rejected(tmp_path, event, form, extension) -> None:
    (tmp_path / WORKFLOW.name).write_text(WORKFLOW.read_text(encoding='utf-8'), encoding='utf-8')
    assert_reviewed_entry_points(tmp_path)
    trigger = {'scalar': event, 'list': f'[{event}]', 'mapping': f'\n  {event}: {{}}'}[form]
    (tmp_path / f'unreviewed.{extension}').write_text(
        f'on: {trigger}\njobs: {{}}\n', encoding='utf-8')
    with pytest.raises(AssertionError, match='Privileged workflow entry points changed'):
        assert_reviewed_entry_points(tmp_path)


def test_existing_workflow_cannot_add_privileged_trigger(tmp_path) -> None:
    text = WORKFLOW.read_text(encoding='utf-8')
    (tmp_path / WORKFLOW.name).write_text(text.replace('on:\n', 'on:\n  workflow_run: {}\n', 1), encoding='utf-8')
    with pytest.raises(AssertionError, match='Privileged workflow entry points changed'):
        assert_reviewed_entry_points(tmp_path)


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
