"""Execute the workflow's actual reader with synthetic GitHub responses."""
from __future__ import annotations

import copy
import io
import json
import textwrap
import urllib.error
import urllib.request
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/owner-lifecycle-gate.yml"
HEAD = "a" * 40


def comment(identity, state=None, **changes):
    result = {
        "id": identity,
        "user": {"login": "owner"},
        "author_association": "OWNER",
        "created_at": "2026-09-23T00:00:00Z",
        "body": "unrelated" if state is None else (
            "MEGALODON-OWNER-AUTHORIZATION-V1\n"
            f"head: {HEAD}\nscope: ready-and-merge\nstate: {state}"
        ),
    }
    result.update(changes)
    return result


def run_gate(monkeypatch, tmp_path, history, *, second=None, pull_changes=None,
             page_transform=None, event_name="pull_request", clock=None):
    text = WORKFLOW.read_text(encoding="utf-8")
    source = textwrap.dedent(text.split("python - <<'PY'\n", 1)[1].rsplit("          PY", 1)[0])
    compile(source, str(WORKFLOW), "exec")
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 1}, "issue": {"number": 1}}))
    for key, value in {
        "GH_TOKEN": "synthetic-token", "GH_API_URL": "https://api.github.test",
        "GH_REPOSITORY": "owner/project", "GH_REPOSITORY_OWNER": "owner",
        "GH_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(event),
    }.items():
        monkeypatch.setenv(key, value)
    calls = []
    pulls = 0
    scan = -1

    def urlopen(request, timeout):
        nonlocal pulls, scan
        assert 0 < timeout <= 20
        url = request.full_url
        calls.append(url)
        if url.endswith("/pulls/1"):
            result = {"head": {"sha": HEAD}, "draft": False, "comments": len(history)}
            if pull_changes:
                result.update(pull_changes(pulls))
            pulls += 1
        else:
            prefix = "https://api.github.test/repos/owner/project/issues/1/comments?per_page=100&page="
            assert url.startswith(prefix)
            page = int(url[len(prefix):])
            if page == 1:
                scan += 1
            current = history if scan == 0 or second is None else second
            result = copy.deepcopy(current[(page - 1) * 100:page * 100])
            if page_transform:
                result = page_transform(scan, page, result)
        if isinstance(result, bytes):
            return io.BytesIO(result)
        return io.BytesIO(json.dumps(result).encode())

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    if clock:
        monkeypatch.setattr("time.monotonic", clock)
    try:
        exec(compile(source, str(WORKFLOW), "exec"), {"__name__": "__main__"})
    except SystemExit as exc:
        return exc.code, calls
    return 0, calls


@pytest.mark.parametrize("count", [1, 100, 101, 1000])
@pytest.mark.parametrize("event_name", ["pull_request", "issue_comment"])
def test_complete_history_authorizes(monkeypatch, tmp_path, count, event_name):
    history = [comment(i) for i in range(1, count)] + [comment(count, "authorized")]
    code, calls = run_gate(monkeypatch, tmp_path, history, event_name=event_name)
    assert code == 0
    assert len(calls) == 3 + 2 * (count // 100 + 1)


@pytest.mark.parametrize("count", [101, 1000])
def test_later_page_revocation_holds(monkeypatch, tmp_path, count, capsys):
    history = [comment(1, "authorized")] + [comment(i) for i in range(2, count)]
    history.append(comment(count, "revoked"))
    assert run_gate(monkeypatch, tmp_path, history)[0] == 3
    assert "is revoked" in capsys.readouterr().out


def test_later_authorization_and_creation_order_remain(monkeypatch, tmp_path):
    history = [comment(1, "revoked"), comment(2, "authorized")]
    assert run_gate(monkeypatch, tmp_path, history)[0] == 0
    history = [comment(1, "authorized", updated_at="2026-09-24T00:00:00Z"), comment(2, "revoked")]
    assert run_gate(monkeypatch, tmp_path, history)[0] == 3


@pytest.mark.parametrize("change", [
    {"user": {"login": "stranger"}}, {"author_association": "CONTRIBUTOR"},
    {"body": f"MEGALODON-OWNER-AUTHORIZATION-V1\nhead: {'b' * 40}\nscope: ready-and-merge\nstate: authorized"},
    {"body": f"MEGALODON-OWNER-AUTHORIZATION-V1\nhead: {HEAD}\nscope: deployment\nstate: authorized"},
])
def test_wrong_identity_head_scope_cannot_authorize(monkeypatch, tmp_path, change):
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized", **change)])[0] == 3


def test_empty_draft_and_over_bound_hold(monkeypatch, tmp_path):
    assert run_gate(monkeypatch, tmp_path, [])[0] == 3
    code, calls = run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                           pull_changes=lambda _: {"draft": True})
    assert code == 3 and len(calls) == 1
    code, calls = run_gate(monkeypatch, tmp_path, [comment(i) for i in range(1, 1002)])
    assert code == 3 and len(calls) == 1


@pytest.mark.parametrize("change", [{"head": {"sha": "b" * 40}}, {"draft": True}, {"comments": 2}])
@pytest.mark.parametrize("read_number", [1, 2])
def test_changed_pull_state_holds(monkeypatch, tmp_path, change, read_number):
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    pull_changes=lambda number: change if number == read_number else {})[0] == 3


def test_count_preserving_delete_append_race_holds(monkeypatch, tmp_path):
    original = [comment(i) for i in range(1, 102)]
    original[98] = comment(99, "authorized")
    original[100] = comment(101, "revoked")
    changed = original[1:] + [comment(102)]

    def concurrent_delete_append(scan, page, data):
        return changed[100:] if scan == 0 and page == 2 else data

    assert run_gate(monkeypatch, tmp_path, original, second=changed,
                    page_transform=concurrent_delete_append)[0] == 3


def test_same_id_edited_body_holds(monkeypatch, tmp_path):
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    second=[comment(1, "revoked")])[0] == 3


@pytest.mark.parametrize("reported", [100, 1000])
def test_full_last_page_requires_endpoint_exhaustion(monkeypatch, tmp_path, reported):
    history = [comment(1, "authorized")] + [comment(i) for i in range(2, reported + 1)]
    history.append(comment(reported + 1, "revoked"))
    assert run_gate(monkeypatch, tmp_path, history,
                    pull_changes=lambda _: {"comments": reported})[0] == 3


@pytest.mark.parametrize("bad", [[], {}, [comment(100)], [comment(101, id=True)],
    [comment(101, body={})], [comment(101, user=None)], [comment(101, created_at="2026-99-23T00:00:00Z")],
    b"invalid JSON", b" " * (8 * 1024 * 1024 + 1)])
def test_incomplete_or_malformed_later_page_holds(monkeypatch, tmp_path, bad):
    history = [comment(1, "authorized")] + [comment(i) for i in range(2, 102)]
    assert run_gate(monkeypatch, tmp_path, history,
                    page_transform=lambda scan, page, data: bad if page == 2 else data)[0] == 3


def test_later_http_failure_holds(monkeypatch, tmp_path):
    history = [comment(1, "authorized")] + [comment(i) for i in range(2, 102)]
    def failure(scan, page, data):
        if page == 2:
            raise urllib.error.URLError("synthetic outage")
        return data
    assert run_gate(monkeypatch, tmp_path, history, page_transform=failure)[0] == 3


def test_shared_deadline_holds(monkeypatch, tmp_path):
    ticks = iter([0, 1, 2, 181])
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    clock=lambda: next(ticks))[0] == 3
