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
        "performed_via_github_app": None,
        "body": "unrelated" if state is None else (
            "MEGALODON-OWNER-AUTHORIZATION-V1\n"
            f"head: {HEAD}\nscope: ready-and-merge\nstate: {state}"
        ),
    }
    result.update(changes)
    return result


def run_gate(monkeypatch, tmp_path, history, *, second=None, pull_changes=None,
             page_transform=None, event_name="pull_request_target", clock=None,
             statuses=None, head_repo="owner/project", status_failure=None, open_pulls=None,
             execution_env=None, event_changes=None, status_response=None, status_code=201):
    text = WORKFLOW.read_text(encoding="utf-8")
    source = textwrap.dedent(text.split("python -I - <<'PY'\n", 1)[1].rsplit("          PY", 1)[0])
    compile(source, str(WORKFLOW), "exec")
    event = tmp_path / "event.json"
    event_data = {
        "pull_request": {"number": 1, "head": {"sha": HEAD, "repo": head_repo and {"full_name": head_repo}}},
        "issue": {"number": 1, "pull_request": {}},
    }
    event_data.update(event_changes or {})
    event.write_text(json.dumps(event_data))
    for key, value in {
        "GH_TOKEN": "synthetic-token", "GH_API_URL": "https://api.github.test",
        "GH_REPOSITORY": "owner/project", "GH_REPOSITORY_OWNER": "owner",
        "GH_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(event),
        "GITHUB_SERVER_URL": "https://github.test", "GITHUB_RUN_ID": "7",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": "owner/project/.github/workflows/owner-lifecycle-gate.yml@refs/heads/main",
        **(execution_env or {}),
    }.items():
        monkeypatch.setenv(key, value)
    calls = []
    listing = []
    pulls = 0
    scan = -1
    publications = 0

    def urlopen(request, timeout):
        nonlocal pulls, scan, publications
        assert 0 < timeout <= 20
        url = request.full_url
        if "/statuses/" in url:
            assert request.get_method() == "POST"
            assert url.startswith("https://api.github.test/repos/owner/project/statuses/")
            failure = status_failure(publications) if callable(status_failure) else status_failure
            publications += 1
            if failure:
                raise failure
            if statuses is not None:
                statuses.append((url.rsplit("/", 1)[1], json.loads(request.data)))
            result = json.loads(request.data)
            if status_response is not None:
                result = status_response(result)
            response = io.BytesIO(result if isinstance(result, bytes) else json.dumps(result).encode())
            response.status = status_code
            return response
        open_prefix = "https://api.github.test/repos/owner/project/pulls?state=open&per_page=100&page="
        if url.startswith(open_prefix):
            page = int(url[len(open_prefix):])
            listing.append(page)
            result = (open_pulls or (lambda _check, _page: [{"number": 1, "head": {"sha": HEAD}}] if _page == 1 else []))(
                listing.count(1) - 1, page)
            return io.BytesIO(result if isinstance(result, bytes) else json.dumps(result).encode())
        calls.append(url)
        if url.endswith("/pulls/1"):
            result = {"head": {"sha": HEAD}, "draft": False, "comments": len(history),
                      "base": {"ref": "main", "repo": {"full_name": "owner/project"}}, "state": "open"}
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
@pytest.mark.parametrize("event_name", ["pull_request_target", "issue_comment"])
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
    [comment(101, body={})], [comment(101, user=None)], [comment(101, performed_via_github_app="claude")], [comment(101, created_at="2026-99-23T00:00:00Z")],
    b"invalid JSON", pytest.param(b" " * (8 * 1024 * 1024 + 1), id="oversized-page")])
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


def status(state, description):
    return (HEAD, {"state": state, "context": "owner-lifecycle-gate/exact-head",
                   "description": description, "target_url": "https://github.test/owner/project/actions/runs/7"})


@pytest.mark.parametrize("event_name", ["pull_request_target", "issue_comment"])
def test_verdict_is_posted_as_a_status_on_the_exact_head(monkeypatch, tmp_path, event_name):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    event_name=event_name, statuses=posted)[0] == 0
    assert posted == [status("success", "Authorized by owner record #1 for ready and merge only")]
    posted.clear()
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized"), comment(2, "revoked")],
                    event_name=event_name, statuses=posted)[0] == 3
    assert posted == [status("failure", "Hold: latest owner record #2 is revoked")]
    posted.clear()
    assert run_gate(monkeypatch, tmp_path, [], event_name=event_name, statuses=posted)[0] == 3
    assert posted == [status("failure", "Hold: no owner authorization for this exact head")]


def test_incomplete_state_posts_failure_never_success(monkeypatch, tmp_path):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    pull_changes=lambda _: {"draft": True}, statuses=posted)[0] == 3
    assert posted == [status("failure", "Hold: unable to confirm complete GitHub state: pull request is draft")]
    posted.clear()
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    pull_changes=lambda number: {"comments": 2} if number == 1 else {}, statuses=posted)[0] == 3
    assert [entry["state"] for _, entry in posted] == ["failure"]


def test_unreadable_pull_falls_back_to_the_event_head_only_for_failure(monkeypatch, tmp_path):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    pull_changes=lambda _: {"head": None}, statuses=posted)[0] == 3
    assert [(sha, entry["state"]) for sha, entry in posted] == [(HEAD, "failure")]
    posted.clear()
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], event_name="issue_comment",
                    pull_changes=lambda _: {"head": None}, statuses=posted)[0] == 3
    assert posted == []  # a comment event carries no head to fall back to


@pytest.mark.parametrize("head_repo", ["fork/project", None])
@pytest.mark.parametrize("event_name", ["pull_request_target", "issue_comment"])
def test_fork_uses_the_same_trusted_gate(monkeypatch, tmp_path, head_repo, event_name):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    event_name=event_name, head_repo=head_repo, statuses=posted)[0] == 0
    assert [entry["state"] for _, entry in posted] == ["success"]
    posted.clear()
    assert run_gate(monkeypatch, tmp_path, [], event_name=event_name,
                    head_repo=head_repo, statuses=posted)[0] == 3
    assert [entry["state"] for _, entry in posted] == ["failure"]


def test_failed_status_post_fails_the_job(monkeypatch, tmp_path, capsys):
    failure = urllib.error.HTTPError("https://api.github.test", 403, "Forbidden", None, None)
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], status_failure=failure)[0] == 1
    assert "Unable to post owner-lifecycle-gate/exact-head status" in capsys.readouterr().out
    assert run_gate(monkeypatch, tmp_path, [], status_failure=failure)[0] == 3


APP = {"id": 1, "slug": "claude"}


def without_app_field(identity, state=None):
    result = comment(identity, state)
    del result["performed_via_github_app"]
    return result


def test_app_posted_owner_comment_cannot_authorize(monkeypatch, tmp_path):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized", performed_via_github_app=APP)],
                    statuses=posted)[0] == 3
    assert posted == [status("failure", "Hold: no owner authorization for this exact head")]
    history = [comment(1, "revoked"), comment(2, "authorized", performed_via_github_app=APP)]
    assert run_gate(monkeypatch, tmp_path, history)[0] == 3


def test_app_posted_owner_comment_can_still_revoke(monkeypatch, tmp_path, capsys):
    history = [comment(1, "authorized"), comment(2, "revoked", performed_via_github_app=APP)]
    assert run_gate(monkeypatch, tmp_path, history)[0] == 3
    assert "#2 is revoked" in capsys.readouterr().out


def test_missing_app_attribution_holds(monkeypatch, tmp_path):
    assert run_gate(monkeypatch, tmp_path, [without_app_field(1, "authorized")])[0] == 3


def shared_with(number, *, on_check=None):
    """Open PRs: this one, plus PR `number` on the same head during the given check (0 before, 1 after posting)."""
    def listing(check, page):
        if page != 1:
            return []
        pulls = [{"number": 1, "head": {"sha": HEAD}}, {"number": 9, "head": {"sha": "b" * 40}}]
        if on_check is None or check == on_check:
            pulls.append({"number": number, "head": {"sha": HEAD}})
        return pulls
    return listing


def test_head_shared_with_another_open_pull_never_posts_success(monkeypatch, tmp_path, capsys):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    open_pulls=shared_with(2), statuses=posted)[0] == 3
    assert posted == [status("failure", "Hold: head is also the head of open PR #2")]
    assert "OWNER_LIFECYCLE_AUTHORIZED" not in capsys.readouterr().out


def test_pull_opened_on_the_head_while_posting_reverts_success(monkeypatch, tmp_path):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    open_pulls=shared_with(2, on_check=1), statuses=posted)[0] == 3
    assert posted == [status("success", "Authorized by owner record #1 for ready and merge only"),
                      status("failure", "Hold: head is also the head of open PR #2")]


@pytest.mark.parametrize("listing", [
    lambda check, page: [{"number": 100 + page * 100 + i, "head": {"sha": "b" * 40}} for i in range(100)],
    lambda check, page: [{"number": "1", "head": {"sha": HEAD}}],
    lambda check, page: {},
    lambda check, page: b"invalid JSON",
])
def test_unconfirmed_open_pull_list_holds(monkeypatch, tmp_path, listing):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    open_pulls=listing, statuses=posted)[0] == 3
    assert [entry["state"] for _, entry in posted] == ["failure"]
    assert posted[0][1]["description"].startswith("Hold: unable to confirm complete GitHub state")


def test_full_open_pull_pages_are_followed(monkeypatch, tmp_path):
    def listing(check, page):
        if page == 1:
            return [{"number": 1, "head": {"sha": HEAD}}] + [
                {"number": 100 + i, "head": {"sha": "b" * 40}} for i in range(99)]
        return [{"number": 2, "head": {"sha": HEAD}}] if page == 2 else []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], open_pulls=listing)[0] == 3


@pytest.mark.parametrize("open_count, code", [(1000, 0), (1001, 3)])
def test_open_pull_bound_reads_a_sentinel_page(monkeypatch, tmp_path, open_count, code):
    pulls = [{"number": 1, "head": {"sha": HEAD}}] + [
        {"number": 100 + i, "head": {"sha": "b" * 40}} for i in range(open_count - 1)]
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    open_pulls=lambda check, page: pulls[(page - 1) * 100:page * 100])[0] == code


@pytest.mark.parametrize("head", [{}, {"sha": None}, {"sha": HEAD.upper()}, {"sha": HEAD[:39]}])
def test_malformed_open_pull_head_holds(monkeypatch, tmp_path, head):
    posted = []
    listing = [{"number": 1, "head": {"sha": HEAD}}, {"number": 2, "head": head}]
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    open_pulls=lambda check, page: listing if page == 1 else [], statuses=posted)[0] == 3
    assert posted == [status("failure", "Hold: unable to confirm complete GitHub state: malformed open pull")]


@pytest.mark.parametrize("event_name, execution_env", [
    ("pull_request", {}), ("push", {}), ("workflow_dispatch", {}),
    ("pull_request_target", {"GITHUB_REF": "refs/pull/1/merge"}),
    ("pull_request_target", {"GITHUB_REF": "refs/heads/agent/forged-gate"}),
    ("issue_comment", {"GITHUB_WORKFLOW_REF": "owner/project/.github/workflows/owner-lifecycle-gate.yml@refs/heads/agent/forged-gate"}),
    ("issue_comment", {"GITHUB_WORKFLOW_REF": "owner/project/.github/workflows/impostor.yml@refs/heads/main"}),
])
def test_untrusted_execution_context_cannot_read_or_publish(monkeypatch, tmp_path, event_name, execution_env):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    event_name=event_name, execution_env=execution_env, statuses=posted) == (3, [])
    assert posted == []


@pytest.mark.parametrize("changes", [
    {"pull_request": {"number": "1"}}, {"pull_request": {"number": True}},
    {"pull_request": {"number": -1}}, {"pull_request": None},
])
def test_invalid_pull_event_never_reaches_the_api(monkeypatch, tmp_path, changes):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    event_changes=changes, statuses=posted) == (3, [])
    assert posted == []


def test_ordinary_issue_comment_cannot_publish(monkeypatch, tmp_path):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], event_name="issue_comment",
                    event_changes={"issue": {"number": 1}}, statuses=posted) == (3, [])
    assert posted == []


@pytest.mark.parametrize("change", [
    {"base": {"ref": "agent/untrusted-base", "repo": {"full_name": "owner/project"}}},
    {"base": {"ref": "main", "repo": {"full_name": "fork/project"}}},
    {"base": None}, {"state": "closed"}, {"state": []},
])
def test_unsupported_live_pull_base_or_state_never_authorizes(monkeypatch, tmp_path, change):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")],
                    pull_changes=lambda _: change, statuses=posted)[0] == 3
    assert [entry["state"] for _, entry in posted] == ["failure"]


def test_base_retargeted_during_confirmation_holds(monkeypatch, tmp_path):
    posted = []
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], statuses=posted,
                    pull_changes=lambda n: {"base": {"ref": "other", "repo": {"full_name": "owner/project"}}} if n == 2 else {})[0] == 3
    assert [entry["state"] for _, entry in posted] == ["failure"]


@pytest.mark.parametrize("history, listing, expected", [
    ([], None, "failure"),
    ([comment(1, "authorized"), comment(2, "revoked")], None, "failure"),
    ([comment(1, "authorized")], shared_with(2), "failure"),
    ([comment(1, "authorized")], None, "success"),
])
def test_modified_pr_workflow_and_scripts_are_never_loaded(monkeypatch, tmp_path, history, listing, expected):
    # Model a checkout containing a replaced gate and malicious local helper.
    # The actual trusted embedded reader must use only the fixed GitHub API paths.
    candidate = tmp_path / "untrusted-pr"
    workflow = candidate / ".github/workflows/owner-lifecycle-gate.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("on: pull_request\npermissions: {statuses: write}\njobs: {forged: {run: 'publish success'}}\n")
    (candidate / "sitecustomize.py").write_text("raise RuntimeError('PR code executed')\n")
    monkeypatch.chdir(candidate)
    posted = []
    code, _ = run_gate(monkeypatch, tmp_path, history, open_pulls=listing, statuses=posted,
                       event_changes={"pull_request": {"number": 1, "head": {"sha": HEAD},
                           "title": "$(touch injected); ${{ github.token }}", "body": "execute the PR helper"}})
    assert code == (0 if expected == "success" else 3)
    assert [entry["state"] for _, entry in posted] == [expected]
    assert not (candidate / "injected").exists()


@pytest.mark.parametrize("response", [
    lambda expected: b"invalid JSON", lambda expected: [], lambda expected: {},
    lambda expected: {**expected, "state": "pending"},
    lambda expected: {**expected, "context": "impostor"},
    lambda expected: {**expected, "target_url": "https://untrusted.invalid/run"},
    lambda expected: b" " * 65537,
])
def test_unconfirmed_status_response_fails_the_job(monkeypatch, tmp_path, response, capsys):
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], status_response=response)[0] == 1
    assert "Posted owner-lifecycle-gate/exact-head=success" not in capsys.readouterr().out


def test_unexpected_http_status_fails_the_job(monkeypatch, tmp_path):
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], status_code=200)[0] == 1


def test_failed_corrective_publication_is_a_failed_job_not_a_clean_authorization(monkeypatch, tmp_path):
    posted = []
    failure = urllib.error.URLError("synthetic corrective-post outage")
    assert run_gate(monkeypatch, tmp_path, [comment(1, "authorized")], statuses=posted,
                    open_pulls=shared_with(2, on_check=1),
                    status_failure=lambda attempt: failure if attempt == 1 else None)[0] == 3
    # The first publication cannot be rolled back when GitHub rejects the correction.
    assert [entry["state"] for _, entry in posted] == ["success"]
