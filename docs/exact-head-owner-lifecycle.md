# Exact-head evidence and owner lifecycle gate

Status: implemented advisory workflow and evidence contract. The owner status
is not an enforced, exclusive-writer authorization boundary. No new required
check or repository setting is enabled by this correction.

## Evidence manifest

`megalodon.exact-head-evidence/v1` binds an observation to a full commit and
tree, the exact commands and exit codes, retained artifact digests, collector,
acceptance posture, and supersession state.

```bash
python tools/validate_exact_head_evidence.py \
  path/to/manifest.json \
  --current-head "$(git rev-parse HEAD)"
```

A manifest marked `current` is invalid unless the supplied observed head
matches. Release, deployment, and host authority are fixed to `false`.
Independent acceptance requires an independent collector.

## Owner lifecycle comment

### Trusted execution

The gate listens to `pull_request_target` for PRs targeting `main` and to
PR `issue_comment` creation, edits and deletion. Authorization code is embedded
in the trusted default-branch workflow. There is no checkout, reusable workflow,
action, cache, downloaded artifact, PR script or PR-content expression in the
executable step. Python runs in isolated mode (`-I`), ignoring user-site,
current-directory and `PYTHON*` import overrides. PR data is consumed as JSON,
never as shell or Python source.
The token has only `issues: read`, `pull-requests: read`, and `statuses: write`
in that job; workflow-level permissions are empty. No contents permission or
repository-content API read is needed.

The reader additionally requires the expected `main` workflow ref and runtime
ref, rejects unsupported events before any API call, and requires the live PR
to be open against this repository's `main`. Base identity and open state join
the existing repeated pull-state comparison. These runtime checks are defense
in depth, not proof of provenance against someone who can replace the script.
The event selection establishes which repository code GitHub executes.

This change takes effect only after reviewed code reaches `main`. CI on this
PR tests candidate code; it does not activate or demonstrate the new trusted
event selection. Re-running a historical run uses its historical workflow and
does not establish adoption of this repair. A fresh event after adoption needs
its workflow ref/SHA, evaluated PR head, run result and published status checked.

The `owner-lifecycle-gate` workflow looks only for an issue comment authored by
the repository owner with `author_association=OWNER` and the exact current PR
head:

```text
MEGALODON-OWNER-AUTHORIZATION-V1
head: <40-character PR head>
scope: ready-and-merge
state: authorized
```

A comment the GitHub API reports as `performed_via_github_app` was posted by
an app acting with the owner's token, not typed by the owner. Such a record can
revoke but never authorizes. GitHub cannot attribute comments made with a
personal access token or an OAuth app this way, nor app edits or deletions of
existing comments, so treat those tokens as able to authorize.

A later exact-head owner record with `state: revoked` supersedes an earlier
authorization. Synchronizing the branch changes the head and invalidates the
old record automatically.

The reader retrieves complete numbered pages for up to 1,000 issue comments
(including an empty sentinel page after an exactly full last page),
then repeats the read and compares all fields used by the decision. Pull head,
draft state, and comment count must remain unchanged before, between, and after
the two scans. Missing, malformed, reordered, or changing records cause HOLD;
so do API failures, the 1,000-comment limit, an 8 MiB response limit, a shared
128 MiB transfer limit, or the shared 180-second read deadline. The five-minute
job timeout remains the outer execution bound. Comment deletions also trigger
reevaluation. Pagination paths are constructed locally, never taken from a
response-provided URL.

These checks detect observed changes and incomplete pagination; they are not an
atomic GitHub snapshot. Comments or the PR can still change after the final
read. Existing records retain creation-time and ID precedence when edited.
An oversized or unstable thread requires a separately reviewed lifecycle
decision; the workflow never silently uses a partial history.

## Commit status on the PR head

The trusted events run in the base/default-branch context, so the
`exact-head-owner-authorization` job check is not evidence of a test of PR code.
Each run therefore also posts its verdict as the
commit status `owner-lifecycle-gate/exact-head` on the PR head it evaluated:

- `success` only for a confirmed, unrevoked owner record naming that exact head;
- `failure` for every HOLD, including draft, incomplete or changing state.
  When the pull request itself cannot be read, a `pull_request_target` run falls back
  to the head SHA in its event, and only ever to post `failure`.

A new push changes the head, which starts with no status until a run evaluates
it. Fork PRs use the same trusted `pull_request_target` evaluator and publication
rules; fork content is never executed. Publication requires HTTP 201 and a
bounded JSON response matching the submitted state, context, description and
run URL. A transport failure, unexpected HTTP status, malformed response or
response mismatch fails the job. This confirms the API response, not future
status persistence or exclusive authorship.

A status stays until a later run replaces it. If a comment-triggered run cannot
read the pull request at all, it has no head to post to: the job fails, and an
earlier `success` stands until a run completes. Re-run the job after posting a
revocation if that run failed.

A status belongs to a commit, not a pull request, so every open PR whose head
is that commit would share it. `success` is therefore posted only while no other
open PR has the same head, checked before posting and again right after; if one
appears, the run replaces `success` with `failure`. Its own run also posts
`failure`. Two open PRs on one head both hold until one closes. Closing does not
trigger this workflow, so re-run the job on the remaining PR. A complete scan
covers up to 1,000 open PRs, confirmed by an empty sentinel page; more, or a
malformed entry, is a HOLD.

### Remaining status identity and enforcement limits

Moving this evaluator to a trusted event fixes PR substitution of **this
workflow's authorization logic**. It does not reserve the status context.
Another same-repository workflow can request `statuses: write` and post the
same `owner-lifecycle-gate/exact-head` context using its `GITHUB_TOKEN` without
executing this evaluator. A repository token's read-only default is not an
immutable ceiling on permissions requested by workflow YAML. Other credentials
with status-write authority can also imitate the context. Selecting GitHub
Actions as the expected App source alone cannot distinguish these workflows.

No consumer may treat a green context alone as owner authorization. Until an
exclusive writer is established, verify the actual trusted workflow run/ref,
exact evaluated head, unrevoked human owner record, and shared-head state.
An ordinary job check is not a replacement for this provenance review.

If a newly opened shared-head PR cannot publish its HOLD, or if a corrective
failure after success cannot be published, the earlier success remains. The
job fails, but GitHub has no atomic transaction spanning PR state, comments
and commit status. Cancellation, skipped events, retargeting away from `main`,
and API failures can leave stale statuses. A failed or absent reevaluation is
never fresh authorization; recheck live state and use a fresh trusted run.

### Free-plan protections and the next owner gate

OBSERVED on 2026-10-18 at `main@b3b81e10b20d5e1a72fea62a0d0ef7d4dfd17659`:
this is a public personal repository. Active ruleset `22394782` targets the
default branch, requires strict `test` from GitHub Actions (integration 15368),
requires a PR and linear history, and prohibits ref creation, deletion and
non-fast-forward updates with no bypass actors. It requires zero approving
reviews; CODEOWNERS, stale-review dismissal, last-push approval and thread
resolution are off. Ruleset `24377756` adds Copilot review plus deletion and
non-fast-forward restrictions; it does not establish human owner authorization.
The classic branch-protection API returned HTTP 403 (`Resource not accessible
by integration`), so no classic-protection completeness claim is made. Neither
observed ruleset requires the owner status.

GitHub Free supports protected branches and branch rulesets for public
repositories. Human review/CODEOWNERS requirements and expected-App status
sources are possible governance choices here, not a reason to buy a plan.
They have not been changed. Default token permissions or CODEOWNERS files
alone do not prevent a different same-repository workflow from writing a status.

PROPOSED, separately authorized: establish a dedicated status/check publisher
identity whose credential and evaluator cannot be reached or replaced by PR
workflows, then bind the required context to that App and retain the existing
`test` requirement. A separately operated App is one design to evaluate; its
credential isolation, free operating arrangement and acceptance are not
established here. Do not make the current shared-identity advisory status a
claimed tamper-proof requirement. No App, secret, paid setting, protection,
merge, release or deployment is created by this change.

Primary GitHub references:

- [Trusted `pull_request_target` event and untrusted-code warning](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request_target)
- [Workflow `permissions` and token behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [Public Free protected branches and expected-App status sources](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Ruleset availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)

### Reproducible candidate validation

From the repository root with its test dependencies installed:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  python -m pytest tests/test_owner_lifecycle_gate_contract.py \
  tests/test_owner_lifecycle_history.py -ra
python -m compileall -q megalodon tests
```

The regression suite executes the actual embedded reader with synthetic API
responses. It covers modified PR workflow/helper files, unsupported execution
contexts, missing and revoked authorization, app-posted comments, exact-head
binding, fork parity, shared heads before/after posting, pagination/bounds,
retargeting, and rejected or unconfirmed publication. These tests cannot prove
GitHub event dispatch, exclusive status identity, or installed-host behavior.

The workflow never checks out or executes pull-request code. Its only write
permission is `statuses: write`, used for that one advisory status. It does not merge,
modify the ruleset, create an independent-human approval floor, or authorize
release, deployment, installation, model or sensor operation, firewall changes,
or host control.

The workflow remains advisory. Enforced owner authorization remains BLOCKED on
an isolated publisher identity, a separate owner protection decision, and
fresh hosted acceptance of the adopted trusted workflow.
