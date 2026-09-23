# Exact-head evidence and owner lifecycle gate

Status: 📜 contract only — proposed exact-head evidence and owner lifecycle
scaffolding; not a required ruleset context at merge time.

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

The `owner-lifecycle-gate` workflow looks only for an issue comment authored by
the repository owner with `author_association=OWNER` and the exact current PR
head:

```text
MEGALODON-OWNER-AUTHORIZATION-V1
head: <40-character PR head>
scope: ready-and-merge
state: authorized
```

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

The workflow never checks out or executes pull-request code and has read-only
permissions. It does not merge, modify the ruleset, create an independent-human
approval floor, or authorize release, deployment, installation, model or sensor
operation, firewall changes, or host control.

The workflow is initially advisory. Making its stable check name required is a
separate owner repository-control decision after exact-head CI and review.
