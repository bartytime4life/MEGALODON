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

The workflow never checks out or executes pull-request code and has read-only
permissions. It does not merge, modify the ruleset, create an independent-human
approval floor, or authorize release, deployment, installation, model or sensor
operation, firewall changes, or host control.

The workflow is initially advisory. Making its stable check name required is a
separate owner repository-control decision after exact-head CI and review.
