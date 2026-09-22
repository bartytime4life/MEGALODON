# Ubuntu candidate evidence coverage index

Status: 📜 contract only — receipt-ingestion scaffold for issue #260; no
candidate, operator drill, or release acceptance is produced by this change.

The repository already has a closed nine-check/two-artifact Ubuntu manifest,
offline packet verification, and digest-bound SBOM/provenance generation. The
coverage index adds the missing cross-reference from every claimed check,
artifact, optional-source state, and remaining acceptance gate to a retained,
digest-bound evidence reference and its authentication class.

Initialize an index without inventing evidence:

```bash
python tools/ubuntu_candidate_coverage.py init candidate-manifest.json \
  --expected-commit <40-char-commit> \
  --expected-tree <40-char-tree> > coverage.json
```

Initialization copies the source manifest's real `passed`, `failed`, `blocked`,
`not_run`, artifact, and optional-component states. Every evidence pointer is
left `not_performed`; the result remains `incomplete`.

Validate an edited index against the exact source manifest:

```bash
python tools/ubuntu_candidate_coverage.py validate \
  candidate-manifest.json coverage.json \
  --expected-commit <40-char-commit> \
  --expected-tree <40-char-tree>
```

A complete index requires all nine source checks to be passed and receipt-bound,
both artifacts to be built and receipt-bound, and all seven remaining gates to
be accepted with retained evidence. Independent disposition requires an
`independent` authentication class. A synthetic manifest can never become
complete. Optional components retain the source contract's `unavailable`
health and cannot be relabeled healthy merely because they are absent, disabled,
or unqualified.

The index consumes existing evidence; it runs no tests, builds no artifacts,
installs no package, performs no recovery drill, authenticates no host, and
grants no tag, release, publication, deployment, service, firewall, sensor,
model, restored-data, or independent-acceptance authority.
