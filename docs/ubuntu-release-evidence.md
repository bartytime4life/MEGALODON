# Ubuntu 24.04 release-evidence boundary

Issue [#260](https://github.com/bartytime4life/MEGALODON/issues/260)
requires an exact-platform evidence packet before MEGALODON can be evaluated as
a Linux release candidate. The v1 contract is deliberately narrower than a
release workflow: it makes missing evidence machine-readable and refuses every
publication or host-authority claim.

The contract and fixtures are under `contracts/release-evidence/v1`. The local
collector records an exact clean commit/tree plus Ubuntu, kernel, architecture,
CPython, pip, and systemd identity. It requires an expected commit anchored
outside the checkout and a tree resolved from that commit, then performs five
fixed read-only commands: Git
commit identity, Git tree identity, Git working-tree status, configured origin
URL, and `systemd --version`. It does not run the nine acceptance checks, inspect
optional tools, build artifacts, contact a network, or write an evidence file.
Every omitted result stays `not_run` or `not_checked`.

Validation is structural and self-asserted. The configured-origin check catches
an accidental unrelated checkout, but a Git remote can be rewritten and is not
an attestation. The manifest digest binds canonical packet bytes only; it does
not authenticate their origin, reproduce a check, verify a log or artifact, or
prove that a statement is true. Governed use must source the expected commit
outside the checkout, verify the tree bound by that commit, and independently
retain/recompute evidence.

Validate the synthetic contract fixture:

```bash
python tools/ubuntu_release_evidence.py validate \
  contracts/release-evidence/v1/fixtures/accepted/synthetic-incomplete.json
```

Collect an incomplete local identity packet from a clean checkout:

```bash
EXPECTED_COMMIT="<commit from a trusted GitHub PR or API readback>"
python tools/ubuntu_release_evidence.py collect \
  --checkout . \
  --declared-commit "$EXPECTED_COMMIT" \
  --declared-tree "$(git rev-parse --verify "${EXPECTED_COMMIT}^{tree}")"
```

The command writes canonical JSON to standard output. Redirecting it is an
operator choice; the collector itself creates no file. A dirty checkout,
declared/observed Git mismatch, non-Ubuntu-24.04 platform, duplicate JSON key,
unexpected check/component/artifact identity, false optional-health claim,
oversized output, or any effect/authority claim fails closed with one bounded
reason.

The validator reads completed regular files, retaining at most 262,144 bytes
plus one excess-byte sentinel before parsing. Non-regular inputs (including a
Linux FIFO with no writer), oversized files, invalid Unicode, excessive JSON
nesting, and containers in scalar fields return a fixed blocked receipt rather
than a traceback or input excerpt. This is a byte/type boundary, not a
filesystem-latency guarantee or evidence authentication. Valid packets and
historical incomplete receipts retain the same schema and canonical digest.

## What remains before candidate evidence

### Retain and verify the identity packet

The PR-only `incomplete-identity-packet` CI job verifies the emitted wrapper,
recomputes its manifest digest, and checks the exact PR head and checked-out
tree before retaining the single JSON file as a GitHub Actions artifact for
30 days. Its name includes the head SHA, run ID, and run attempt. Upload runs
only after successful collection and validation; a missing file fails the job.
This CI evidence upload contains source/platform identity only, not telemetry,
raw logs, captures, databases, or model output. It is not a package publication
and does not add network access to the offline tool or application.

Download and extract that artifact from the matching Actions run, then verify
it offline from a reviewed checkout. Supply the expected commit and tree from
an independently trusted repository readback, not from the downloaded packet:

```bash
python tools/ubuntu_release_evidence.py verify-packet \
  /path/to/ubuntu-24.04-incomplete-identity.json \
  --expected-commit '<trusted 40-character commit SHA>' \
  --expected-tree '<trusted 40-character tree SHA>'
```

`validate` reads a bare manifest; `verify-packet` reads the complete output of
`collect` or `validate`. The latter rejects extra wrapper keys, malformed or
changed digests, invalid manifests, and mismatched external pins. It uses the
same 256 KiB completed-file input budget and emits the existing canonical
wrapper on success. Verification reads no checkout metadata, invokes no host
commands, and makes no network request. Synthetic packets remain synthetic.

The digest detects inconsistent bytes, not an adversary who changes a manifest
and recomputes its digest. Source pins do not authenticate reported host facts.
Retain the run URL, run attempt, artifact ID and downloaded artifact separately
before expiry if longer retention is needed. Neither this artifact nor a green
identity job supplies the nine execution checks or two built subjects: they
remain `not_run`, and release authority remains `not_authorized`.

### Remaining candidate gates

- Run the exact nine checks on an authorized Ubuntu 24.04 host or runner and
  retain bounded, digest-bound outcomes.
- Build wheel and source distribution only as ephemeral subjects, bind their
  sizes and SHA-256 values, and install/test them in disposable environments.
- Retain the complete operator backup/restore/read-only-inspection drill.
- Produce and review the canonical CycloneDX SBOM and provenance subjects.
- Independently verify license/notice metadata for the exact built subjects.
  The repository Apache-2.0 decision and package metadata merged in #298;
  #255 is closed. This identity-only collector does not inspect license files
  or built artifacts and reports `license.status: not_assessed`, not a stale
  open-issue blocker or a redistribution approval. Historical packets with
  the original #255 blocker remain valid historical contract evidence.
- Obtain the required owner/independent disposition for the exact candidate.

Synthetic contract fixtures cannot be promoted to `candidate_evidence`.
Even a structurally valid observed `candidate_evidence` packet is not attested,
authenticated, independently reproduced, or a tag, GitHub release, package
publication, deployment, installation, supported-platform promise, sensor/model
operation, firewall authority, or operator acceptance.
