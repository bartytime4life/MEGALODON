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

The dependent `identity-artifact-roundtrip` job uses a fresh runner and the
upload step's exact artifact ID, never a latest-artifact search. It rejects a
missing ID, fails on an archive-digest mismatch, requires exactly the expected
non-symlink JSON file, and compares its SHA-256 with the producer job's original
file digest. It then verifies the wrapper against the event's PR head and the
tree independently resolved from that checkout, and requires an incomplete
local-checkout packet with all checks/subjects `not_run` and effects false.
Success proves a same-run artifact round trip; it is not independent security
review, host-fact authentication, or completion of the release-candidate checks.

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

## Release-evidence packet

`tools/release_evidence_packet.py` is the narrow handoff after a complete
GitHub-Actions `candidate_evidence` wrapper exists. It does not build or install
packages, execute a host command, inspect the environment, contact a network,
sign, tag, publish, upload, or deploy. It accepts exactly one pure-Python wheel
and one sdist for `megalodon-defense`, recomputes their bounded SHA-256 values
and sizes, and requires exact equality with the candidate manifest. A
synthetic, local-checkout, incomplete, source-mismatched, non-canonical, or
artifact-mismatched input is refused with a fixed reason that does not include
input data or local paths.

Generation requires the expected commit and tree from an independently trusted
readback and an explicit UTC timestamp. The tool never reads the host clock.
The destination must not exist; output is first written with private file modes
to a sibling staging directory, verified there, and atomically renamed. It
never overwrites an existing path.

```bash
python tools/release_evidence_packet.py generate \
  --candidate /path/to/candidate-evidence.json \
  --wheel /path/to/megalodon_defense-0.1.0-py3-none-any.whl \
  --sdist /path/to/megalodon_defense-0.1.0.tar.gz \
  --output /new/path/megalodon-release-evidence \
  --package-version 0.1.0 \
  --generated-at '2026-09-20T23:59:59Z' \
  --expected-commit '<trusted 40-character commit SHA>' \
  --expected-tree '<trusted 40-character tree SHA>'
```

The closed output set is:

- `candidate-evidence.json`: the canonical validated input wrapper;
- `megalodon.cdx.json`: CycloneDX 1.7 JSON for the core package, its declared
  empty runtime dependency set, and the exact wheel/sdist subjects;
- `provenance.intoto.json`: an in-toto Statement v1 with the SLSA provenance v1
  predicate, source identities, candidate digest, and both artifact subjects;
- `packet.json`: the source, artifact, candidate, SBOM, and provenance digest
binding plus privacy, effect, and limitation statements.

The provenance profile's `buildType` is this section at the exact source
commit. Its closed `externalParameters` name the repository, commit, tree,
package, version, `.github/workflows/ci.yml`, the `wheel-smoke` job, and the
canonical candidate-evidence digest. `resolvedDependencies` binds the Git
commit, Git tree, and candidate-evidence bytes. `runDetails.builder.id` binds
the workflow path to the same commit. `internalParameters` is empty and the
profile deliberately omits an invocation ID, runner name, environment, command
line, and build timestamps; those values are not required to recompute the
subject binding and would expand the receipt's identifying surface. The
repository-controlled workflow is the described build entrypoint; the packet
generator only records the already built subjects and never initiates it.

Every JSON file is UTF-8, key-sorted, compact, newline-terminated canonical
JSON. The packet and command receipts include source identities, artifact
basenames/sizes/digests, document digests, package identity, and the explicit
timestamp. They exclude absolute paths, usernames, hostnames, environment
variables, command lines, logs, telemetry, and credentials. The SBOM scope is
intentionally the core distribution and declared runtime dependencies; optional,
build, test, OS, and browser components are not silently presented as covered.

Offline verification reads exactly the four regular packet files and the two
artifact subjects, recomputes every digest, rebuilds the expected SBOM and
provenance shapes, and compares the source to external pins. It invokes no host
command and performs no network request or write:

```bash
python tools/release_evidence_packet.py verify \
  /path/to/megalodon-release-evidence \
  --wheel /path/to/megalodon_defense-0.1.0-py3-none-any.whl \
  --sdist /path/to/megalodon_defense-0.1.0.tar.gz \
  --expected-commit '<trusted 40-character commit SHA>' \
  --expected-tree '<trusted 40-character tree SHA>'
```

Successful output says only `binding_verified` and
`authentication: not_performed`. The provenance is unsigned and self-asserted;
the source-pinned workflow builder identity does not establish a SLSA build level. The
packet remains `generated_unreviewed` and does not convert the existing SBOM or
provenance gates to accepted, authenticate the runner or host facts, prove a
reproducible build, review artifact notices, or grant release authority.

### Remaining candidate gates

The separate PR workflow `Ubuntu synthetic recovery rehearsal` runs the real
sample ingestion, backup and restore CLI paths as a non-root user on Ubuntu
24.04. It uses 13 synthetic events in private temporary directories, compares
the backup/manifest digests reported by both operations, verifies source and
restored databases read-only (integrity, foreign keys and event counts), and
confirms a second restore refuses the existing destination without replacing
it. It emits a small source-pinned summary; it uploads no database or raw log.
Temporary rehearsal files are removed when the test ends. No restored store
is activated and no operator database is inspected or modified.

This exercise is repeatable synthetic CLI integration evidence. It does not
populate the release packet's nine checks, retain a recovery backup for an
operator, or establish physical disk-full, power-loss, high-write WAL, clock
rollback, installed-package recovery, independent review or owner acceptance.
Those candidate gates remain below.

- Run the exact nine checks on an authorized Ubuntu 24.04 host or runner and
  retain bounded, digest-bound outcomes.
- Build wheel and source distribution only as ephemeral subjects, bind their
  sizes and SHA-256 values, and install/test them in disposable environments.
- Retain the complete operator backup/restore/read-only-inspection drill.
- Generate the digest-bound CycloneDX/provenance packet for the exact candidate,
  retain it with the subjects, and complete independent review/authentication.
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
