# Ubuntu installed-wheel recovery evidence

The planning issue [#260](https://github.com/bartytime4life/MEGALODON/issues/260)
was closed on 2026-09-22; operational release acceptance remains incomplete.
These synthetic CI slices exercise installed wheels on fresh
non-root Ubuntu 24.04 x86_64 runners with CPython 3.12. One rehearses an
independently built ephemeral wheel; the other rehearses the exact wheel retained
as a release subject. Neither completes the release-evidence packet or the
operator recovery drill.

## What runs

The PR-only [independent recovery workflow](../.github/workflows/installed-recovery-evidence.yml)
builds its own ephemeral wheel. The
[release-subject workflow](../.github/workflows/release-subject-evidence.yml)
also runs recovery in its `build-subjects` job, using the one wheel already built
for retention and the actual `release-build` Python environment that built it.
It does not rebuild a replacement wheel. Both check out the exact PR head with
read-only repository permissions and without persisted credentials, and verify
a clean commit/tree before building and before and after recovery. Existing CI
and the source-checkout recovery rehearsal remain separate.

1. Create separate disposable build and installed-package virtual environments
   on the clean hosted runner. Install the existing hash-locked binary build
   requirements, then build with isolation and the package index disabled. The
   independent workflow builds one wheel; the release-subject job reuses its
   wheel-and-sdist build. No project dependency or lock version changes.
2. Install that wheel into the fresh runtime environment with `--no-index
   --no-deps --no-cache-dir`. Run Python with `-I`, outside the checkout, without
   `PYTHONPATH` or `PYTHONHOME`. Require only pip and megalodon-defense to be
   installed; confirm the imported package is inside this environment, pip's
   local-wheel SHA-256 matches, and installed package files equal the wheel bytes.
3. In owner-private temporary directories, ingest exactly 13 built-in synthetic
   sample events. Explicitly disable dashboard and firewall behavior. Run the
   real CLI backup and restore commands, restoring only into a new destination.
4. Independently hash the backup and manifest and compare both operations'
   digests. After CLI writers exit, inspect the source with `mode=ro`; require
   no sidecars on the closed backup/restored files and inspect them with
   `mode=ro&immutable=1`: schema v3,
   full integrity check, zero foreign-key violations, and exact equality of all
   seven tables, including ingestion relationships and SQLite sequences.
5. Repeat restore into the now-existing destination. Require exit code 2 and
   `DESTINATION_EXISTS`, with no created/complete destination claim. Compare
   device/inode identity and exact file bytes before and after the refusal,
   then repeat read-only inspection. Check the source bytes and contents remain
   unchanged. Remove the synthetic temporary directory before reporting success.

The [collector/verifier](../tools/installed_recovery_evidence.py) uses a closed
allowlist and emits success only after every check passes. Commands have a
30-second deadline and a combined 16 KiB stdout/stderr limit enforced while
draining pipes. Files are limited to 8 MiB; manifests and receipts to 16 KiB;
table reads to 1,024 rows per table with a five-second SQLite query deadline.
The independent workflow has a ten-minute limit. Failure emits one fixed reason
with no raw exception, command output, or path; the success artifact step does
not run.
The independent `installed-recovery-roundtrip` job downloads the producer's exact
artifact ID on a fresh runner. It requires the one expected regular JSON file,
compares its bytes with the producer's SHA-256, resolves the PR head/tree from
its own clean checkout, and verifies every phase binding offline. It does not
repeat the recovery drill or turn a self-asserted receipt into acceptance.

For retained-subject recovery, collection additionally verifies the closed
three-file release-subject directory against the external commit/tree and
requires the installed wheel's version, size and SHA-256 to match its manifest.
It repeats this binding after the drill. The release workflow's
`subject-roundtrip` job downloads the producer's exact subject and recovery
artifact IDs into separate directories, compares their manifest/receipt hashes
with the producer's outputs, and verifies both source pins and the cross-artifact
wheel binding. The recovery receipt stays outside the subject directory, which
still contains exactly the wheel, sdist and `subjects.json`.

Python CLI subprocesses reject socket and process-launch audit events. This is
an accidental-effect guard, not an OS sandbox or hostile-native-code containment
claim. The workflows use network access only for GitHub checkout/setup, the
hash-locked build-tool acquisition, and artifact transport. Wheel installation
and recovery have no network fallback, sensor/model operation, or network test.

## Retained evidence and offline verification

The independent recovery workflow uploads only `installed-wheel-recovery.json`
for 14 days, under `installed-recovery-<head>-<run-id>-<attempt>`. Its wheel is
not retained. The release-subject workflow retains its wheel, sdist and
`subjects.json` as before, and uploads the same recovery JSON format separately
under `release-subject-recovery-<head>-<run-id>-<attempt>`, also for 14 days.
Neither recovery artifact includes a database, backup manifest, configuration,
raw CLI receipt or rehearsal log. Normal GitHub build/install logs remain
subject to GitHub's log retention settings; the collector never prints raw
recovery output into those logs.

The canonical JSON wrapper contains `receipt` and `receipt_sha256`, a SHA-256
over the key-sorted compact UTF-8 receipt **including its final newline**. The
closed `installed-wheel-recovery-v2` receipt retains only:

- Exact observed commit/tree and clean-source result; wheel distribution,
  version, size and SHA-256.
- Ubuntu/image version, architecture, kernel, systemd, Python, SQLite, installer
  pip, actual build-tool versions and build-requirements digest; non-root as a
  boolean, never a numeric UID. Local validation is explicitly a different
  basis with no hosted-runner image claim.
- Four ordered, closed phase receipts for backup, read-only inspection,
  restore, and overwrite refusal. Each repeats the exact commit/tree, installed
  wheel digest, original source digest, backup digest and manifest digest.
  Restore and refusal additionally bind the restored database digest. CLI
  phases retain only the digest of the canonical raw CLI receipt, never its
  host paths. The verifier requires matching subject digests across phases and
  the same restored database digest before and after refusal.
- Fixed aggregate outcomes and explicit exclusions. It contains no paths,
  usernames, hostnames, environment dumps, timestamps, device/inode identities,
  synthetic event data, or raw CLI receipts. The temporary database, backup and
  restore bytes are removed after inspection; their digests remain as
  self-asserted bindings.

Obtain the expected commit and tree from the reviewed PR source independently
of the downloaded receipt. From that exact checkout, verify offline:

```bash
python tools/installed_recovery_evidence.py \
  --expected-commit '<reviewed 40-character commit>' \
  --expected-tree '<reviewed 40-character tree>' \
  verify /path/to/installed-wheel-recovery.json
```

Verification reads bounded receipt bytes, checks the closed fields and values,
canonical encoding, digest, phase relationships, and both external source pins.
It invokes no host commands and performs no network request or write. Successful
receipt-only output is `binding_verified` with `authentication: not_performed`.
It does not compare the wheel digest with a retained release artifact. For the
independent workflow, the wheel itself is unavailable after cleanup; matching
source pins or package versions do not establish matching archive bytes.

To verify the retained-subject path, download both artifacts from the same
release-subject workflow run and supply the subject directory as well:

```bash
python tools/installed_recovery_evidence.py \
  --expected-commit '<reviewed 40-character commit>' \
  --expected-tree '<reviewed 40-character tree>' \
  verify /path/to/recovery/installed-wheel-recovery.json \
  --subjects-directory /path/to/release-subjects
```

The optional `--subjects-directory` argument follows `collect` or `verify`.
When supplied, it requires native release-subject verification and exact
wheel version/size/SHA-256 equality; it never falls back to receipt-only
verification. Successful paired verification reports
`release_subject_binding_verified` with `authentication: not_performed`.
The existing v2 receipt format remains unchanged. The independent workflow and
historical receipts retain their narrower meaning.

This paired check binds a synthetic recovery receipt to the retained wheel
bytes. It does not authenticate the CI runner or builder, prove that an
independent rebuild is byte-identical, or perform signature verification. The
backup, backup manifest and restored database are still not retained; their
digests cannot independently prove their temporary bytes after cleanup.

## Scope and remaining gates

These workflows authorize only temporary CI installation and synthetic data
creation/removal. They do not install onto an operator host or inspect operator
data. The restored store is never selected or activated. No release, tag,
package publication, trusted publishing, deployment, service installation,
remote UI, firewall apply, scheduler/notifier, live sensor or model operation,
or broader network authority follows.

The existing candidate packet's nine-check/two-artifact state is unchanged.
Sdist recovery, install/upgrade/rollback/uninstall qualification, the complete
operator backup/verify/restore/read-only-inspection drill, canonical candidate
SBOM/provenance review and authentication, artifact notices, independent review
and exact-candidate owner acceptance remain separate gates. Physical disk-full,
power-loss/hard-kill, concurrent high-write WAL, clock rollback, native Windows,
and operational recovery durability remain unproved. Closing the planning issue
does not promote a synthetic success receipt to operator or release acceptance.

Focused regression tests:

```bash
python -m pytest -q tests/test_installed_recovery_evidence.py
```

They cover the real SQLite rehearsal and refusal, wrong-content/foreign-key and
manifest faults, source/destination preservation, temporary cleanup, receipt
privacy/claim refusals, source-pin mismatches, output/deadline enforcement and
the CLI effect guard. The CI recovery jobs supply the installed-wheel tests;
the unit rehearsal uses the source CLI and does not claim installed evidence.
