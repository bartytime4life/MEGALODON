# Ubuntu installed-wheel recovery evidence

Issue [#260](https://github.com/bartytime4life/MEGALODON/issues/260) remains
**PARTIAL / open**. This separate synthetic CI slice exercises one built wheel
on a fresh non-root Ubuntu 24.04 x86_64 runner with CPython 3.12. It does not
complete the release-evidence packet or the operator recovery drill.

## What runs

The PR-only [workflow](../.github/workflows/installed-recovery-evidence.yml)
checks out the exact PR head with read-only repository permissions and without
persisted credentials. It verifies a clean commit/tree before building and
again before and after recovery. Existing CI and the source-checkout recovery
rehearsal remain separate.

1. Create separate disposable build and installed-package virtual environments
   on the clean hosted runner. Install the existing hash-locked binary build
   requirements, then build one ephemeral wheel with build isolation disabled
   and the package index disabled. No project dependency or lock version changes.
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
The workflow has a ten-minute limit. Failure emits one fixed reason with no
raw exception, command output, or path; the success artifact step does not run.

Python CLI subprocesses reject socket and process-launch audit events. This is
an accidental-effect guard, not an OS sandbox or hostile-native-code containment
claim. The workflow uses network access only for GitHub checkout/setup, the
hash-locked build-tool acquisition, and receipt transport. Wheel installation
and recovery have no network fallback, sensor/model operation, or network test.

## Retained evidence and offline verification

Only `installed-wheel-recovery.json` is uploaded, for 14 days, under an artifact
name containing the exact PR commit, run ID and attempt. No wheel, database,
manifest, configuration, raw CLI receipt or rehearsal log is uploaded. Normal
GitHub build/install logs remain subject to GitHub's log retention settings;
the collector never prints raw recovery output into those logs.

The canonical JSON wrapper contains `receipt` and `receipt_sha256`, a SHA-256
over the key-sorted compact UTF-8 receipt **including its final newline**. The
closed `installed-wheel-recovery-v1` receipt retains only:

- Exact observed commit/tree and clean-source result; wheel distribution,
  version, size and SHA-256.
- Ubuntu/image version, architecture, kernel, systemd, Python, SQLite, installer
  pip, actual build-tool versions and build-requirements digest; non-root as a
  boolean, never a numeric UID. Local validation is explicitly a different
  basis with no hosted-runner image claim.
- Fixed aggregate outcomes and explicit exclusions. It contains no paths,
  usernames, hostnames, environment dumps, timestamps, device/inode identities,
  synthetic event data, raw receipts, or database/manifest digests. Temporary
  database digests and identities are used for comparisons only and discarded.

Obtain the expected commit and tree from the reviewed PR source independently
of the downloaded receipt. From that exact checkout, verify offline:

```bash
python tools/installed_recovery_evidence.py \
  --expected-commit '<reviewed 40-character commit>' \
  --expected-tree '<reviewed 40-character tree>' \
  verify /path/to/installed-wheel-recovery.json
```

Verification reads bounded receipt bytes, checks the closed fields and values,
canonical encoding, digest, and both external source pins. It invokes no host
commands and performs no network request or write. Successful output is
`binding_verified` with `authentication: not_performed`. The wheel digest binds
the described ephemeral subject; the wheel itself is deliberately not retained
by this slice. This is self-asserted CI evidence, not signature verification,
independent reproduction, or an authenticated artifact/build provenance claim.

## Scope and remaining gates

This workflow authorizes only temporary CI installation and synthetic data
creation/removal. It does not install onto an operator host or inspect operator
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
and operational recovery durability remain unproved. Do not close #260 or
promote a synthetic success receipt to operator or release acceptance.

Focused regression tests:

```bash
python -m pytest -q tests/test_installed_recovery_evidence.py
```

They cover the real SQLite rehearsal and refusal, wrong-content/foreign-key and
manifest faults, source/destination preservation, temporary cleanup, receipt
privacy/claim refusals, source-pin mismatches, output/deadline enforcement and
the CLI effect guard. The dedicated CI job supplies the installed-wheel test;
the unit rehearsal uses the source CLI and does not claim installed evidence.
