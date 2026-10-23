# Read-only host-backup evidence admission

This offline Stage 0 slice validates imported evidence only. It opens no backup,
mounts nothing, runs no restore test, and changes no host file, baseline, process,
firewall, service or recovery target. It cannot certify that a backup is clean,
currently reachable, applicable to this running host, or safe to restore. A
separately authorized design and operator decision are required before adding
any host-changing recovery capability.

## Trust and meaning

An operator must independently review the backup producer's receipt and a
separate verifier's **completed, isolated, full-snapshot restore test** through
an authenticated external channel. The operator establishes the logical source
identity, distinct producer/verifier identities, exact receipt SHA-256 pins and
approval dates in a separate private trust record. The evidence itself cannot
establish or change these anchors. A different identifier alone does not prove
organizational independence: that remains an operator trust decision.

Digest pins bind the exact reviewed bytes; they are **not issuer signatures**.
Anyone who can rewrite both receipts and the operator's trust record can forge
this evidence. Compromised root, the owning account and a dishonest trusted
verifier are outside this proof. No trust record is created by MEGALODON, no
trust-on-first-use occurs, and the browser has no import or approval action.

`verified_external_evidence` means only that the separately pinned records agree,
their closed contracts and chronology validate, and their recorded validity has
not expired. The availability observation, backup creation, test completion and
approval times remain distinct. No fresh backup probe or independent test was
performed by this validator. The external full-snapshot digest algorithm and
the logical source's contents must be reviewed by the operator; arbitrary
producer digests do not establish that a partial backup is a complete host image.

## Fixed private inputs

The protected existing `GET /api/support-config` reads only:

| Input | Fixed path under the HUD user's home |
| --- | --- |
| Operator trust record | `.config/megalodon/recovery-trust.json` |
| Backup producer receipt | `.local/share/megalodon/support/recovery-evidence/backup.json` |
| Independent restore-test receipt | `.local/share/megalodon/support/recovery-evidence/restore-test.json` |

The containing directory must be owner-private and every file an owner-private,
single-link regular file. Reads pin real directory ancestry and use nonblocking,
no-follow file descriptors, bounded to 16 KiB per file. Identity/metadata changes,
symlinks, hardlinks, FIFOs, unsafe ancestry and broad permissions are refused.
The trust bytes are read again after both receipts to detect a concurrent
approval/revocation change. The reader creates no files or directories, never
follows a receipt-supplied path or URL, and retains no positive evidence cache.
Missing or rejected inputs clear every displayed evidence identity.

There is one reviewed backup/source/test pair per trust record. Replace approved
records only through a separate operator-controlled process; a partial update is
unavailable. Removing the trust file revokes admission at the next Setup read.
Synthetic fixtures under `tests/fixtures/host-backup-evidence` are illustrative,
dated test data, not real backup or installed-host acceptance evidence. Never
install their trust record as production approval.

## Closed contracts

All objects require exactly the fields below. IDs contain 1–64 ASCII letters,
digits, dots, underscores or hyphens, starting with a letter or digit. SHA-256
values contain exactly 64 lowercase hexadecimal characters. Timestamps are real
UTC seconds in `YYYY-MM-DDTHH:MM:SSZ` form. Duplicate JSON keys, unexpected fields,
incorrect types and oversized/malformed inputs fail closed.

| Record / schema | Required fields beyond `schema` |
| --- | --- |
| `megalodon-host-backup-receipt-v1` | `backup_id`, `source_id`, `producer_id`, `created_at`, `verified_at`, `expires_at`, `artifact_sha256`, `source_snapshot_sha256`, `artifact_bytes`, `availability` |
| `megalodon-isolated-restore-test-v1` | `test_id`, `backup_id`, `source_id`, `verifier_id`, `artifact_sha256`, `source_snapshot_sha256`, `restored_snapshot_sha256`, `started_at`, `completed_at`, `expires_at`, `result`, `coverage`, `environment`, `conflicts` |
| `megalodon-backup-trust-v1` | `backup_id`, `source_id`, `producer_id`, `verifier_id`, `backup_receipt_sha256`, `restore_test_receipt_sha256`, `approved_at`, `expires_at` |

Admission requires:

- Exact **raw-byte** receipt hashes matching the separate trust record, including
  whitespace and final newlines. Never compute the trust pins automatically from
  unreviewed input as part of an import.
- Matching backup and source IDs across all records, producer/verifier identities
  matching the trust record, and producer distinct from verifier.
- Matching artifact and full source-snapshot digests across backup and test, and
  restored-snapshot digest equal to source-snapshot digest.
- `availability: observed_available`, a positive safe-integer artifact byte count,
  `result: passed`, `coverage: full_snapshot`, `environment: isolated`.
- `conflicts: not_assessed` or `reported_legitimate_changes`. Neither represents
  clearance of current-host conflicts. Reported legitimate changes remain visible
  with an instruction to preserve current work.
- Creation ≤ availability verification ≤ test start ≤ test completion ≤ approval
  ≤ current clock. Each expiry is later than its observation/approval and at most
  seven days later. All three expiries must be strictly later than now; equality
  is expired. The effective expiry is their minimum. A new approval cannot renew
  an expired observation or test. A future observation/approval or clock reversal
  fails closed. The wall clock and external timestamps are trust assumptions.

The projection's fixed refusal reasons are `missing`, `malformed`, `untrusted`,
`conflicting`, `incomplete`, `expired` and `unreadable`. All detail fields are null
on refusal; raw exceptions and paths are never returned.

## Recovery readiness integration

The existing v1 `recovery_readiness` projection is unchanged: host recovery stays
unavailable, backups are not integrated as executable recovery sources,
`restore_eligible` is false, attribution is unavailable and current conflicts are
not assessed. The separate `backup_evidence` field on the same protected Setup
response adds `megalodon-backup-evidence-v1` and a bounded receipt summary. Setup
renders it **inside Recovery readiness** as pinned external evidence with source,
backup and test IDs, dates and digests. The browser independently validates the
summary, chronology and expiry when rendering, uses text nodes only, and clears
the details on failed Setup reads. Existing Setup polling supplies fresh reads;
this slice adds no timer, action endpoint, dependency, upload, collector or model
permission.

An AIDE change, no-difference report, reputation match or AI explanation never
changes admission or restoration eligibility. Valid receipts can coexist with
legitimate package updates and user edits; the earlier snapshot must not be
recommended for restoration on that basis. Audit-database recovery and reference
library rollback remain separate and cannot supply host-backup evidence here.

## Verification and rollback

Run the synthetic validator and panel tests, Setup integration tests, existing
integrity/host findings tests, repository hygiene guard and CodeQL workflow on
the exact candidate. Native installed-host acceptance and real independent
restore-test evidence remain unverified until separately obtained.

Rollback to the previous MEGALODON version or remove the trust record; no cleanup,
host restoration, file deletion or containment is needed. Preserve real receipts
outside the repository under operator control.
