# Native Windows core acceptance v1

Status: **EVALUATION CONTRACT AND SYNTHETIC NEGATIVE CONTROLS; NATIVE SUPPORT
UNPROVED.** This document implements the bounded planning/test-fixture slice in
[issue #27](https://github.com/bartytime4life/MEGALODON/issues/27). It follows the
canonical [platform baseline](platform-baseline.md) and does not add a driver,
analyzer, firewall backend, service, installer, privilege, or support claim.

The machine-readable matrix is
[`contracts/platform/windows-core-v1/acceptance.json`](../contracts/platform/windows-core-v1/acceptance.json).
Its historical inspection basis is
`7435eee1503f76b6b07ccbc45278f4ad71aec4cf`; that baseline is not an execution
target. Because a file cannot embed the SHA of a commit that contains itself,
the exact candidate commit and tree must come from the current PR or operator
handoff receipt and must be recorded with the native result.
`synthetic_reusable` means a test is a candidate for native execution; it does
not mean that test has run on Windows. `native_receipt_required` identifies a
boundary that Linux execution or platform monkeypatching cannot settle.

## Acceptance matrix

| Feature | Current evidence | Required native W1 evidence | Promotion boundary |
| --- | --- | --- | --- |
| Metadata validation and bounded JSONL/sample processing | Portable-looking deterministic tests; no native result | Standard CPython 3.13 on maintained Windows 11 x64; exact-head selected tests and CLI sample/JSONL receipts | May be called tested only for the recorded OS/build/interpreter |
| Fixed detectors | Deterministic synthetic acceptance fixtures | Same fixtures on native W1 with exact counts and no blanket skips | Does not establish real-world detection accuracy |
| SQLite audit | Linux transaction/failure tests | Local non-synced NTFS database plus WAL/SHM behavior, transaction tests, reopen/integrity result and ACL inventory | Temporary-directory success or POSIX modes do not certify privacy |
| Read-only dashboard | Linux DOM/API/bind tests | Numeric loopback listener readback and real native browser/API flow, including error recovery and no mutation endpoints | No remote bind, proxy, tunnel, or authentication claim |
| Private storage | Documentation only | Reviewed owner/access entries for checkout, database, WAL/SHM and any receipts; reject redirected/shared locations | Displaying an ACL is not remediation or approval |
| Offline analysis/projection | Linux-only implementation | Deterministic `LINUX_REQUIRED`; use a separately validated Linux guest for supported analysis | Installing Windows Wireshark/TShark does not enable the adapter |
| Live Scapy capture | Unsupported | Bounded Linux-only refusal before Scapy import or interface access | No Npcap/driver installation or substitution |
| nftables planning | Unsupported | Bounded Linux-only plan refusal before executable discovery; live apply is always refused first | No Windows Firewall translation or host change |

## Native execution handoff

Obtain the exact candidate commit and tree from the current PR or reviewed
operator handoff, verify both after a fresh detached checkout, and confirm that
the checkout contains this matrix. Do not substitute `repository_baseline` or a
branch name. Run the matrix's exact selected paths and node IDs in a non-elevated,
local, non-synced directory. Record Windows edition/build, x64 architecture, the
exact standard CPython 3.13 version, dependency resolution, commit/tree, and every
selected test's pass/fail/skip count. Exercise sample and bounded synthetic JSONL
only. Do not use a live interface, real telemetry, offline analyzer, firewall
command, service, scheduled task, Administrator session, or security exception.

Before opening SQLite, inventory the target NTFS owner and access entries. After
the synthetic writes, inspect the database and any `-wal`/`-shm` sidecars, reopen
the database, run the existing integrity/transaction checks, and record only
bounded metadata. Do not publish paths containing personal data, database rows,
addresses, or the database files themselves.

For the UI, start the foreground server on `127.0.0.1`, read back the native
listener, and use a real local browser to test the current summary/events API,
five-field projection, keyboard controls, pause/hidden polling, and recovery.
Stop the server manually. A source assertion or CI server process is not a native
Windows 11 browser receipt.

## Unsupported-operation controls

The runtime refuses Windows Scapy capture and nftables planning before optional
imports or executable discovery. Every live-apply route, on every platform,
returns its fixed evaluation-release diagnostic before configuration, platform,
executable, privilege, or subprocess work. The existing offline command and the
offline-dashboard projection return `LINUX_REQUIRED` before POSIX descriptor or
ownership operations. Tests use only platform substitution and forbidden-boundary
sentinels; they do not emulate a Windows kernel, NTFS, Winsock, browser, or
process model.

## Evidence and lifecycle rules

Keep the Ubuntu 24.04/Python 3.11 job named `test` unchanged and required. A
future Windows job is additive and must name its narrower profile; skipped
Linux-only operations are negative evidence, not positive feature passes. Do not
promote the capability catalog from `evaluation_only` until the native receipts
above exist at one exact head and have independent review. Green hosted checks,
a merged PR, or issue closure do not supply that review.
