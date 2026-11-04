# Independent file-inspection review — November 4, 2026

## Scope and decision

Reviewed PR #738 head `1e8086c17a7c42bf2b6f6a6bab2a61dd829590fb`,
its inspection modules, HTTP routing/authentication, runtime catalog/installer,
focused and native tests, HTTP contract and security documentation. Also read
the merged #739 authentication correction on main
`bf2be74e9bdbbb606d366b54b4996dbbd87f7add` before preparing this follow-up.

**Acceptance remains conditional.** The design contains concrete fail-closed
controls, but #738 alone did not enforce its required-authentication claim.
#739 corrects that discrepancy. This follow-up corrects an additional report
coverage defect. Source review and historical CI are not installed-PC acceptance
or proof of parser/kernel vulnerability freedom. No merge, release or installation
is authorized by this review.

## Findings

1. **Required authentication was bypassable in #738 (already fixed by #739).**
   The shared HUD helper deliberately allows read-only launches with no password.
   #738 reused it for inspection without requiring configured sign-in. A local
   caller could obtain the nonce and submit/cancel inspections. Current main
   requires `_file_inspection_context()` on GET and POST and only creates the
   service for protected launches. Existing #739 HTTP tests cover password,
   saved verifier, session cookies, disabled sign-in and nonce/report refusal.
   This review inspected the correction; it did not implement or merge #739.
2. **P2: incomplete structure could pass both report boundaries.**
   `validate_structure()` allowed fewer slice records than `slices_detected`.
   Consequently `normalize_lief()` and `report()` could accept a two-slice
   Mach-O with one reported slice and label both tools completed. The browser
   also accepted that mismatch, counts above 16 with fewer records, and multiple
   ELF/PE slices. The native worker already checks complete Mach-O parsing, so
   this is a defense-in-depth/report-integrity defect, not a demonstrated
   sandbox escape or demonstrated parser output from an actual sample.
   Require exact slice coverage in Python and JavaScript, enforce the 16-slice
   browser ceiling and single-slice ELF/PE rule. New regression tests reproduced
   the acceptance before the fix. The existing UI fixture itself modeled
   incomplete coverage; it now models complete coverage and still tests hostile
   labels rendered as text.

## Safeguards traced in source

| Boundary | Enforcement | Evidence limitation |
| --- | --- | --- |
| HTTP | Exact bound Host; existing operator authentication plus #739 protected-session requirement; exact Origin/check/nonce on actions; duplicate/encoded/chunked envelope refusal; explicit octet-stream bytes only | Authentication is optional elsewhere in the HUD; the inspection-specific gate is essential |
| Upload | One reserved job before body receipt; 1 byte–64 MiB; 64 KiB reads; 10-second monotonic receipt deadline and 0.5-second socket inactivity timeout; failed receipt aborts and closes its descriptor; connection closes to prevent unread-body reuse | Whole-server connection/thread exhaustion is not proven bounded by the single inspection slot |
| Isolation | Required bubblewrap user/PID/network namespaces, disabled nested user namespaces, dropped capabilities, cleared environment, fixed read-only mounts, sealed non-executable input, 1 MiB temporary filesystem | System libraries and Python standard library remain readable trusted mounts; private-runtime hashes do not authenticate those host components |
| Syscalls | Socket/network syscalls, namespace/mount changes, process inspection and other dangerous operations denied; LIEF clone denied; DIE permits only CLONE_THREAD-style clone, with clone3 returning ENOSYS | This is a denylist, not a minimal syscall allowlist; it does not establish immunity to kernel exploits or code execution inside an exploited native parser |
| Memory/tasks | LIEF 512 MiB RLIMIT_AS; DIE 2.5 GiB RLIMIT_AS only after reading exact 512 MiB memory.max, zero memory.swap.max and at most 32 pids.max in its systemd user scope; mismatch exits before bubblewrap/parser | Native cgroup behavior, delegation and OOM teardown must be checked on the installed PC; upload memory lies outside that zero-swap scope |
| Deadline/output | Shared 30-second analysis deadline; per-adapter 15-second CPU limit; 64 KiB output; flooding discarded; no raw stderr returned | Process wait/kill is not a proof against an uninterruptible kernel stall |
| Cleanup/cancel | Receipt stays reserved until abort/submit; running stays reserved until runner exits; cancellation discards late success; process-group kill/reap; parent-death supervisor and PID-namespace teardown; input FD closed in worker finally | Existing native tests exercise controller death for both adapters; this review did not rerun them here |
| Dependencies | Fixed artifact sizes/SHA-256; verification repeated for injected downloaders; extraction selects regular CLI/database/library/license files; private complete-tree digest rejects extra files, links and changed bytes/modes; no maintainer scripts | Catalog byte identity is not signed provenance, a dependency source audit or a current vulnerability assessment; same-user/kernel compromise is outside the stated threat model |
| Malformed/output | Fixed format admission, complete bounded universal slices, parser errors normalized; duplicate JSON keys/nonfinite numbers/excess output rejected; bounded labels/counts; fixed explanations and no safety verdict | Synthetic inputs do not establish detection accuracy or exhaustive malformed-input resilience; the new exact-coverage checks close the identified mismatch |

The analysis path contains no network downloader. Optional installation is a
separate explicit authorized action and does download pinned dependencies;
"offline inspection" must not be interpreted as "the installer never networks."
No selected program, personal download or untrusted executable was run during
this review. No confinement, host policy or firewall setting was weakened.

## Test and CI evidence

- New standard-library regression suite: five tests passed, including Python
  normalizer/report rejection, complete supported coverage and Node execution
  of the shipped browser validator. Before the fix, four test methods failed
  (six assertions/subtests), including both Python and browser acceptance.
- Existing `tests/file_inspection_browser.cjs` workflow passed with the shipped
  JavaScript and updated complete-coverage fixture. Selection/upload, report
  rendering/export, stale association, cancellation and hostile text checks
  remain in that existing harness. This is an inert-DOM component test, not a
  fresh native Chrome or installed-HUD review.
- Python compilation passed for the changed Python files. The scratch runtime
  has no pytest or private native analyzer runtime, so the historical focused,
  full pytest and native results below are not claimed as rerun here.
- #738 exact head: all ten returned PR workflow runs completed successfully,
  including [CI 41889309124](https://github.com/bartytime4life/MEGALODON/actions/runs/41889309124)
  and CodeQL. Its PR records 143 focused tests including 20 native tests.
- #739 exact head `15a85bf`: [CI 41895223137](https://github.com/bartytime4life/MEGALODON/actions/runs/41895223137)
  completed successfully. Its source-test job log independently confirms
  **7,463 passed, 26 skipped, 388 subtests passed**. Its PR records 277 focused
  tests including 21 native tests; those native counts are prior recorded
  evidence. CodeQL and browser acceptance passed. The macOS M1 workflow now
  reports failure with its sole job cancelled; do not describe every #739
  workflow as green. No source defect is established by that cancellation.
- These prior workflow results do not qualify this follow-up's new head.
  Its exact-head checks must be considered separately before promotion.

## Installed Linux PC acceptance still required

Under established owner authorization, use only synthetic fixtures and the
installed application's actual Python/runtime. Confirm protected sign-in and
nonce/report refusal when sign-in is absent; explicit upload only after Inspect;
exact runtime digests; required namespace/seccomp refusal on missing isolation;
ELF/PE/thin and universal Mach-O coverage; malformed/unsupported refusal;
independent DIE memory/swap/task caps and over-cap termination; timeout/output
flood/cancel; FD/scope/namespace cleanup after cancellation, shutdown and
controller death. Confirm no sample persistence, no worker network access,
no target execution and no automatic safety verdict. Review the real HUD at
desktop/mobile sizes and verify report selection/export associations.

Retain exact installed version, source/package identity and measured receipts.
Missing enforcement must refuse inspection, never trigger an unconfined retry.
Owner approval for release/installation remains separate from this source review
and from any observed merges performed by the owner.
