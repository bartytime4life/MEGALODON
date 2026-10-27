# Documentation refresh — October 27, 2026

## Source and scope

The source basis is `7c912322b12fe40fbe92de79b32fdc678054a3da`, tree
`f56752b3cd5d4aa9e70d058f6474ae6c5a37f862`. Before editing, an isolated
snapshot matched all **1,033 source Git blob identities**. The primary local
checkout was older and contained unfinished application edits; it was preserved.
An execution-environment interruption was recovered before local validation.

This pass updates maintained README/field-guide/Wiki entry points, connects
current Findings and Setup documentation through three investigation journeys,
and adds two finite moving visuals with still alternatives and byte provenance.
The original synthetic capture bytes and historical benchmarks are unchanged.

## Claims corrected

The README overstated external backup-evidence trust. Two receipts are pinned
by hashes in a separate operator-controlled trust record. That trust record is
not independently hash-pinned; rewriting all three files can forge evidence.
The README, technical chapter and new journey now state this explicitly.

Current-source CI `40552674917`, CodeQL `40552674698` and Qwen zero-effect
`40552674943` were observed successful. Linux browser `40552674797` was
cancelled. Its cancellation is not a browser pass. The earlier October 22
check results remain historical with their original pin.

No current hosting metadata, installed-PC revision, native producer/model
acceptance, operational detection accuracy or independent security clearance
is inferred from this work. The Security Cloud UI was opened; no scan result
was supplied by that operation and no security scan is claimed.

## Local validation

Environment: CPython 3.12.3, pytest 9.1.1, plugin autoload disabled; existing
Node runtime for repository JavaScript harness tests. The image generators
used CPython 3.14 with Pillow 12.1.1 and local DejaVu fonts. These are the
available local tools, not the repository's hash-locked CPython 3.11 CI profile.

The focused selection passed **203 tests and 24 subtests**:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -o addopts='' --capture=sys -q \
  tests/test_wiki_sync.py tests/test_documentation_currentness.py \
  tests/test_detector.py tests/test_detector_evidence.py tests/test_validation.py \
  tests/test_recovery_readiness.py tests/test_ai_doctor_consent.py \
  tests/test_dashboard_findings_ui.py tests/test_qwen_zero_effect.py
```

The pure external-backup-evidence selection passed **60 tests**, with **15
deselected** private-filesystem cases:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -o addopts='' --capture=sys -q \
  tests/test_backup_evidence.py \
  -k 'not fixed_private_reads and not unsafe_files and not missing_files and not changed_trust and not changes_during_read'
```

The same 15 cases had already failed at fixture setup on unchanged source:
their fixture creates private directories under the home directory, which is
read-only in this sandbox. No filesystem guard or fixture was weakened. An
initial documentation check also failed because the reconstructed snapshot did
not yet have Git metadata; initializing its disposable local Git repository
allowed the existing ignore-pattern assertion to run. The subsequent baseline
selection passed 170 tests and 24 subtests before prose edits.

These scoped passes total **263 tests and 24 subtests**. They are not a full
repository-suite result. No real sensor, model, capture, service, firewall,
backup or restore was operated. JavaScript harness passes do not constitute
real-browser application acceptance.

The local Markdown check accounted for **174 documents** and resolved **1,084
file/heading targets**, including HTML image sources and the new journey links,
with no missing local target. It does not crawl external URLs. Wiki projection
validation prepared **16 files** successfully without publication. Both new
generator modules compiled. Asset hashes, 61-frame dimensions, absent loop
extensions, 4,800 ms play durations and the 1 MiB limits were checked.

## Visual interpretation

`workspace-reel` proportionally composes both original historical synthetic
PR #654 stills. Its moving trace is outside the screenshots. It does not fake
application interaction. `signal-path` is an explanatory schematic of the
metadata core, with default rule thresholds taken from source. Motion is not
a route, timing or throughput measurement.

Both new GIFs have 61 frames, one 4.8-second play, no loop extension and a
final still. Both are below 1 MiB and have explicit PNG alternatives. Labels
remain visible; text/table equivalents carry the meaning. The still compositions
were opened and visually inspected; timing, dimensions, hashes and finite-loop
metadata were checked programmatically. Exact reproduction may depend on
Pillow/font versions. See [asset provenance](../assets/docs/README.md).

The native Wiki remains a projection of `docs/wiki/`. Its existing workflow
publishes after review and merge. This candidate does not manually push the
Wiki or bypass the repository's explicit PR-numbered owner merge decision.
Source, candidate CI, human review, merge and public Wiki publication remain
separate observations.
