# Practical project improvements — November 9, 2026

Source baseline inspected: local checkout
`a0db1cc2384d076b418dedd1a254dde3cf27a9b5`.
This is a source-based improvement plan, not an installed-PC, release or
operational detection assessment. Dates and check receipts in older documents
keep their original scope.

The immediate product goal is to help a Linux user finish a local inspection or
finding review, understand what the evidence supports, and recover from a
blocked step. New integrations and promotional assets follow those journeys.

## Now

| Outcome | Current source evidence | Completion proof |
| --- | --- | --- |
| A user can follow protected-launch instructions without being sent to a second HUD that cannot own evidence | [Setup launch help](../megalodon/dashboard_setup.py), [exclusive store lease](../megalodon/evidence_storage.py), [file-inspection guide](file-inspection.md) | Clear foreground/background stop and relaunch steps; literal command-generation regression checks; isolated refusal of a second store owner and successful acquisition after the first closes |
| Completed inspection evidence survives a later adapter's isolation-setup refusal | [Sandbox adapter](../megalodon/file_inspection_sandbox.py), [inspection workflow](../megalodon/file_inspection.py), [inspection tests](../tests/test_file_inspection.py) | A synthetic identification-filter refusal retains completed structure and clues as partial coverage; setup-failure checks verify descriptor and seccomp-context cleanup |
| A current invalid file stays clearly distinguished from an earlier report after refresh | [Inspection presentation](../megalodon/dashboard_file_inspection.py), [workflow regressions](../tests/file_inspection_browser.cjs) | Oversized and empty selections retain their warning and disabled Inspect control; only a completed or partial report belonging to the current submission advances to Understand; desktop/mobile fixture checks retain the older report's scope label |
| Operator guides agree about relaunch ownership and dated snapshot-viewer evidence | [Quick start](gui-quick-start.md), [local setup](local-pc-setup.md), [overview](../README.md) | Current launch instructions explain ownership and collection interruption; historical publication records retain their dates and do not imply current hosted availability |

Prepared launch commands remain inert. Stopping an installed HUD interrupts its
in-process collection; separately managed companion services retain their own
lifecycle. The [handoff guide](local-pc-setup.md#optional-require-a-password-for-a-launch)
explains that the normal application launcher can start the background HUD
again. This pass does not operate that service or change saved settings.

## Next

| Outcome | Next practical proof |
| --- | --- |
| One complete inspection journey is demonstrated at a named revision | Exercise sign-in denial, command preparation, successful protected session, harmless executable fixture, partial coverage, cancellation and metadata export in a disposable environment. Component fixtures and native-runtime checks remain separately labeled. |
| One complete finding review is demonstrated at the same revision | Use saved synthetic evidence to select a finding, inspect original source/times, preserve missing measurements, save an assessment and verify a stale-context refusal. A local AI request remains a separate explicit choice. |
| Users can find the current task guides | Link the inspection journey from the field guide and documentation catalog; reconcile current operator instructions without rewriting historical source pins or hosted receipts. |
| Improvements have meaningful measures | Record completion/refusal outcomes and the step that blocked each named synthetic journey. Keep elapsed time, environment and fixture identity together. No adoption, accuracy or conversion rate is inferred without observations and a defined denominator. |

## Later

- Qualify representative privacy-reviewed executable formats and failure cases
  before expanding inspection coverage. Structural coverage is distinct from
  malware-detection precision or recall.
- Complete one exact producer or canonical model acceptance gate using its
  existing contract and retained evidence before broadening integrations.
- Refresh public tours or creative media after current application journeys
  have been captured and reviewed. Existing images are explicitly historical;
  new illustrations would not resolve launch ownership or evidence-state gaps.

## Validation for this pass

Final source validation: **7,478 passed, 27 skipped, 396 subtests passed**
in 249.64 seconds using Python 3.12.3. This applies to the working tree on
`codex/project-improvements-20261109`, based on the source baseline above.

The full suite ran with a private temporary directory and a capability-free
child process:

```bash
setpriv --inh-caps=-all --ambient-caps=-all .venv312/bin/python -m pytest --basetemp="$PRIVATE_TEST_ROOT"
```

`PRIVATE_TEST_ROOT` must name a fresh owner-private test directory. An initial
run inherited a nonzero Linux inheritable-capability flag and correctly failed
one capability-free acceptance gate (7,468 passed, 1 failed, 27 skipped).
That test passed when repeated without inherited capabilities, followed by the
successful full run above. The product's privilege gate was preserved.

JavaScript syntax checks, changed-document local link targets and
`git diff --check` also passed. These checks do not verify remote links.

Focused regression checks passed: backend inspection, isolation refusal and
cleanup (44 tests and 8 subtests); Setup, HUD launch and evidence storage
(142 tests); inspection presentation (2 tests, 1 opt-in Chrome skip).
These subsets overlap the full suite and are not additional totals.

The shipped inspection component was also exercised in the in-app Browser at
desktop and 390-pixel widths using synthetic responses. Empty/oversized file
warnings survived refresh, older reports stayed labeled and exportable, and a
new explicit synthetic submission advanced to Understand only for its own
report. Independent review checked three additional stale-refresh/submission/
cancellation interleavings. The temporary preview was stopped afterward.

Dedicated native-parser/kernel-confinement rehearsal and the opt-in Chrome
acceptance were not executed; the latter requires a local Playwright package
that is unavailable. Browser fixtures do not establish native analysis,
whole-HUD acceptance, detection accuracy or accessibility conformance.

The source preflight passed its bounded read-only checks. That preflight does
not acquire the managed evidence-store lease or prove a replacement HUD can
start. An isolated temporary-home ownership check separately refused a second
owner and admitted a replacement after the first closed. No installed service
was stopped or relaunched, no settings were changed, and no private downloaded
program was inspected for this record.

## GitHub publication revalidation

Before publication, the scoped change was transferred onto current
`main@9378307d6f787803c2821fdb26f3c0e168d7cf51` on
`codex/inspection-evidence-20261109`. The original tested branch and commit
were retained; the newer model-library and Stage 0 changes were preserved.

The complete source suite passed again on this publication candidate:
**7,690 passed, 27 skipped, 396 subtests passed** in 252.20 seconds, using the
same Python 3.12 interpreter, capability-free child process and a fresh private
temporary directory. Existing documentation/Wiki checks separately passed
36 tests. The six changed Markdown documents passed local-link and heading-
anchor checks; remote destinations were not checked. The catalog now links
both the inspection guide and this record without rewriting dated counts.

These are local source results. Hosted exact-head checks, owner review,
merge, installation and native analysis remain separate states. This record
does not authorize any of them.

## Follow-up: retained history and Setup focus

This separate source pass starts at
`main@d03bc43d13a9f030cfcff7eb8beaea5fc318abae` and is retained on
`codex/history-setup-reliability-20261109`. The original checkout at
`187ec95960f48e85c325e1211ad8b9bdd1f07d72` remains unchanged. Earlier results
above keep their original scope.

The history and Setup changes below are retained **runtime candidates**. This
documentation branch contains their dated review and validation record, not
their runtime implementation or a claim that either candidate has merged.

| Candidate correction | Demonstrated behavior in the retained combined candidate |
| --- | --- |
| Qualify compacted history counts | A conversation crossing the selected interval previously produced a partial marker without a coverage gap, allowing the HUD to display zero packets and the end of the retained range. The API now explains the missing interval allocation; the HUD shows **Unknown** or **At least** the represented totals. Fully contained observations and genuinely empty ranges retain exact counts. |
| Normalize compacted observation times | Compact rows inherited offset-bearing timestamps that the HUD's UTC timestamp validator refused. Every returned source now uses canonical UTC with a trailing `Z`. |
| Preserve focus after Setup checks | A delayed success or failure respects focus moved to another field or workspace. Software links and disclosure controls retain equivalent focus after their rows are replaced; filtered or collapsed targets recover at the visible search field. Hidden sections cannot reclaim focus. |
| Refresh source and contributor guidance | The README and current-state page identify the November 9 source, inspection/model preparation and the partial Stage 0 fence. Operational generation remains UNBOUND. Contributor instructions explain how to run capability-free test children without weakening the application gate. |

The runtime candidates are retained in `715b68e` (history) and `f541bd7` (Setup).
New history cases run real compacted API pages through the shipped HUD validator
and renderer: start/end crossings, exact interval boundaries, offset timestamps,
mixed lower bounds, contained totals and a genuinely empty range. Deferred
Setup tests cover success/failure, navigation, replaced links and disclosures,
filtered targets, and hidden/collapsed ancestors. Separate agent reviews found
no remaining concrete issue in these scoped final diffs; this is not independent
maintainer approval.

Final local source suite on the retained **combined history/Setup candidate**:
**7,736 passed, 27 skipped, 594 subtests passed** in 250.11 seconds on Python
3.12.3. This is not a test result for the documentation-only branch or a
separately rebased runtime PR. The command used a fresh private temporary
directory, disabled ambient pytest plugin loading, and removed inherited and
ambient capabilities from the test child:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS= PYTEST_ADDOPTS= \
  setpriv --inh-caps=-all --ambient-caps=-all "$TEST_PYTHON" \
  -m pytest -ra --basetemp="$PRIVATE_TEST_ROOT"
```

`TEST_PYTHON` names the prepared development interpreter; `PRIVATE_TEST_ROOT`
names a fresh owner-private directory. The initial baseline run correctly
refused one real capability-free triage test because this desktop session passed
an inheritable capability. The final run removes that capability only from the
test process; the product refusal is unchanged.

The skips retain the existing opt-in ClamAV, native socket, Chrome inspection,
native inspection, TShark and platform-specific path scopes. Node behavior tests
are not rendered-browser or human accessibility acceptance. No new hosted CI,
native-parser, real-model, installed-PC, release or publication result is claimed.
The retained worktree's read-only source preflight passed with
`data_not_configured`; it created no store and does not verify a running HUD.
The temporary synthetic browser preview was stopped. No installed HUD, saved
setting, model, capture or companion service was changed.
