# Repository and application review — November 17, 2026

Source basis: merged `main@dee4027a8541335f43460d6bef37024606f4bfdf`, tree
`481694b9000db76d9fc66197d89c3429c67b1744`. This follows host protection #780 and
the Playwright 1.65.2 repair #779. Changes below are candidate source until their
own PR merges; an installed PC and published Wiki require separate readback.

## Discovery, fixes and second pass

| Finding | Result | Verification |
| --- | --- | --- |
| Protection buttons appeared available during a status read, while the action handler silently rejected clicks | Disable actions during the read and restore them afterward | Inert DOM/HTTP-promise test; existing protection journey remains in browser CI |
| Protection status continued polling in a hidden document | Pause status timers while hidden and perform a fresh read on return | Synthetic visibility and GET-only assertions; no visibility event grants apply authority |
| Failed security-library status retained action readiness and current-looking counts | Clear current authority, storage/learning claims and stale reference results; require a successful status pair before maintenance can resume | Failure/recovery test, including a late search response and attempted stale-token action |
| Second pass: incomplete HTTP-successful status data threw during rendering and interrupted polling | Treat render/parse failure as unavailable, clear authority and recover after a valid status pair | Both endpoint failures reproduced before repair; stale searches/actions remain refused and recovery continues |
| Second pass: visibility changes could overlap the active security-library status pair | Admit one pair at a time and visibly disable maintenance while refreshing | Delayed reads and repeated foreground events produce only one pair |
| Static repository audit misclassified twelve generated app-card anchors as broken | Classify only the shipped closed constructor's known targets; retain unknown-link failures | Current browser navigation plus positive and missing-constructor negative checks |
| Help did not connect the new PC protection controls or offer an interactive science explanation | Add task links, offline metric examples, uncertainty explanations and defensive lessons | Exact-ratio and independent score-test oracle; browser keyboard, navigation and phone checks |
| Pattern comparison chose the last imported copy when the same historical hour disagreed | Exclude conflicting copies, collapse identical copies and retain a diagnostic; preserve source separation and the 24-hour minimum | Replay permutations, eligibility/count/dependency conflicts and restoration with an additional unambiguous hour |
| Cadence review showed a typical interval without explaining its tolerance | Show measured spread, lower-median ratio and fixed 5% basis, with missing-start/jitter limitations | Exact boundary and inconsistent-facts UI checks; no action requests |
| Maintained entry pages still led with older source orientation and browser qualification | Reconcile current guides, catalog and Wiki source; preserve dated receipts and their original pins | Repository link/syntax inventory, catalog coverage, Wiki projection and package checks |

The initial focused run caught the old assertion that Help contains no buttons.
Help now has three strictly local example buttons; its test permits only those
non-submit controls inside the lab. Host workflow actions remain on their
existing protected surfaces. The invalid test assumption was updated explicitly,
with separate checks that the lab has no fetch, storage, timer or action path.

## Coverage and evidence limits

The repository inventory reads tracked and non-ignored files plus retained paths
from its historical baseline, parses Python/JSON/TOML and checks shell/JavaScript
syntax and relative Markdown links. It inventories controls and duplicate/static
anchors. Generated app-card references are separately identified from literal
HTML IDs. This is not an independent line-by-line security audit or proof of
runtime behavior for every control. Historical ledgers are not overwritten.

The local product audit used the assembled HUD in the in-app browser, with
synthetic unavailable APIs and all action endpoints inert. It inspected Help,
app-card navigation, worked examples, invalid-count recovery, 390/320-pixel
layout, lesson links and keyboard-focus destinations. Screenshots and receipts
remain outside the public source tree. One initial phone capture showed the
Help entry rather than the lab and was rejected; the accepted capture follows
explicit task navigation. No real telemetry or private screenshot was committed.

Daybreak's current authorized canonical query returned zero open findings for
this repository; that is not a completed repository scan. Codex Security's
advisory TAC readback was `not_granted`, which did not gate local inspection.
The literature/standards review used SciSpace, TinyFish and primary NIST,
MITRE and RFC sources. Drive's older project instructions were coordination
context, not a replacement for the current GitHub source.

Full-suite, package and hosted results belong to the exact final PR head and
are recorded in its review description and local validation receipt. The
source guide [Security science in Help](security-science-lab.md) defines the
formulas, inputs, assumptions and regression commands. No test result is a
field false-positive rate, independent security clearance or host acceptance.

The open Stage 0, model-library acceptance and exact native producer tasks retain
their own contracts. This review neither closes those issues nor removes the
UNBOUND model fence. No installed application, capture service, live firewall,
network configuration, repository protection, release or deployment is changed.
