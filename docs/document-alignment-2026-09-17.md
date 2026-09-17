# Repository and document alignment — 2026-09-17

## Observed repository baseline

The GitHub `main` branch and clean local project initially matched
[`77f082a0548e64f97090c94dd11503a68ca05d99`](https://github.com/bartytime4life/MEGALODON/commit/77f082a0548e64f97090c94dd11503a68ca05d99).
This is a dated reconciliation, not a floating claim that later remote changes
have been copied locally. GitHub source and merge readbacks determine delivery;
Drive plans and handoffs supply coordination context.

| Work | Verified delivery at this baseline | Remaining boundary |
| --- | --- | --- |
| Reference Library recovery | PR #91 merged as `1b16069e430b539f9677c616a5f61c597fd0bec2` | Pinned registration context, not threat intelligence or live service identification |
| HUD and companion controls | PR #245 merged | Presence checks and copy-only guidance do not operate companions or connect feeds |
| Offline threat context | PR #269 merged as `ec2603452bde5c635aa2a43fdc5ff46d0aec39f7` | Bounded completed-file STIX reader only; no feed, persistence, pattern execution, detection or action |
| Currentness schema | PR #270 merged as `2e5099fcec2d1a08007efab70b4607cd5ba652ac` | Issue #254 remains open; selected-field validation is not maintainer acceptance |
| SQLite recovery | PR #271 merged as `77f082a0548e64f97090c94dd11503a68ca05d99` | Contract, fixtures and runbook only; no runtime backup/restore command; #256 remains open |

Eight issues (#254–#261), zero open PRs, and zero releases were observed before
this alignment branch was published. This is an ordinary API readback, not a
new validated capture from `tools/repository_currentness.py`. The older
`2e5099f` currentness receipt retains its original commit and observation window.

All four checks at `77f082a` succeeded: `test`, `wheel-smoke`,
`browser-acceptance`, and `Analyze Python source`. The corresponding successful
workflows are [CI 35253173546](https://github.com/bartytime4life/MEGALODON/actions/runs/35253173546),
[Linux browser acceptance 35253173435](https://github.com/bartytime4life/MEGALODON/actions/runs/35253173435),
and [CodeQL 35253173398](https://github.com/bartytime4life/MEGALODON/actions/runs/35253173398).
These receipts apply to that baseline, not automatically to this documentation
change or a future merge.

## Reconciliation decisions

- Refresh README, contributor guidance, the security register, integration and
  recovery documents, roadmap and Wiki source to distinguish merged delivery
  from proposed runtime work.
- Correct active references to #3 and #68. #3 is closed `not_planned` and
  records the owner-directed review workflow; it does not enforce an independent
  human approval floor. #68 is closed `completed` for bounded resource controls;
  operator retention choices and native sustained-capacity evidence remain open
  obligations. Historical receipts keep their original facts and dates.
- Review the existing Drive coordination log, command-center blueprint,
  platform roadmap, project instructions, and recent recovery, currentness,
  exchange, and lifecycle handoffs. Their pre-merge statuses are superseded by
  the GitHub readbacks above. Private document bodies are not copied into the
  public repository. Proposed designs remain proposals.
- Preserve pinned dependency constraints, reference-data snapshots, schemas,
  synthetic fixtures and recorded test environments. A document refresh does
  not authorize replacing those reviewed inputs with unqualified newer data.
- Refresh the repository Site reader label and README. Version 17 remains the
  last recorded hosted deployment; this source change was not deployed. Current
  whole-source parity is unverified. Preserve its historical thirteen-file
  receipt and distinguish local Python, repository Site source, published Wiki,
  and hosted Site lifecycle.

## Local verification and synchronization

The requested local project is the repository checkout itself. The reconciled
branch therefore contains the complete tracked repository state locally; no
second copy or destructive directory replacement is required. Existing ignored
virtual environments and runtime-only paths are preserved. No database backup,
restore, sensor operation, model invocation, package upgrade, or Site deployment
is part of this synchronization.

Validation on Linux / CPython 3.12.3 / pytest 8.4.2 / Node 22.13.1:

- Python suite: **2,409 passed, 1 skipped**. The skip is the explicitly enabled
  installed-TShark lane. Plugin autoload and ambient pytest plugin/argument
  overrides were disabled.
- Site suites: **38 passed** (33 readiness/exchange and 5 controls cases).
- Python compilation, JavaScript syntax, repository hygiene, deterministic
  build-input inventory, nine-file generated Wiki validation, and diff
  whitespace checks passed.
- All **240 relative file links across 72 Markdown files** resolved locally.
  This does not certify external website availability or Markdown anchors.

An initial sandboxed Python run was blocked by socket and private-file fixture
restrictions. The normal-host run exposed one stale documentation phrase
assertion; after correcting the wording, the complete suite passed as above.
A draft PR preserves the explicit owner merge decision; the local branch is
not represented as a new `main` merge.

The next work remains maintainer disposition for currentness/recovery, the
owner's license choice, a separately reviewed recovery implementation, and
producer/detector/release evidence. None is implied complete by document alignment.
