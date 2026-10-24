# Connection lens acceptance — October 24, 2026

PR #686 was merged as `c1e72933d3149b64010f446eba3e24bd46099129` before
this acceptance pass began. This follow-up starts at main `6d85147` and keeps
installed-PC sensor qualification separate from synthetic interface acceptance.

## Demonstrated defects and corrections

- Retained third-party traffic previously acquired lines to **This device**.
  `Operations.snapshot()` now counts only flows with exactly one local endpoint
  as local relationships. The lens draws device links only with that explicit
  evidence. Missing relationship metadata leaves the node unlinked; the roster
  and inspector remain available. Local exit anchors retain their separate role.
- The interactive SVG was hidden from assistive technology. It now exposes a
  named group, individually named endpoint buttons, evidence state, relationship
  qualification, and the inspector relationship. Refresh preserves keyboard
  focus, and keyboard focus has a visible node outline.
- Pause previously admitted an already pending response. Pause now invalidates
  that response and suppresses manual/scheduled operations refresh until resume.
  This freezes this view only; it does not stop sensors or other status views.
- Geographic labels no longer stand in for an unobserved host identity. Search
  includes location labels and provenance without inferring identity or safety.
- Selecting a node or roster row focuses the inspector with native scrolling,
  so a phone layout can bring the updated inspector into view.

## Evidence collected locally

The source-derived inert DOM tests exercise Enter/Space selection, the shared
inspector, focus restoration after polling, all four evidence filters, address/
name/protocol/port/finding/location/source searches, no matches, pause during an
in-flight request, resume, failure qualification, and absent/invalid relationship
counts. They assert that this journey sends no action POST. Backend tests cover
third-party, local-to-remote, remote-to-local, and local-to-local flows.

These tests are behavioral regression evidence, not pixel or human screen-reader
acceptance. No capture, probing, AI, containment, credentials, or installed-PC
operation was performed.

## Native browser evidence

The cloud browser rejected both attempted synthetic preview URLs (client block
and HTTP response failure). No screenshot or visual acceptance is claimed for
that browser. Existing preview files and another in-progress checkout were left
unchanged; this work uses an isolated Git worktree.

The existing Linux browser acceptance workflow now includes
`tests/browser_connection_lens.py`. It uses the shipped dashboard, the existing
sandboxed Chrome driver, documentation-address fixtures, reduced motion, local
GETs, and one disposable-dashboard sign-in. Host-action requests and nonlocal
requests are refused by the fixture handler. It covers:

1. Accessible endpoint names and evidence-supported device links.
2. Native Tab/Enter/Space selection and inspector updates.
3. Focus retention through a real scheduled refresh.
4. Evidence filters, broad searches, empty results, and anchor qualification.
5. Pause during an in-flight refresh, then resume to a changed snapshot.
6. Desktop 1440×1000 and phone-sized 390×844 / 320×740 reflow and scrolling.
7. OS/browser reduced-motion preference and static lens/globe state.
8. Dense 24-endpoint desktop/phone screenshots and failed-refresh wording.

The workflow uploads `artifacts/connection-lens/`, including PNG viewports and a
manifest with browser version, candidate identity, dimensions, hashes, scenarios,
and limits. A script being present is not a passed run. Workflow results and
visual inspection of those exact artifacts must be recorded before calling the
synthetic graphical gate accepted.

## Screenshot-driven corrections

The first successful native run was `40137521277`, candidate `9f0a2f9`,
synthetic merge commit `fb7f5440626bde02675ba7ddbc3731fa53d563f1`.
It passed the browser journey and produced eight real PNGs. Visual inspection
found unreadably scaled phone labels and overlapping dense labels despite the
passing reflow checks. That visual gate was rejected.

The correction gives compact screens at most six nodes in a full-size SVG
coordinate system with 46px circle targets and separate, readable label slots.
The searchable roster retains every endpoint. Desktop dense labels use separate
columns with leader lines. Full identity/provenance remains available through
accessible names and the inspector; abbreviated visible names are not new
identities. Browser regression checks now measure label intersections, compact
hit targets, bounded display counts, and preservation of the full roster.
Screenshots capture complete panel headers rather than starting at the title.

The earlier full local run collected 6,420 tests and reported 42 failures. All
42 failed cases reproduced on unchanged base `6d85147`; no whole-suite pass is
claimed. The independent review of `9f0a2f9` completed with no findings. The
visual correction needs its own exact-candidate run and review.

## Remaining acceptance gates

- Read the exact-candidate CI results and independently review the follow-up diff.
- Inspect the generated desktop/phone PNGs, including dense-label legibility,
  touch targets, clipping, and scroll behavior. Fix any demonstrated defect.
- Human screen-reader, actual phone hardware, native browser zoom, and
  installed-PC sensor coverage remain distinct checks. No complete accessibility
  compliance, location precision, complete network visibility, or malicious
  classification is inferred from synthetic acceptance.
