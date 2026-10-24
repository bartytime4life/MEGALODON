# Live Connections design QA

Target: selected radial connection-lens direction, implemented in the existing
Live network workspace.

## Passed remotely

- Source-derived DOM has unique IDs and preserves the Live workspace ownership.
- Connection lens renders from the validated operations payload and selects the
  same endpoint inspector used by the roster.
- Evidence-state filters, broad metadata search, and pause/resume behavior are
  covered by inert browser-DOM and Python tests.
- Identity remains provenance-qualified; unknown is distinct from a finding.
- Enrichment is passive only: no DNS, WHOIS, reputation, service probing,
  payload inspection, or credential collection was added.
- Responsive rules keep controls touch-sized and collapse the lens, roster, and
  inspector into one column on narrow or coarse-pointer viewports.
- All added content uses text nodes, bounded arrays, existing validation, and
  reduced-motion behavior.

## Blocked in this environment

- Pixel-level desktop and mobile screenshots could not be captured because the
  remote browser bridge rejected its loopback preview, and no local browser
  executable was available. This is recorded as unavailable, not passed.
- Real sensor coverage and installed-PC interaction evidence require the target
  computer and remain a separate acceptance gate.

## Installed-PC acceptance gate

1. Open the local HUD on port 8797 with reviewed telemetry.
2. Compare the lens, roster, and sticky inspector at desktop and phone widths.
3. Exercise All, Observed, Needs review, Unknown, search, Pause view, node
   selection, and roster selection.
4. Confirm labels do not overlap, focus remains visible, and the page has no
   horizontal overflow.
5. Capture screenshots and record source coverage before approving the exact
   pull-request head.
