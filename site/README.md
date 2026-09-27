# MEGALODON Defense Console source

The existing private [Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) is a hosted reference console. It is separate from the local Python dashboard. Its project identity is preserved in `.openai/hosting.json`.

The local dashboard's core telemetry routes are read-only. Its separately
enabled AI question POST requires a per-launch operator token and can write
private AI receipts and bounded report snapshots; see
[`docs/ai-control-plane.md`](https://github.com/bartytime4life/MEGALODON/blob/main/docs/ai-control-plane.md). This hosted Site has
no connection to those routes. Its Activity view does not accept local activity
telemetry or `megalodon-hud-snapshot-v1` files; it shows one passive unavailable
boundary and a reference globe. The local HUD retains its bounded summary
preview and download workflow for private review. Source changes for the exporter
and uniform tool setup must be installed locally before those local controls are
available. The Site and local HUD share a generated feature/tool data-coverage
map; use `python scripts/sync-hud-assets.py` after changing that canonical source.

The saved osquery package-count panel accepts only a counts-only JSON produced
from one operator-run `deb_packages` count. It stays in the browser tab and
does not start osquery, upload package names, or establish live host health.
See [the workflow guide](../docs/hud-workflow.md). The current publication receipt
is recorded in [source alignment](../docs/site-source-alignment.md).

## Navigation and install path

The source has four views: Overview, Evidence desk, Tools & setup, and
Boundaries. It adds view links such as `#view=integrations`, Back/Forward
navigation, and per-view reading positions for the current page session.
Reload restores the selected view; it does not retain reading positions or
imported reports. Navigation labels remain visible at desktop, tablet and
mobile widths. Unknown fragments, including the retired `#view=missions`, are
ignored, and navigation remains usable if history is unavailable. Setup and
workflow actions open the current repository guides in protected new tabs rather
than maintaining a second command catalog in the hosted Site.
The hosted install guide was published in Sites v29. See
`docs/site-source-alignment.md` in the parent repository for the exact current
publication receipt; later source edits require their own version and deployment.

The local HUD includes a rolling-hour activity globe and Actions workspace as
implemented on repository `main@a767e69bcaf7ac0020e03b89578e6c76ec264560`.
The globe reads bounded stored metadata and uses optional offline, approximate
IP regions. The Actions workspace provides copy-only reviewed scripts and a
bounded recurrence preview; it creates no schedule or job and runs no command.
Those local features are not available through this hosted Site.

The hosted Home view now draws the same bundled public-domain Natural Earth
land mask as a geographic reference. West/East controls rotate the map locally.
Separate normal and danger/critical traffic bar tracks show an explicit
disconnected state here, with LOW/MEDIUM review signals listed separately.
No marker, timestamp, IP location, or event count is created. The normal lane
means no returned linked finding, not proven-safe traffic; the danger/critical
lane refers to HIGH/CRITICAL findings requiring review. Actual volume meters
and the interactive rolling-hour timeline use qualified stored data in the
local HUD. This hosted Site has no local telemetry connection or refresh loop.

## Direct setup and workflow guides

Overview links directly to the current
[`docs/local-pc-setup.md`](../docs/local-pc-setup.md) guide. The disconnected
traffic panel and Evidence desk link to
[`docs/operator-workflows.md`](../docs/operator-workflows.md), which indexes the
authoritative local dashboard, bounded JSONL replay, saved capture, Suricata
review, and integration-plan documents. Tools & setup routes its setup action
to the same local PC guide without trying to open a loopback app or per-tool
local evidence view. These links open the repository documentation in protected
new tabs; the Site does not execute or copy workflow commands.

The local HUD can open before data exists. Neither a launcher nor the browser
starts sensors or creates sample evidence, and an empty local HUD is labeled
unavailable rather than zero traffic. The hosted Site does not navigate to a
device loopback address. The brand returns to Overview, view changes focus
their heading, and saved-console filters update immediately when a bookmark
changes.

Local and hosted tool controls share the canonical Python asset constants in
`megalodon/dashboard_tool_assets.py`. The repository's
`scripts/sync-hud-assets.py` regenerates `controls.js`, `controls.css`,
`lifecycle.js` and `readiness.js`; parity is tested. Fourteen fixed tools support
official setup links and copy-only maintenance commands. Optional saved console
addresses persist per browser origin; they open the actual companion app in a
separate tab. No embedding, probing, credential storage or host execution occurs.
Tool search includes local evidence paths and saved-console filters; an empty
result offers a filter reset. The integrations view points to the documented
local setup entry point. Supported evidence cards state that their local views
remain separate without opening loopback URLs. Manual presence-report import
remains optional for this hosted page.

## Actual behavior

- No network feed is connected. The Activity view shows one passive unavailable boundary, not zeros, generated rates, detections, protocol shares or example receipts. Separate evidence imports retain their own controls; setup and workflow actions route to repository guides. None starts a sensor or establishes liveness.
- Fourteen integration cards show one presence light next to each name: a fresh manual note or imported executable-presence report sets it green or red, stale evidence sets it amber, and otherwise it stays grey. The imported report is an unauthenticated PATH claim, not proof of installation or service health. This hosted page cannot see the PC. The local HUD provides recent presence observations, visible unknown/stale states, setup guidance and, where implemented, separately authorized Install/Start controls (see `docs/tool-heartbeat.md`).
- Manual notes persist in this browser's `localStorage`, expire after seven days, and can be cleared. A readiness JSON import stays only in page memory and is never uploaded or saved to `localStorage`.
- Readiness import accepts only the closed `megalodon-tool-readiness-v1` schema, fixed registry/boundaries and at most 8,192 UTF-8 bytes. Duplicate keys, unsupported claims, malformed/future timestamps and overlapping reads fail closed. Reports older than 24 hours are marked stale; they are not authenticated.
- Lifecycle diagnostics and commands are reference text. The browser never executes them. Qwen operations use one explicit example model tag and literal local provider; the tag is mutable and not an approved digest. Zabbix requires one selected role. Greenbone labels distinguish image inventory, container removal and image refresh. Zeek/OSSEC/Nagios defer to the actual installation method instead of inventing universal package commands.
- Package commands can download dependencies or start services when an operator runs them. They do not bypass the repository's guarded setup or establish MEGALODON operational acceptance. No command was executed to test host changes.
- The local Suricata projection is an immutable startup snapshot, not this Site's feed. Client-side Qwen admission does not confine the separate model process. Linux reference support does not imply native Windows/macOS acceptance.
- The exchange map now distinguishes the bounded offline STIX reader delivered by merged PR #269 from the implemented bounded local ECS/OCSF writer and the still-contract-only SOAR lane. This hosted page cannot select or upload a bundle and has no threat-feed, TAXII, SIEM, or SOAR runtime connection.

## Source and verification

Repository license checkpoint: merged PR #298 is now `main@a0b140093ca17ea64fbfe0354966379a3d5fc7ce`, tree `69aac8e40c0dad550304f52777934d30296d7b59`, and records the owner's Apache-2.0 selection with aligned package metadata. Exact-head CI, Linux browser acceptance and CodeQL passed, the merged tree matches the tested candidate, and issue #255 is closed completed. No package, tag or release was published.

Historical alignment baseline: merged PR #307 at `main@f3bf5d6a08c64363651e17fae07ff2e88386c0c0` delivered the source launcher. Merged PR #323 at `main@16742fed020283aafad35e30238986c851d7542a` added the user-scoped installer and guided readiness; its Site guide was published in v29. See `docs/document-alignment-2026-09-20.md` in the repository for the older baseline and validation receipt. Installation and Site publication remain separate from a software release and operator acceptance. PR #294 delivered the closed detector registry and bounded synthetic evidence report; this Site presents that repository capability without representing it as runtime telemetry or operational accuracy. PR #269 delivered the bounded threat-context reader and exchange map; PRs #274, #276, #277 and #278 delivered the separate local traffic projection, anchored HUD, capability-state matrix and browser-local report flow. The hosted Site remains disconnected from those local runtime APIs. Readiness and the optional local Suricata view were delivered by PRs #241 and #239. The source owns `dist/`, this README, the hosting manifest and `tests/*.test.cjs`; README/tests stay outside the deployed archive. Deployment and source parity require their own receipt and do not establish runtime or independent acceptance.

Run `node --check dist/app.js`, `node --check dist/lifecycle.js`, `node --check dist/readiness.js` and `node --test --test-reporter=tap tests/*.test.cjs`. The current Site suites cover the actual parser, lifecycle semantics, empty telemetry, detector-evidence and license labeling, four-view navigation/focus, bookmark filter updates, and direct documentation routing. The DOM stub is not rendered-browser acceptance. The Python repository also tests real CLI-to-parser interoperability.

Local browser verification at desktop, tablet and mobile widths is recorded in
[`docs/local-pc-readiness-review.md`](../docs/local-pc-readiness-review.md).
It used a loopback static server and does not verify the currently hosted
publication. Deployment, matching source bytes, tests, native producer acceptance
and human review are distinct evidence.

See the GitHub mirror's `docs/site-source-alignment.md` for the deployed source/version/rollback receipt and `docs/evidence-alignment-review.md` for corrected claims.
