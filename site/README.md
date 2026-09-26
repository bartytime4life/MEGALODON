# MEGALODON Defense Console source

The existing private [Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) is a hosted reference console. It is separate from the local Python dashboard. Its project identity is preserved in `.openai/hosting.json`.

The local dashboard's core telemetry routes are read-only. Its separately
enabled AI question POST requires a per-launch operator token and can write
private AI receipts and bounded report snapshots; see
[`docs/ai-control-plane.md`](https://github.com/bartytime4life/MEGALODON/blob/main/docs/ai-control-plane.md). This hosted Site has
no connection to those routes. The deployable files in `dist/` and the hosting
manifest match the MEGALODON repository at
`main@799dc984cadf23990fb074f252b4c53a4534e855`. Its local HUD wording
follows the operator-authorization change merged in PR #392. A saved Sites
version and deployment must be verified separately from this source commit.

## Current navigation and install path

The merged source adds view links such as `#view=integrations`, Back/Forward
navigation, and per-view reading positions for the current page session.
Reload restores the selected view; it does not retain reading positions or
imported reports. Navigation labels remain visible at desktop, tablet and
mobile widths; the first-run steps stack before their three columns become
cramped. Unknown
fragments are ignored, and navigation remains usable if history is unavailable.
The hosted install guide was published in Sites v29. See
`docs/site-source-alignment.md` in the parent repository for the exact current
publication receipt; later source edits require their own version and deployment.

The Home view also points to the local HUD's rolling-hour activity globe and
Actions workspace as implemented on repository `main@a767e69bcaf7ac0020e03b89578e6c76ec264560`.
The globe reads bounded stored metadata and uses optional offline, approximate
IP regions. The Actions workspace provides copy-only reviewed scripts and a
bounded recurrence preview; it creates no schedule or job and runs no command.
Those local features are not available through this hosted Site.

## Quick-start controls

The first view follows Review / Install / Open: from a reviewed repository root,
run `./scripts/install-local.sh`, open **MEGALODON** from the application menu,
and use Home → Data and tools → Check this computer. Python >=3.11 is required;
Linux is the reference platform. See
[`docs/local-pc-setup.md`](../docs/local-pc-setup.md) for preparation and
troubleshooting. The installer creates a private user application and stable
launchers, may obtain declared Python build requirements, and does not install
companion tools or create telemetry. The separate disclosure keeps
`./scripts/start-local.sh` available for a source-only launch.

The local HUD opens before data exists and performs startup presence checks;
Home → Data and tools contains those checks and next-launch options. Keep the
terminal open and stop with Ctrl+C. Neither the launcher nor the browser starts
sensors or creates sample evidence. The local link does not probe the PC.
Disconnected hosted measurements remain under an explicit status disclosure.
The status action opens the Site's evidence workflows; it does not run a local
workflow. An empty local HUD is labeled unavailable rather than zero traffic.

The local address points to the device opening the link; a phone cannot use it
to reach a Linux computer. Missing or sample-only evidence is not zero traffic.
The setup link targets the current Ubuntu guide. The brand returns to Home,
view changes focus their heading, and saved-console filters update immediately
when a bookmark changes.

Local and hosted tool controls share the canonical Python asset constants in
`megalodon/dashboard_tool_assets.py`. The repository's
`scripts/sync-hud-assets.py` regenerates `controls.js`, `controls.css`,
`lifecycle.js` and `readiness.js`; parity is tested. Fourteen fixed tools support
official setup links and copy-only maintenance commands. Optional saved console
addresses persist per browser origin; they open the actual companion app in a
separate tab. No embedding, probing, credential storage or host execution occurs.
Tool search includes local evidence paths and saved-console filters; an empty
result offers a filter reset. The integrations view links to a HUD already
running on the same computer, and supported evidence cards link to their
matching local view. Manual presence-report import remains optional for this
hosted page.

## Actual behavior

- No network feed is connected. The HUD shows unavailable measurements, not zeros, generated rates, detections, protocol shares or example receipts. Workflows points to the local dashboard for actual stored evidence; this does not start a sensor or establish liveness.
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

Run `node --check dist/app.js`, `node --check dist/lifecycle.js`, `node --check dist/readiness.js` and `node --test --test-reporter=tap tests/*.test.cjs`. The current Site suites cover the actual parser, lifecycle semantics, empty telemetry, detector-evidence and license labeling, navigation/focus, bookmark filter updates, and the user-install quick start. The DOM stub is not rendered-browser acceptance. The Python repository also tests real CLI-to-parser interoperability.

Local browser verification at desktop, tablet and mobile widths is recorded in
[`docs/local-pc-readiness-review.md`](../docs/local-pc-readiness-review.md).
It used a loopback static server and does not verify the currently hosted
publication. Deployment, matching source bytes, tests, native producer acceptance
and human review are distinct evidence.

See the GitHub mirror's `docs/site-source-alignment.md` for the deployed source/version/rollback receipt and `docs/evidence-alignment-review.md` for corrected claims.
