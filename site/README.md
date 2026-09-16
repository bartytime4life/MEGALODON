# MEGALODON Defense Console source

The existing private [Defense Console](https://megalodon-defense-console.blackbart-55.chatgpt.site) is a hosted reference console. It is separate from the local Python dashboard. Its project identity is preserved in `.openai/hosting.json`.

## Quick-start controls

The first view leads with `python -m megalodon hud`, a direct link to the local
HUD and tool search. The command requires installation of the HUD update. It
opens a local workspace before data exists, includes startup presence checks,
and does not create sample evidence or start a sensor. Disconnected hosted
measurements are collapsed under an explicit status disclosure.

Local and hosted tool controls share the canonical Python asset constants in
`megalodon/dashboard_tool_assets.py`. The repository's
`scripts/sync-hud-assets.py` regenerates `controls.js`, `controls.css`,
`lifecycle.js` and `readiness.js`; parity is tested. Fourteen fixed tools support
official setup links and copy-only maintenance commands. Optional saved console
addresses persist per browser origin; they open the actual companion app in a
separate tab. No embedding, probing, credential storage or host execution occurs.
Tool search includes local evidence paths and saved-console filters. Manual
presence-report import remains optional for this hosted page.

## Actual behavior

- No network feed is connected. The HUD shows unavailable measurements, not zeros, generated rates, detections, protocol shares or example receipts. Workflows points to the local dashboard for actual stored evidence; this does not start a sensor or establish liveness.
- Fourteen integration cards distinguish repository implementation status, timestamped **self-reported** installation notes, and imported executable-presence findings. No card automatically verifies installation or service health.
- Manual notes persist in this browser's `localStorage`, expire after seven days, and can be cleared. A readiness JSON import stays only in page memory and is never uploaded or saved to `localStorage`.
- Readiness import accepts only the closed `megalodon-tool-readiness-v1` schema, fixed registry/boundaries and at most 8,192 UTF-8 bytes. Duplicate keys, unsupported claims, malformed/future timestamps and overlapping reads fail closed. Reports older than 24 hours are marked stale; they are not authenticated.
- Lifecycle diagnostics and commands are reference text. The browser never executes them. Qwen operations use one explicit example model tag and literal local provider; the tag is mutable and not an approved digest. Zabbix requires one selected role. Greenbone labels distinguish image inventory, container removal and image refresh. Zeek/OSSEC/Nagios defer to the actual installation method instead of inventing universal package commands.
- Package commands can download dependencies or start services when an operator runs them. They do not bypass the repository's guarded setup or establish MEGALODON operational acceptance. No command was executed to test host changes.
- The local Suricata projection is an immutable startup snapshot, not this Site's feed. Client-side Qwen admission does not confine the separate model process. Linux reference support does not imply native Windows/macOS acceptance.

## Source and verification

Implementation baseline: `73d2a2e36ed4e110b7ecbdc138359ebc9b06c23c` (merged PR #244), with the HUD update on `agent/intuitive-hud-20260916`. Readiness and the optional local Suricata view were delivered by PRs #241 and #239. The source owns `dist/`, this README, the hosting manifest and `tests/*.test.cjs`; README/tests stay outside the deployed archive.

Run `node --check dist/app.js`, `node --check dist/lifecycle.js`, `node --check dist/readiness.js` and `node --test --test-reporter=tap tests/*.test.cjs`. The current Site suites have 37 checks for the actual parser, lifecycle semantics, empty telemetry and application initialization/navigation. The DOM stub is not rendered-browser acceptance. The Python repository also tests real CLI-to-parser interoperability.

The managed preview service has no compatible server for this plain-static Site. No current visual walkthrough is claimed. Deployment, matching source bytes, tests, native producer acceptance and human review are distinct evidence.

See the GitHub mirror's `docs/site-source-alignment.md` for the deployed source/version/rollback receipt and `docs/evidence-alignment-review.md` for corrected claims.
