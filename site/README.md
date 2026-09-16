# MEGALODON Defense Console

This repository is the deployment source for the private MEGALODON Defense Console at https://megalodon-defense-console.blackbart-55.chatgpt.site.

The Site is a static, browser-only interface prototype. It has no backend, connector, host probe, packet intake, database access, installer, service control, model call, firewall path, or write API. Synthetic preview values are labeled and must not be interpreted as observations from a user's network. An optional user-selected readiness JSON report is validated and displayed in page memory only; it is never uploaded or persisted.

## Source alignment

- Site project: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3`
- Public project repository: https://github.com/bartytime4life/MEGALODON
- Repository baseline represented by this revision: `main@5583ac1d7f465757a0375d64cf1c18ee7c47ade9`
- Public mirror path: `site/`
- Deployable static assets: `dist/`
- Brand asset: `assets/megalodon-github-hero-compact.png` from the repository README

The MEGALODON repository root remains authoritative for product behavior, security contracts, tests, and implementation status. This Site summarizes those contracts for human review; it does not expand runtime authority.

The Suricata surface reflects both the accepted durable-consumer capacity gate and the explicit commit-unknown reconciliation contract. The single atomic writer still checks a fixed consumer-owned logical 512 MiB ceiling before runtime writes. The separate reader pins the existing database with `O_RDONLY`, holds a Linux OFD read lock across SQLite's complete locking-byte region, refuses persistent WAL state and coordination sidecars, queries in read-only/query-only mode, and returns only `committed`, `not_committed`, or conservative `indeterminate` evidence for the exact publication and attempt identity. Neither path repairs permissions, migrates schema, deletes retained evidence, starts a producer, blocks traffic, attributes an action, or executes a response. Separately, merged PR #239 adds an optional `dashboard --suricata-db` read-only startup projection: up to five recent validated publications, at most 50 alerts, and 64 KiB output within a cooperative five-second deadline. HTTP requests use immutable startup bytes, with no per-request database access. The shared 30-second deadline is cooperative, not a process-termination or filesystem-stall SLA.

## Evidence and readiness surfaces

- The Evidence desk links bundled synthetic records to five illustrative run states: complete, incomplete, and commit unknown. These are display examples, not runtime receipts or production acceptance evidence. Retained counts are kept separate by packet, flow, alert, and detection units.
- The activity window filters actual bounded demo records and changes chart sample spacing. Source, text, and disposition filters apply to the event table. An empty result never implies network safety. The ring buffer holds at most 128 synthetic rows, no older than 15 demo minutes.
- Readiness import accepts only `megalodon-tool-readiness-v1`, `path_presence_only`, the exact 14-entry tool registry and fixed boundary text, at most 8 KiB UTF-8. Duplicate keys, unknown fields/statuses, excessive nesting, invalid/future dates, and unsupported probe claims fail closed. Rejected or superseded imports clear prior results. The Site does not authenticate the report or verify its claims.
- Imported findings say `Executable found`, `Not found on checked PATH`, or `Not checked`. A report over 24 hours old is visibly stale. Ollama presence never proves a Qwen model is installed. This report is separate from browser-local manual notes, which are explicitly self-reported, timestamped, and marked for recheck after seven days. Untimestamped v1 notes are not promoted.
- Every integration card also exposes an explicit browser-local installation state: `Installed · self-reported`, `Not installed · self-reported`, `Recheck required`, or `Not checked`. Its inspector provides copy-only verify, uninstall, and reinstall reference commands for all 14 integrations. The Site never executes those commands; package-manager, model, container, and source-install variants require operator confirmation before use.
- Motion preference pauses the demo initially; inactive/hidden views do not advance it. Record inspection and run navigation remain available without animation. Clipboard failure is shown honestly.

## Validation

Before publishing, verify JavaScript syntax, local asset references, the hosting manifest, the displayed repository pin, and the absence of executable install or host-control paths. A Site version and a public GitHub mirror are separate delivery records and must identify the same files when parity is claimed.

This revision passed `node --check dist/app.js`, `node --check dist/readiness.js`, and all 25 dependency-free checks in `node --test tests/readiness.test.cjs`, including duplicate keys, timestamps, forged claims, input bounds, overlapping reads, and HTML asset/control references. Independent review reproduced the real Python CLI-to-JavaScript schema path and additional negative cases. Local browser interaction and visual acceptance remain unproved: Chromium download timed out and Cloud Browser policy refused local preview URLs. Tests and this README are excluded from the deployment archive.

The readiness CLI was delivered by merged [PR #241](https://github.com/bartytime4life/MEGALODON/pull/241) at `5583ac1d7f465757a0375d64cf1c18ee7c47ade9`. Run `python -m megalodon readiness > megalodon-readiness.json` for the bounded presence-only report. The optional local Suricata projection was delivered by [PR #239](https://github.com/bartytime4life/MEGALODON/pull/239). The hosted Site remains a synthetic static interface with no connection to the local dashboard or Suricata store. This revision adds explicit installation-state labels and copy-only lifecycle commands while preserving the no-host-access boundary.
