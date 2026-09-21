# Operator Guide

The HUD is for reading bounded local evidence. It is not a sensor controller,
host-management console, incident verdict, or proof that an external tool is
healthy.

## Start and stop

For the desktop installation, open **MEGALODON** from the application menu or
run `~/.local/bin/megalodon-hud`. From a checkout, use
`./scripts/start-local.sh`; its optional `--check` preflight is useful when the
HUD cannot start. An ordinary installed environment can run
`python -m megalodon hud`. Use <http://127.0.0.1:8787/> on the same computer.
The process stays in the foreground; stop it with Ctrl+C. Do not expose it
through a remote bind, reverse proxy, tunnel, or port forward.

On Home → **Data and tools**, use **Change data for the next launch** to prepare a quoted restart
command for a settings file, completed offline run, or Suricata store. The form
does not browse, open, or validate an arbitrary path. Restarting is required to
take new startup snapshots.

Use **Check this computer** to refresh tool observations and check the runtime
and selected store without restarting. Download buttons open publisher pages;
the software list groups essentials and optional workflows. Follow the
[visual quick start](../gui-quick-start.md) for a click-by-click tour. The optional
terminal preflight `./scripts/start-local.sh --check` helps when startup fails.

## Read the seven workspaces

| Workspace | Use it for | Do not infer |
| --- | --- | --- |
| Home | Evidence availability, coverage, shared UTC range, headline counts, and common next actions | Whole-network visibility, sensor continuity, or an incident verdict |
| Traffic | Qualified stored metadata linked to non-sample ingestion runs | Payload content, wire speed, or complete traffic history |
| Findings | Fixed detector results linked to the qualified event set | Malware attribution, uniqueness, or authorization to respond |
| Apps | Static 14-tool guidance, startup executable/process observations, saved console links, and copy-only commands | Installation integrity, supported compatibility, service health, or connected data |
| Reports | Preview and download one bounded local JSON report for the selected range | Server-side persistence, complete case evidence, or a compliance report |
| Evidence | Separate audit, offline, Suricata, reference, ingestion, and optional Qwen projections | That the sources share one transactional snapshot or live connection |
| Help | Status vocabulary and safe next steps | Operational acceptance |

## Time range, paging, and qualification

Traffic defaults to the newest bounded view. Choose **Last hour**, **Today
(UTC)**, or a custom UTC interval of at most 31 days. History uses pages of at
most 500 candidates; a page can contain only excluded records. Findings are
capped at 200 rows per page. Retention or concurrent ingestion can change a page
when it is read again.

Sample, unlinked, and unqualified records are excluded from the primary Traffic
and Findings views. An imported JSONL provenance statement remains
operator-supplied rather than independently attested. Always record the selected
range, fetch time, source/run identity, exclusions, and row bounds when handing
off evidence.

## Apps and companion consoles

**Executable found**, **Process observed**, **Supported**, and **Connected** are
different claims. Startup checks do not execute a tool, probe a version, test a
service, or prove data flow.

A saved HTTP(S) console address stays in this browser origin. Do not include
credentials in it. **View in HUD** opens the explicitly selected address in a
sandboxed frame; some applications will require **Open outside HUD** because
they refuse embedding or need external sign-in. The companion application keeps
its own network access, authentication, and action permissions. Viewing its UI
does not connect its telemetry to MEGALODON.

## Reports

Reports use the currently selected range and already accepted local projections.
Preview the exact JSON before downloading it. The browser does not POST evidence,
write the database, invoke an analyzer, or create a server-side report. A report
describes bounded stored metadata; it does not prove capture completeness,
service health, incident state, or remediation.

## Separate evidence sources

- **Reference Library:** verified bundled IANA registration context, never a service or threat verdict.
- **Offline snapshot:** one explicitly selected completed report loaded at startup, not a live analyzer.
- **Suricata evidence:** one bounded startup snapshot from a separate durable store, not a live sensor or MEGALODON finding.
- **Qwen receipt:** one optional validated startup-supplied result, not a dashboard invocation or evidence source.
- **Ingestion receipts:** bounded run outcomes, not proof that a source was complete beyond its own receipt.

Unavailable and empty are intentionally distinct. A failed refresh may preserve
an older view as stale; do not silently treat it as current.

Use the full [operator and acceptance runbook](../dashboard-operations.md) for
storage admission, troubleshooting, browser checks, and exact API semantics.
