# MEGALODON Defense Console

This repository is the deployment source for the private MEGALODON Defense Console at https://megalodon-defense-console.blackbart-55.chatgpt.site.

The Site is a static, browser-only interface prototype. It has no backend, connector, host probe, packet intake, database access, installer, service control, model call, firewall path, or write API. Synthetic preview values are labeled and must not be interpreted as observations from a user's network.

## Source alignment

- Site project: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3`
- Public project repository: https://github.com/bartytime4life/MEGALODON
- Repository baseline represented by this revision: `main@ef688cb26a9cdbc251b0219fb8f5f3e763a70e34`
- Public mirror path: `site/`
- Deployable static assets: `dist/`

The MEGALODON repository root remains authoritative for product behavior, security contracts, tests, and implementation status. This Site summarizes those contracts for human review; it does not expand runtime authority.

The Suricata surface reflects the accepted durable-consumer capacity gate: a fixed consumer-owned logical 512 MiB ceiling is checked before runtime writes, refusal leaves no rows, and the single atomic writer remains Linux-only, non-root, capability-free, and limited to an already-private pre-created store. The shared 30-second deadline is cooperative, not a process-termination or filesystem-stall SLA. Retention, deletion, migration, reconciliation, producer orchestration, dashboard projection, blocking, action attribution, and every response path remain separate authority gates.

## Validation

Before publishing, verify JavaScript syntax, local asset references, the hosting manifest, the displayed repository pin, and the absence of executable install or host-control paths. A Site version and a public GitHub mirror are separate delivery records and must identify the same files when parity is claimed.
