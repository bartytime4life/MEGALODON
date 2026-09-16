# MEGALODON Defense Console

This repository is the deployment source for the private MEGALODON Defense Console at https://megalodon-defense-console.blackbart-55.chatgpt.site.

The Site is a static, browser-only interface prototype. It has no backend, connector, host probe, packet intake, database access, installer, service control, model call, firewall path, or write API. Synthetic preview values are labeled and must not be interpreted as observations from a user's network.

## Source alignment

- Site project: `appgprj_6aaa2be9d9288191a15a9c1d743af0b3`
- Public project repository: https://github.com/bartytime4life/MEGALODON
- Repository baseline represented by this revision: `main@a19426fec90cff063e882ebeba7179590c4ff78f`
- Public mirror path: `site/`
- Deployable static assets: `dist/`
- Brand asset: `assets/megalodon-github-hero-compact.png` from the repository README

The MEGALODON repository root remains authoritative for product behavior, security contracts, tests, and implementation status. This Site summarizes those contracts for human review; it does not expand runtime authority.

The Suricata surface reflects both the accepted durable-consumer capacity gate and the explicit commit-unknown reconciliation contract. The single atomic writer still checks a fixed consumer-owned logical 512 MiB ceiling before runtime writes. The separate reader pins the existing database with `O_RDONLY`, holds a Linux OFD read lock across SQLite's complete locking-byte region, refuses persistent WAL state and coordination sidecars, queries in read-only/query-only mode, and returns only `committed`, `not_committed`, or conservative `indeterminate` evidence for the exact publication and attempt identity. Neither path repairs permissions, migrates schema, deletes retained evidence, starts a producer, projects a dashboard, blocks traffic, attributes an action, or executes a response. The shared 30-second deadline is cooperative, not a process-termination or filesystem-stall SLA.

## Validation

Before publishing, verify JavaScript syntax, local asset references, the hosting manifest, the displayed repository pin, and the absence of executable install or host-control paths. A Site version and a public GitHub mirror are separate delivery records and must identify the same files when parity is claimed.
