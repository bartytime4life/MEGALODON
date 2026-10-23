# Practical Applications

MEGALODON is useful when a person needs to understand a local observation and
retain the evidence behind a decision. These walkthroughs use implemented
features at [`2cb7060`](https://github.com/bartytime4life/MEGALODON/commit/2cb706039724d9ea0bda09cbd3c17698b15ba55c); they are illustrative tasks,
not claims about customers, incident outcomes or production accuracy.

## Investigate an unexpected connection

1. Inspect the selected source, interface, time window and collection state.
2. Use the atlas and its text roster for observed peers. Unmapped peers remain
   visible; IP geography is approximate and does not show a physical route.
3. Review own-account **Programs on the network** for available executable and
   socket context. Other accounts, privileges and read limits create gaps.
4. If a qualified finding exists, open its linked event and ingestion receipt.
   Read all three clocks and the source qualification before making a report.

An executable hash identifies bytes, not reputation. A temporary/deleted program
or unfamiliar destination can come from legitimate updates or applications.
No automatic containment follows. [Atlas](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/live-connection-globe.md),
[program review](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-security.md#programs-on-the-network).

## Review a system change after maintenance

Lynis can surface configuration suggestions; AIDE compares its fixed readable
scope against an explicitly created baseline. Persistence review compares
bounded startup entries. Review the private source report, baseline identity,
observation date and known package/operator changes together. A baseline is
`observed_not_known_clean` where that contract specifies it; it does not certify
an uncompromised system. Partial/unreadable scope stays disclosed.

Preserve the old baseline before any deliberate replacement. A change category
is not a file count or an attack attribution, and a no-difference comparison
does not establish recoverability. [Host checks](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-security.md).

## Teach deterministic detection in an owned lab

Use the checked-in synthetic corpus and offline evaluation recipes to explore
SYN bursts, distinct destination ports and DNS query-length thresholds. Explain
why a rule fires, which inputs it uses and which normal activity might also
match. Keep synthetic data in a separate private environment and label every
result. No real capture, model or firewall privilege is needed for this lesson.

The corpus has 12 deterministic scenarios / 6,492 event-shaped records; it is
synthetic-only and uncalibrated. It cannot establish operational precision,
recall or network coverage. [Reference/corpus contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/reference-data.md),
[safe recipes](https://github.com/bartytime4life/MEGALODON/blob/main/README.md#installation-and-first-run).

## Prepare a local investigation handoff

Reports combine retained evidence within their source-specific windows. Check
gaps, exclusions, units and timestamps before saving or printing. Keep model
commentary visibly separate from deterministic findings. A report can explain
what was observed and what needs review; it cannot make missing evidence appear.

Exports can contain private operational information. Inspect the finished export
before sharing, and never commit real reports, captures, host paths or tokens
as documentation examples. Downloaded copies are outside managed retention.
[Reporting](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/efficient-recording-reports.md).

## Assess recovery preparation

Setup's read-only Recovery readiness reveals the difference between an AIDE
comparison and an external backup receipt. Separately reviewed, pinned producer
and independent isolated-test records can establish that those records agree
within their validity window. MEGALODON does not perform the external test,
probe the backup or supply the operator's trust decision.

Host restore remains unavailable, even when external evidence is admitted.
Current-host conflicts, malicious causality and file cleanliness remain unknown.
The practical outcome is a clearer preparation gap and a safer handoff to a
separately authorized recovery process—not an automatic rollback recommendation.
[Receipt contract](https://github.com/bartytime4life/MEGALODON/blob/2cb706039724d9ea0bda09cbd3c17698b15ba55c/docs/host-backup-evidence.md).

## Explore local AI without delegating authority

Choose a reviewed installed model through Setup, inspect provider/response
status and ask for an explanation of the bounded selected evidence. Treat the
answer as advice. Verify important claims against the linked records and use
the existing operator workflow only after its separate authorization steps.
Model availability does not complete canonical Qwen binding, provenance,
containment or representative evaluation. [Local AI](integrations-and-qwen.md).

[Quick start](quick-start.md) · [Technical deep dive](technical-deep-dive.md) ·
[Roadmap and limits](roadmap-and-limits.md)
