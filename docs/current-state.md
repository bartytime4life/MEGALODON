# Current state and evidence boundaries

**Documentation basis — 2026-10-19 UTC / October 18 in America/Chicago.**
Repository: [bartytime4life/MEGALODON](https://github.com/bartytime4life/MEGALODON).
Source pin: [`a380fe0d60f798106bf05c29729ca7cce91cca67`](https://github.com/bartytime4life/MEGALODON/commit/a380fe0d60f798106bf05c29729ca7cce91cca67);
tree `170066be53387deaf757862227710a24e28e2e9f`.

This is an orientation and correction layer. It preserves dated records and
does not approve a model, host action, release, or deployment. **OBSERVED** below
means source or external state was read; tests need their own revision and result.

## What exists at this pin

| Area | OBSERVED implementation | Boundary and primary source |
| --- | --- | --- |
| Metadata core | Bounded typed input, three fixed rules, private SQLite audit | Payloads and payload-derived hashes are outside the event model. [Specification](../SPECIFICATION.md), [models](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/megalodon/models.py), [detectors](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/megalodon/detector.py) |
| Linux workspace | HUD, Findings, Sensors, Setup, Reports, Evidence and Help | Loopback host application; read projections and protected actions are different routes. [HTTP contract](dashboard-http-contract.md) |
| Finding inspector | A qualified finding links to its stored event and ingestion-run receipt | Returned-page scope, recorded times and ingestion completion are visible. It does not establish current sensor liveness. [PR #654](https://github.com/bartytime4life/MEGALODON/pull/654), [control room contract](control-room-contract.md) |
| History and reports | Segmented private evidence, bounded history, compact summaries and local visual reports | Gaps, packet/flow units and report windows remain explicit. Defaults: 14 days / 20 GiB, daily reports at 9 AM local time. [Managed evidence](managed-evidence.md), [reports](efficient-recording-reports.md) |
| Companion catalog | Twelve static entries, including Lynis and AIDE | Presence is distinct from running, configured and admitted data. Static catalog commands execute nothing. [Catalog](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/megalodon/capabilities.py), [background tools](background-tools.md) |
| Host security | Explicit Lynis audits, AIDE baseline/comparison, fixed public threat-reference refresh | Unprivileged audit coverage; file differences and feed matches need interpretation. No automatic hardening, quarantine or containment. [Host security](host-security.md) |
| Offline sources | Bounded TShark, Zeek and Suricata paths with separate contracts | A completed-file importer does not operate or qualify a producer. [Offline analysis](offline-analysis.md), [Suricata projection](suricata-evidence-projection.md) |
| Local models | Optional installed-model selection, bounded explanation and closed proposals | Runtime selection does not complete canonical Qwen Airlock acceptance; model output is untrusted. [Model selection](local-model-selection.md), [canonical binding](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/config/model-bindings/qwen.unbound.json) |
| Firewall interfaces | Legacy CLI apply refuses; separate protected Linux HUD containment exists | Distinguish existing implementation from authorization to use it. This documentation task authorizes no host operation. [Defense contract](visual-operations-defense.md), [legacy backend](https://github.com/bartytime4life/MEGALODON/blob/a380fe0d60f798106bf05c29729ca7cce91cca67/megalodon/firewall.py) |
| Hosting | A separate address-free snapshot viewer; local HUD remains the host application | Site readback: **PC Snapshot Console v67**, active, at the existing Site address. This does not prove source parity or live telemetry. [Site scope](../site/README.md), [publication history](site-source-alignment.md) |
| License | Apache-2.0 | Packaging and redistribution obligations remain applicable. [LICENSE](../LICENSE), [notices](../NOTICE) |

## Corrections to older orientation material

| Older statement | Present interpretation |
| --- | --- |
| “The hosted console is retired” | Correct for the historical empty-410 publication. The existing Site was later restored as a separate snapshot viewer. It does not control the PC. |
| “The catalog has ten tools” | The current static catalog includes Lynis and AIDE, for twelve entries including the core. Old twelve-tool references containing OSSEC/Zabbix describe a different historical catalog. |
| “The dashboard is read-only” | Correct for core telemetry-reader interfaces. Current Linux HUD actions are separately protected capabilities. Never use a read-only claim to describe all application routes. |
| “All firewall application is unsupported” | Applies to the retained legacy CLI/backend. A separate HUD workflow exists; its implementation does not itself authorize its use. |
| “No scheduler or feed path exists” | Applies to the inert general automation contract. Fixed local report/companion schedules and explicit public reference downloads are separate implemented workflows. No general-purpose SOAR executor follows. |
| “No license” or September issue/test counts | Preserved research/history only. Re-read current source, issue state and exact-head checks before use. |

These distinctions supplement the scope notes in the specification and security
review. They do not silently change their normative security requirements.
Where a contract and implementation disagree, treat it as a review question;
do not infer permission from the presence of code.

## Remaining public gates

GitHub readback in this pass found three open issues and no open pull requests
before this documentation candidate was created. This is a dated queue snapshot,
not an acceptance result.

| Issue | Remaining gate |
| --- | --- |
| [#345](https://github.com/bartytime4life/MEGALODON/issues/345) | Native macOS M1 storage admission; synthetic CI does not establish native acceptance |
| [#445](https://github.com/bartytime4life/MEGALODON/issues/445) | One exact Zeek offline producer profile; owner selection and fixture checks do not complete qualification |
| [#446](https://github.com/bartytime4life/MEGALODON/issues/446) | Canonical Qwen Airlock binding and zero-effect/containment/evaluation acceptance; record remains UNBOUND / operator decision NOT_RECORDED |

The [owner lifecycle gate](exact-head-owner-lifecycle.md) has documented workflow
trust and enforcement limits. Green technical CI, an advisory owner status, a
merge, and human GitHub approval are different evidence. No protection setting
was changed in this task.

## What the visuals prove

The [visual tour](wiki/visual-tour.md) includes historical synthetic browser
captures from PR #654, bound to candidate
`424d957472ad121becec635171bc281bec2de995`, run
[39180659477](https://github.com/bartytime4life/MEGALODON/actions/runs/39180659477).
They show that candidate's rendered interface with documentation addresses.
They do not show a live PC, current host configuration, fresh browser acceptance
at this documentation head, detection accuracy, or an accepted release.
The [asset record](../assets/docs/README.md) identifies exact bytes and sources.

The October 1 recording benchmark remains a **historical finite synthetic
measurement**. Its 98.1% lower OS-written bytes comes with increased query p95;
it is not a current performance guarantee. See [the case study](wiki/engineering-case-studies.md#1-recording-efficiency-with-a-visible-tradeoff).

## Keep the documentation current

1. Read `main`, the relevant code, tests, PRs and issues at an exact SHA.
2. Update current task guides and this orientation only where evidence changed.
3. Preserve dates, original pins and result counts in historical records.
4. Validate links and the generated Wiki, then review the exact candidate.
5. Merge and Wiki publication require their separate repository lifecycle gates.

[Field guide](README.md) · [Complete catalog](documentation-map.md) · [Contribution contract](../CONTRIBUTING.md)
