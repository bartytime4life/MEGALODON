# Documentation reconciliation — October 22, 2026

Status: **OBSERVED source alignment; documentation only.** Repository:
[bartytime4life/MEGALODON](https://github.com/bartytime4life/MEGALODON).
Baseline: [`0acdf72663804c9ae8380522e344a515ac65978c`](https://github.com/bartytime4life/MEGALODON/commit/0acdf72663804c9ae8380522e344a515ac65978c),
tree `028f67a172b011ab4281e68b2162597a21a05920`.
Dates in this record use America/Chicago unless a timestamp explicitly says UTC.

## Scope and reading order

The [current-state page](current-state.md) is the dated orientation; the
[field guide](README.md) routes operator tasks; the [complete catalog](documentation-map.md)
accounts for every tracked Markdown file. The specification and security review
retain normative authority. Dated research, measurements, source-alignment
receipts and lifecycle records retain their original pins and outcomes.

All 159 existing Markdown files were inventoried and read programmatically for
local file/heading links and stale-claim searches. Maintained entry pages and
flagged task/contract statements were checked against named source owners. This
is not a manual technical audit of every paragraph, upstream research refresh,
security scan, independent approval or operational acceptance. With this record,
the documentation catalog contains 160 files. Correct guides where behavior or
tracking differs; do not rewrite historical evidence to make it look current.

Runtime code, tests, dependencies, schemas, workflow definitions, fixture bytes,
image assets and saved audit/acceptance receipts are unchanged. No installation,
collector, model, service or firewall operation was performed. Wiki source is
prepared for review; the native Wiki and hosted Site were not published.

## Supplied planning sources

The two attached copies begin with a September 20 correction layer and preserve
older originals below it. Their current-file identities are different from the
original-only digests printed inside them. They were read as design/history,
not as current repository evidence, and were not modified or copied into Git.

| Supplied file | Attached-copy bytes / SHA-256 |
| --- | --- |
| `MEGALODON-unified-architecture-and-roadmap.md` | 50,848 / `df4037d43144a718c022a0639aedc248d07dae9332dcb852ce9bfde5c54b74d8` |
| `MEGALODON-research-backed-path-forward-2026-09-17(1).md` | 125,877 / `5645df2647c4b454d544718bc2df169cf8421af2b9170719111227253c298c23` |

| Planning statement | Current disposition and owning guide |
| --- | --- |
| No project license | Superseded: Apache-2.0 root/package licensing exists; [license decision](license-decision-2026-09-20.md). No redistribution or release clearance is inferred |
| Atomic evidence, recovery, durable Suricata and registry still need implementation | Implemented boundaries exist; operational proof remains separate. [Ingestion](ingestion-integrity.md), [recovery](sqlite-recovery-contract.md), [Suricata](suricata-evidence-projection.md), [detector receipt](detector-acceptance.md) |
| Dashboard/read-only and firewall/plan-only describe the whole product | Those remain the legacy/core-reader contracts. The source also contains separately protected Linux HUD setup and defense routes. [HTTP contract](dashboard-http-contract.md), [defense](visual-operations-defense.md). Their presence grants no host authority |
| No scheduler, watcher or downloads anywhere | The general automation contract remains bounded preview/design. Fixed companion/report schedules, configured collectors and public reference refreshes are separate implementations. [Background tools](background-tools.md), [reports](efficient-recording-reports.md), [knowledge](security-knowledge.md) |
| Qwen acceptance follows from a working local model | Rejected: installed-model selection and the canonical Airlock are different boundaries. Binding remains UNBOUND; [#446 packet](qwen-446-owner-decision-packet.md) owns missing evidence |
| Zeek build or Community ID completes producer admission | Rejected: the owner selected a private 8.0.10 candidate, but the versioned profile remains a placeholder; [#445 selection/qualification](zeek-producer-selection-packet-2026-10-04.md) |
| Proposed gateway promotion, unrestricted scripting, model recursion or automatic response | Remain proposals or conflicts, not accepted requirements. [Original reconciliation](unified-roadmap-currentness.md), [automation contract](automation-contract.md), [model containment](model-containment-review.md) |
| September schedules, upstream versions, issue counts and hosted Console version | Historical, not today's deadlines or deployment/acceptance state. [Current state](current-state.md) records fresh source/check/issue observations; hosting was not re-read |

This reconciliation does not authenticate the supplied incident narrative or
adopt a 90-day deadline, inline gateway role, model tool authority, automatic
blocking, remote administration or any other runtime expansion.

## Corrections across maintained documentation

| Area | Correction / source owner |
| --- | --- |
| Entry pages and Wiki | Advance descriptive source orientation to the baseline; preserve original screenshot/benchmark identities and historical case studies |
| Catalog and readiness | Twelve components/workflows, including Lynis/AIDE, agree with `capabilities.py`, `hub.py`, `readiness.py`, HTTP limits and browser ID sets. PATH-only v2 and HUD known-location v3 remain distinct; old ten-ID v2 imports are normalized locally |
| Operator setup | Setup navigation, manual checks, private-prefix discovery and installed-HUD behavior replace obsolete hosted-mirror instructions |
| Startup | Document managed user-service start, separate login enable, disable-and-stop, foreground fallback, saved monitoring and independent companion-service lifecycle |
| Installer | Fresh installation includes `geo`/`knowledge`; upgrades may preserve supported capture extras. Dependencies, data downloads and collector authority are different choices |
| Hub and downloads | Static plans/converters do not execute tools; separately configured HUD inventory, scans, Suricata service and Zeek sampling do exist. Fixed ClamAV updater controls and operator-reviewed HUD containment are scoped separately |
| Acceptance tracking | #345 closed after #656; #445/#446 remain open. Earlier #258/#261/#327 wording now points to successor qualification gates. macOS support is not promoted |
| Dependency evidence | Pluggy 1.7.0 merged through #657. Main retains Playwright 1.63.0; open #658/#660 do not change it. Record main's browser timeout without attributing it to a proposed version bump |
| Publication and governance | Snapshot-viewer v67 is the last recorded hosting observation. Current lifecycle code uses default-branch `pull_request_target`/comment events; its advisory status and enforcement limits remain in [the owner gate contract](exact-head-owner-lifecycle.md). No live protection change is claimed |

## Validation and limits

**VERIFIED locally on this documentation candidate:**

| Check | Result |
| --- | --- |
| Existing focused pytest selections listed below | 150 passed on Python 3.12.14 / pytest 9.1.1 / Pluggy 1.7.0 |
| Complete catalog and Markdown/HTML local links | 160 Markdown files accounted for; 971 local file/heading links valid at the initial final-content scan |
| Wiki projection | 13 generated files, including sidebar/footer, validated without publishing |
| Source build-input inventory | `BUILD_INPUT_INVENTORY:OK`; no regeneration needed |
| Compilation and whitespace | `compileall` and `git diff --check` passed |
| Safe CLI smokes | Core/offline/evaluation help and static capabilities/hub plans; no tool or model launch |

Focused pytest command, from the repository root in the prepared test environment:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTEST_PLUGINS='' PYTEST_ADDOPTS='' \
  python -m pytest -o addopts='' -q \
  tests/test_documentation_currentness.py tests/test_wiki_sync.py \
  tests/test_capabilities.py tests/test_hub.py tests/test_readiness.py \
  tests/test_red_blue_security_guide.py tests/test_tool_setup.py \
  tests/test_hud_autostart.py
python -m compileall -q megalodon tests tools
python tools/build_input_inventory.py --check
bash .github/scripts/sync-wiki.sh --validate
git diff --check
```

The local environment was installed with `-c constraints/ci.txt -e '.[test]'`.
This used package indexes; it is not the CI hash-verified wheel acquisition or
an installed-host acceptance receipt. No full pytest or real-browser rerun was
needed to change prose. External URLs were not globally crawled.
The existing [documentation tests](../tests/test_documentation_currentness.py),
[Wiki tests](../tests/test_wiki_sync.py), static catalog/hub/readiness tests and
safe help/static-plan commands are the relevant bounded checks. They do not
launch a producer, model, installed HUD or live firewall.

[Source-head GitHub observations](current-state.md#exact-source-head-checks-observed)
remain separate: core CI and CodeQL succeeded; browser run `39787193736` failed
with `TimeoutError` at suite line 701 after successful 1.63.0 driver preparation.
That is an inherited observation with unproved cause, not a passing candidate
browser result. Both identity-packet jobs were skipped. The releases endpoint
returned no releases at this readback; this prose does not publish one.

No fresh real browser, native macOS/Windows, installed-host, producer, provider,
release packet or hosted-deployment acceptance was performed. Review this draft
at its exact head; any later merge, Wiki publication, install or operation has
its own gate.
