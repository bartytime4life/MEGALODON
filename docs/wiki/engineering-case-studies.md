# Engineering Case Studies

> **Historical case studies:** The four studies retain their October 11 source revision and recorded measurement scope. [Current documentation](https://github.com/bartytime4life/MEGALODON/blob/main/docs/current-state.md) and [the new visual tour](visual-tour.md) cover later additions without rewriting these results.

Four examples show how MEGALODON connects product choices to implementation and evidence. Source links below are pinned to `4da7fae0d8df2d8cd6b3ff93964055f7e14972bb`. Linked tests describe regression protection; their existence alone is not a claim that every check passed or that a host was accepted.

## 1. Recording efficiency with a visible tradeoff

**Problem:** Frequent durable packet-metadata writes can create substantial disk activity, while the project must retain qualified evidence and preserve detector consistency.

**Choice:** Balanced recording batches ordinary events until two seconds, 256 events, or 1 MiB. Findings flush linked evidence immediately. Detector windows become committed only after the evidence transaction succeeds. Reports read bounded retained segments rather than the dashboard’s newest slice.

**Recorded result:** The October 1, 2026 synthetic comparison used fresh private stores and 10,000 records per workload, with concurrent history reads.

| Packet workload | Before | Balanced |
| --- | ---: | ---: |
| OS-written bytes | 400,125,952 | 7,479,296 |
| Retained records | 10,000 | 10,000 |
| History-query p95 | 4.21 ms | 27.06 ms |
| Recorded run duration | 18.64 s | 0.91 s |

This is **98.1% fewer OS-written bytes** in the saved packet case. The separate summary case records a 43.6% reduction. The measurement is historical and synthetic; it does not establish long-running throughput, production accuracy, flash-cell writes, or SSD lifespan. A sudden process/power failure can lose the unsaved batch. Query latency increased in the packet case.

**Inspect:** [Raw measurements](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/benchmarks/efficient-recording-comparison.json) · [Reproduction tool](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tools/benchmark_recording.py) · [Storage implementation](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/evidence_storage.py) · [Batching and storage tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_recording_storage.py) · [Full interpretation](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/efficient-recording-reports.md)

## 2. A network atlas that keeps uncertainty visible

**Problem:** Attractive network graphics can imply physical routing, device ownership, or comprehensive visibility that the underlying data cannot prove.

**Choice:** Animate only recent observed directions. Keep approximate IP locations labeled. Suppress stale or hidden-view motion, preserve unmapped endpoints in the roster, and separate the globe from local network relationships. Limit the retained live cache to 512 tuples and the returned projection to 128 rows.

**Implementation:** A local Linux capture path qualifies metadata before it enters the live view. Sessions are finite and receipted; errors stop automatic retries. Location updates are a separate opt-in. The graphic is an evidence projection with camera controls, not a geolocation verdict or route tracer.

**Tradeoff:** Cache eviction, capture gaps, unknown locations and the hidden hemisphere limit what can be seen. A text roster and source-status disclosure carry what the visualization cannot.

**Inspect:** [Live connection cache](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/live_connections.py) · [Canvas presentation](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/dashboard_globe.py) · [Cache, freshness and limit tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_live_connections.py) · [Geography and motion contract](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/live-connection-globe.md)

## 3. Security at the point of use

**Problem:** Local applications still face concurrent requests, untrusted filenames, ambiguous file identity and failure after a host action.

**Choices and merged examples:**

| Boundary | Concrete repair | Evidence |
| --- | --- | --- |
| Concurrent sign-in | Atomic password-check admission across sign-in routes | [#524](https://github.com/bartytime4life/MEGALODON/pull/524) |
| Local socket ownership | Refuse Linux HUD connections from other local accounts; handle IPv4-mapped loopback | [#525](https://github.com/bartytime4life/MEGALODON/pull/525), [#526](https://github.com/bartytime4life/MEGALODON/pull/526) |
| Untrusted scan output | Keep scanned filenames from hiding ClamAV matches | [#538](https://github.com/bartytime4life/MEGALODON/pull/538) |
| Parser admission | Refuse HTTP/0.9 simple requests before headers | [#534](https://github.com/bartytime4life/MEGALODON/pull/534) |
| Containment recovery | Preserve release paths, audit outcomes and protected service endpoints | [#535](https://github.com/bartytime4life/MEGALODON/pull/535), [#536](https://github.com/bartytime4life/MEGALODON/pull/536) |

Temporary HUD containment requires an observed public endpoint, preview, separate operator action and OS approval. Rules live in the fixed managed table with a five-minute kernel timeout. Model output never grants that approval. The legacy firewall CLI apply flags continue to refuse.

**Tradeoff:** Refusal and visible ambiguous outcomes can interrupt a workflow. They preserve the evidence needed to decide what happened. Merged repairs are not a whole-project security certification.

**Inspect:** [HTTP boundary](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/dashboard.py) · [Action lifecycle](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/defense.py) · [Fixed privileged helper](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/defense_guard.py) · [Refusal and recovery tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_defense.py) · [Security boundaries](security-boundaries.md)

## 4. AI advice without transferring authority

**Problem:** A useful explanation must not turn malformed model text, fabricated evidence or a mutable model alias into a command or trusted finding.

**Choice:** HUD model selection uses installed local completion models and exact digest checks. Evidence prompts and output are bounded. IP analysis accepts a closed explanation/proposal shape. Provider failures stay visible; deterministic evidence survives independently. Advice can suggest a fixed workflow, but an operator chooses its execution.

**Regression example:** [#520](https://github.com/bartytime4life/MEGALODON/pull/520) keeps disabled model telemetry idle. [Sentinel tests](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/tests/test_qwen_zero_effect.py) distinguish disabled denial, read-only status, explicitly audited broker behavior, and the limits of the canonical binding gate.

**Acceptance boundary:** `config/model-bindings/qwen.unbound.json` remains **UNBOUND** with no recorded owner model decision. [#446](https://github.com/bartytime4life/MEGALODON/issues/446) is open. HUD runtime model selection and working provider code do not establish canonical Airlock acceptance, native containment, or representative model quality. [#530–#532](https://github.com/bartytime4life/MEGALODON/pull/530) add privacy-minimized evaluation and outcome-consistency contracts; they do not supply an executed production corpus.

**Inspect:** [Model selection](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/local-model-selection.md) · [Advisory adapter](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/megalodon/qwen_advisory.py) · [Canonical binding](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/config/model-bindings/qwen.unbound.json) · [Evaluation contract](https://github.com/bartytime4life/MEGALODON/blob/4da7fae0d8df2d8cd6b3ff93964055f7e14972bb/docs/qwen-adversarial-evaluation.md)

[Builder profile](builder-profile.md) · [Visual tour](visual-tour.md) · [Evidence index](evidence-index.md)
