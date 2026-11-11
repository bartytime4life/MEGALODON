# Local security knowledge and patterns

## Using it

Open **Setup → AI knowledge & patterns**. Three preferences control local
baseline learning, automatic explanations, and daily public-reference updates.
The HUD's **Review activity** link opens Findings. Each review answers **What
happened**, **Why it matters**, and **What you can do**. Measurements, source
references, alternative explanations and missing information are under Details.

The endpoint inspector uses the same committed-evidence explanation pipeline.
The selected Ollama model is preserved. This feature retrieves reference text;
it does not train model weights. Background analysis proposes only. Inventory
refresh, file scanning and containment use the existing operator-reviewed
defense routes. Model text never becomes a command.

## Reference library

The packaged starter is a deliberately small **202-document subset**. Its JSON
contains source edition, canonical URL, retrieval time, upstream SHA-256,
attribution and license text. `starter.sha256` verifies the packaged content.
Documents are selected/truncated excerpts, identified as such.

| Publisher | Admitted format | License / scope |
|---|---|---|
| MITRE ATT&CK | Enterprise STIX, active techniques and mitigations | MITRE license; retired objects excluded |
| MITRE ATLAS | Published format 6 YAML, techniques, mitigations and cases | Apache-2.0; aliases and custom tags refused |
| MITRE D3FEND | JSON-LD defined concepts | MITRE D3FEND license; third-party attack graphs excluded |
| OWASP GenAI | Ten canonical 2026 Markdown documents | CC-BY-SA-4.0; adapted reference text retains this license |
| CISA KEV | Official `cisagov/kev-data` JSON mirror | CC0-1.0; vulnerability context only |
| IANA | Existing verified protocol/service library | Existing attribution and lookup contract unchanged |

OWASP editions and ATLAS format major versions are fixed in reviewed code. A new
edition/format needs a code update. Changed publisher licensing blocks activation
until reviewed. Updates cannot silently change these assumptions.

Reference checks run in the local service at **08:00 local time**. The latest
missed slot is checked once after downtime. The slot is persisted before the
attempt; failure does not cause repeated downloads on refresh. Shutdown during
a check is not recorded as a failed check; the interrupted slot runs again after
restart. A clock rollback does not repeat an earlier slot. **Check references
now** retries immediately.

Requests use fixed HTTPS publisher endpoints, no proxy or redirect, and
conditional ETags. No IP observations, hostnames, prompts or reports accompany
them. ATLAS's release pointer is restricted to an approved monthly filename
within the format-6 directory. Document links are never fetched automatically.
Each download has an outer 90-second deadline in a disposable, resource-limited
worker. The worker runs in Python isolated mode from `/`, so the dashboard's
working directory, user site and `PYTHON*` variables cannot supply its modules;
only this package's own directory is added to its import path. UTF-8 JSON
structure and YAML nesting are bounded before object materialization.
Cancellation kills and reaps the download worker.

The private `knowledge` directory beside managed evidence has a separate
**512 MiB maximum**. It holds immutable SQLite FTS5 generations, compressed
source bodies for conditional updates, provenance, relationships and an
activation manifest. Each generation is capped at 160 MiB, allowing an active
generation, its predecessor and staging. Updates need this headroom and a
16 MiB free-disk reserve. Failed validation, interruption or insufficient
space leaves the active version in place. Activation replaces the manifest
atomically; **Use previous library** swaps the retained generations. A failed
index read, including corruption detected after launch, switches status,
search and pattern references to the verified packaged starter with a fixed
review warning. These reads do not repair files, change the manifest, start an
update or download anything. The damaged generation and last good predecessor
remain available for explicit recovery. Restoring file bytes alone does not
clear the warning; a validated rollback or successful activation does.

Fallback exposes `starter:<SHA-256 of the packaged starter>` as its serving
generation, so source attribution and cached explanations can distinguish it
from the failed index. Stored active/previous identities stay unchanged during
fallback reads. Digest-cache qualification includes device and change time,
and file identity is checked around hashing and each index read. This detects
observed local index changes; it is not protection against an owner who can
rewrite the application, reference files and trust metadata together. The next
successful update keeps the last good predecessor as the rollback target
and retires the damaged generation. If an update activates but its final status
cannot be saved, the status reports the activation rather than a failure.

`pip install .[knowledge]` supplies PyYAML for ATLAS updates. The Linux installer
includes this supported extra. The packaged starter works without PyYAML.

## Measurement and learning

Pattern work uses committed, qualified historical pages and existing offline
heuristics. It starts no packet collector. Packets and flow summaries stay in
distinct groups. Sensor, interface and source device identify each baseline.
Qualified packet rollups supply weighted protocol/port counts; lost per-packet
timing is never reconstructed.

Completed hours are compared with the preceding seven days. A group needs
**24 distinct eligible hours**. An eligible hour has at least 20 observations
spanning 50 minutes, no associated finding for that device, and no known
truncation or read gap. This is not proof of complete capture. Unknown sensor
health remains unknown.

New ports need five observations. Protocol/service shifts need five observations
and an exact, unrounded 20-percentage-point difference. The existing
regular-interval rule applies to flow observations, not packet ACK timing. Port-53 bursts count observations,
not verified DNS queries. Inventory comparisons never infer departure from
absence. Ordinary backups, updates and scheduled tasks can produce candidates.

One hourly read is bounded to 20,000 returned rows, 80,000 scanned rows and an
eight-second work budget. At most 128 traffic identities are grouped; timing
checks retain at most 2,048 observations per group. Busy/incomplete windows
disclose limits and cannot train baseline-dependent alerts. These bounds are
not a claim of full high-volume server coverage.

The reader selects qualified originals or compact replacements, not both.
Separately observed sensors are never summed into one network total. Ports,
service labels and periodic traffic cannot establish a particular installed
application or AI-assisted attacker. KEV applicability requires an explicit CVE
or independently verified affected product/version evidence; search results
themselves remain context only.

Baselines, candidates, feedback and AI receipts use managed evidence segments.
Their timestamp is the oldest source used, including comparison hours. Missing
source segments invalidate derived records; verified compact replacements can
preserve provenance. Dependencies are committed alongside the segment data and
recovered after restart. Cases and reports inherit those dependencies. Source
retirement reclaims dependent segments; mixed segments may expire early. Action
ledgers keep review identifiers rather than longer-lived copies of explanations.
Up to 256 source segments can support a comparison; larger sets report a gap.
Hour completion is checkpointed after candidate persistence.

### Exact comparison arithmetic and indexed history

For a label with current count `n` out of `C` and baseline count `b` out of
`B`, the share change in percentage points is `100 × (nB − bC) / (CB)`.
Admission compares the integers `100 × abs(nB − bC)` and `20 × CB` before
rounding. A 19.96-point difference therefore stays below the 20-point threshold,
even though its one-decimal display would be 20.0. Exact 20-point changes
remain eligible. Display values round the exact fraction to one decimal with
ties to even. Counts may exceed floating-point precision after compaction and
aggregation; [Python's rational arithmetic](https://docs.python.org/3.11/library/fractions.html)
keeps this display step separate from the integer admission decision.

Each hourly pass partitions retained baselines once by address, interface,
sensor and measurement. History-key selection becomes `O(H + G)` rather than
`O(H × G)`, for `H` historical rows and `G` current groups. Distribution
aggregation still visits the selected historical counts. The index holds
references for the current call only; it is not a cache that can outlive source
expiry. Existing seven-day traffic and two-hour inventory windows, distinct-hour
deduplication, input-order tie handling, coverage exclusions and dependencies
remain in force. Indexing adds `O(H)` temporary references to the history already
supplied for this call; the index is discarded when the call finishes.

The [synthetic comparison measurements](benchmarks/pattern-comparison-20261111.json)
compare complete pure hourly analysis against source revision
`16f8d33e336173c0abd8916000bc801d7768e835`, using 1, 8, 32 and 128 groups with
168 historical hours each. At 128 groups, history-key reads fell from 2,752,512
to 21,504; median runtime across seven runs fell from 149.829 ms to 31.456 ms
(about 4.8 times faster). Outputs, including two 25-point review candidates,
matched exactly on these cases. Traced temporary peak allocation increased from
425,804 to 613,780 bytes. Small histories pay indexing overhead; the one-group
case rose from 0.197 ms to 0.213 ms. These finite timings describe this synthetic
workload, not capture capacity, model performance or malware accuracy.

Reproduce from a trusted Git checkout with:

```bash
python tools/benchmark_pattern_comparison.py \
  --baseline-revision 16f8d33e336173c0abd8916000bc801d7768e835
```

The benchmark executes the selected local source snapshot and the current
implementation against synthetic compacted metadata. It creates no evidence
store and performs no capture, provider, model or host action. Boundary tests
separately use exact rational expectations, large counts, display ties,
source separation, expiry windows and duplicate hours; away-from-threshold
benchmark parity does not cover the deliberately corrected threshold cases.
Repeated work uses stable IDs. AI failure does not remove detector findings.

## Scheduling, feedback and reports

The service learns up to four completed hours per pass. Equivalent candidates
coalesce within 24 hours. The view retains at most 1,024 reviews and returns up
to 64 per status response. **Expected activity**, **Investigate** and **Incorrect
match** are durable feedback, not detector edits. Investigate remains unresolved.

Automatic inference allows four attempts in a sliding hour, including failures.
Endpoint inspector reviews are never selected for automatic explanation; they
belong to the manual request that created them.
Budget admission persists before inference. One inference slot is shared with
existing controls. Manual requests can interrupt background generation; queued
manual reviews take the next slot. Cancellation targets that background job.

Prompts retain the existing 4 KiB and 256-output-token bounds. An oversized
prompt is refused before the provider is contacted. When a HUD question's
knowledge search returns more than one prompt holds, only the model's copy of
the excerpts is shortened; the operator still receives the complete broker
result. Responses use a
closed JSON contract with evidence/reference identifiers and a fixed workflow
ID. Unknown citations, executable fields and unsupported workflows are rejected.
Measurements are rendered from stored values. The provider schema asks for short,
nonempty text and fixed citation tokens; the validator requires the observation
citation and checks every knowledge identifier against the supplied references.
Valid citations do not prove a
model's reasoning; explanations remain advice.

A ready explanation is reused only when its selected AI settings, versioned
prompt/response contract and immutable knowledge-library generation all match.
Legacy explanations without this complete identity regenerate on request. A
model-setting or library-generation change during inference rejects the result
instead of saving it under the wrong provenance. This cache identity is an
auditability boundary, not proof that the model's interpretation is correct.

Reports include up to 128 reviews from the recent 1,024 candidates and at most
256 derived source dependencies, with coverage limits stated. Downloading a
report runs no inference. Reports containing expired source-derived explanations
become unavailable. This feature preserves the 14-day / 20-GiB evidence policy.

## Development

`tools/build_security_starter.py` selects the starter from reviewed publisher
downloads. New sources, executable workflows, thresholds and permissions require
code changes and tests. See `tests/test_security_knowledge.py`,
`tests/test_security_patterns.py` and `tests/test_intelligence_http.py` for
failure, provenance, retention and request-boundary checks. Measured acceptance
results are recorded in [the acceptance record](security-knowledge-acceptance.md).

The local HUD remains supported. The GPT Site remains retired.

### Comparing saved explanations

Review cards keep their short observation and advice visible. Expand **Advanced ·
explanations, measurements and sources** to compare a completed model's
interpretation with its alternative explanation, suggested distinguishing
information, citation references and the reviewed next workflow. Suggestions are
not verified causes; both explanations may remain unresolved. Missing values
are labeled, and failed or unfinished analyses do not display a comparison.

The comparison uses the existing saved review and refresh path. It does not
invoke a model when expanded, add confidence scores, or introduce automatic
reanalysis of changed evidence. Source-retention checks and existing opt-in
analysis scheduling still govern which reviews are available.
