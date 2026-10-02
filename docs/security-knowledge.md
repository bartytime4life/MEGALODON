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
attempt; failure does not cause repeated downloads on refresh. A clock rollback
does not repeat an earlier slot. **Check references now** retries immediately.

Requests use fixed HTTPS publisher endpoints, no proxy or redirect, and
conditional ETags. No IP observations, hostnames, prompts or reports accompany
them. ATLAS's release pointer is restricted to an approved monthly filename
within the format-6 directory. Document links are never fetched automatically.
Each download has an outer 90-second deadline in a disposable, resource-limited
worker. UTF-8 JSON structure and YAML nesting are bounded before object
materialization. Cancellation kills and reaps the download worker.

The private `knowledge` directory beside managed evidence has a separate
**512 MiB maximum**. It holds immutable SQLite FTS5 generations, compressed
source bodies for conditional updates, provenance, relationships and an
activation manifest. Each generation is capped at 160 MiB, allowing an active
generation, its predecessor and staging. Updates need this headroom and a
16 MiB free-disk reserve. Failed validation, interruption or insufficient
space leaves the active version in place. Activation replaces the manifest
atomically; **Use previous library** swaps the retained generations. Corrupt
indexes fall back to the starter while visibly reporting the problem.

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
and a 20-percentage-point difference. The existing regular-interval rule applies
to flow observations, not packet ACK timing. Port-53 bursts count observations,
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
Repeated work uses stable IDs. AI failure does not remove detector findings.

## Scheduling, feedback and reports

The service learns up to four completed hours per pass. Equivalent candidates
coalesce within 24 hours. The view retains at most 1,024 reviews and returns up
to 64 per status response. **Expected activity**, **Investigate** and **Incorrect
match** are durable feedback, not detector edits. Investigate remains unresolved.

Automatic inference allows four attempts in a sliding hour, including failures.
Budget admission persists before inference. One inference slot is shared with
existing controls. Manual requests can interrupt background generation; queued
manual reviews take the next slot. Cancellation targets that background job.

Prompts retain the existing 4 KiB and 256-output-token bounds. Responses use a
closed JSON contract with evidence/reference identifiers and a fixed workflow
ID. Unknown citations, executable fields and unsupported workflows are rejected.
Measurements are rendered from stored values. The provider schema asks for short,
nonempty text and fixed citation tokens; the validator requires the observation
citation and checks every knowledge identifier against the supplied references.
Valid citations do not prove a
model's reasoning; explanations remain advice.

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
