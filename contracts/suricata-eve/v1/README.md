# Suricata EVE alert contract v1

**Status: PROPOSED / NORMATIVE DRAFT / SCHEMA AND SYNTHETIC FIXTURES ONLY.**
This directory does not implement an importer, install or run Suricata, download
rules, capture packets, start a scheduler, persist telemetry, modify the dashboard,
or authorize a firewall action. Nothing under `megalodon/` is changed.

Authoring base: `dc35854a4bb9a4d353b3832cb18d5dee780d244c` in
`bartytime4life/MEGALODON`. The current MVP specification and security review
remain authoritative. This proposal does not override their safety boundaries.

## 1. Scope and compatibility

The first dependency-closed slice defines an input envelope, a separate
`ExternalAlertRecord` representation, accepted pairs, rejected mutations, and
byte-framing examples. All fixture addresses and rule labels are synthetic;
forbidden-content tests use null/empty markers, not packet payloads or hashes.

`schema.json` uses JSON Schema Draft 2020-12 with local-only references:
`$defs/inputEnvelope` and `$defs/externalAlert` are the two entry points. Objects
are closed at every level. Conformance requires the schema **and** the framing,
semantic, and pair rules below. A schema-only pass is not full conformance.

The documentary field baseline is the Suricata **8.0.1** EVE documentation [1,2],
read September 7, 2026. This is not an installation recommendation or a claim
that 8.0.1 is current, secure, installed, or tested. `declared_version` accepts
only bounded numeric `major.minor.patch` syntax; accepting that declaration does
not put any release on a compatibility allowlist. No real producer version or
producer configuration is validated by this slice.

The envelope is a MEGALODON contract, **not a stock Suricata log line**. Its
`event` member is an intentionally narrow EVE alert profile; `source` and
`source_record_index` are separate run context for a future operator-driven
importer. Ordinary EVE output can contain additional fields and will not
necessarily conform. There is no producer filter or scrubbing tool here. Do not
blindly strip forbidden fields to make a mixed or sensitive EVE log pass.

## 2. Input profile

Only TCP and UDP alert events with both endpoint ports are admitted. An unknown
protocol, event type, field, or nested object is a rejection, not a default,
coercion, ignored extension, or partially successful import.

| Input | Contract |
| --- | --- |
| `schema_version` | Exactly `suricata-eve-alert-input-v1` |
| `source` | Engine `suricata`, adapter profile `suricata-eve-alert-v1`, declared version, sensor/run/ruleset IDs, and explicit `operator_declared` version/ruleset provenance |
| `source_record_index` | Integer 1 through 10,000; ordinal in one selected source/run, not a global event identity |
| `event.timestamp` | Explicit offset or `Z`; 0 through 6 fractional digits; no naive timestamp |
| `event.event_type` | Exactly `alert` |
| `event.src_ip`, `event.dest_ip` | Valid IPv4 or IPv6 strings, no zone/scope IDs, both in the same address family |
| `event.src_port`, `event.dest_port` | Integers 0 through 65,535, never booleans, strings, floating-point or exponent tokens |
| `event.proto` | `TCP` or `UDP` |
| `event.alert` | Required `gid`, `signature_id`, `rev`, `severity`, and `action`; optional bounded `signature` and `category` only |

Rule identifiers and revision are integers 1 through 4,294,967,295; native
severity is an integer 1 through 255. These are deliberate **profile limits**,
not a claim about every value an upstream engine or custom rule can emit.
`action` is `allowed` or `blocked`. Optional rule labels are 1 through 160
printable ASCII characters with no control characters, including trailing
newlines. They are transient untrusted rule metadata and MUST NOT enter the
normalized record, a diagnostic, a report, or a dashboard message.

Sensor, run, and ruleset IDs are non-sensitive operator labels of 1 through 64
ASCII letters/digits/underscores/hyphens, beginning with a letter. They are not
paths, URLs, commands, authenticators, rule content, or cryptographic evidence.
A future importer must obtain its run context through a reviewed operator
boundary, not take it from arbitrary EVE extensions. Declared provenance is not
independent verification of the producer, the sensor, or the ruleset.

The closed field sets reject payload/packet fields, HTTP/DNS/TLS objects, file
information, extracted artifacts, arbitrary metadata, capture paths, hashes,
flow/correlation extensions, and verdict objects. Original JSON MUST NOT be
retained or echoed. A future display may generate a fixed local message from
validated numeric rule identity; it must not promote a rule label to attribution.

## 3. Framing and semantic conformance

The test-only conformance examples in `tests/test_suricata_contract.py` specify
these additional gates. They are **not a production reader** and must not be
imported by runtime code.

A logical record is at most **65,536 bytes**, including an optional final LF or
CRLF, and is exactly one UTF-8 JSON value. Embedded physical newlines, a BOM,
duplicate keys at any level, malformed UTF-8/JSON, and container nesting deeper
than **4** are rejected. Numeric tokens must be integers of at most **10 decimal
digits**, excluding the minus sign; floats, exponent notation, NaN and infinity
are rejected before schema validation. This is deliberately stricter than JSON
Schema's mathematical definition of `integer`, which alone admits `1.0` [3].

After shape and IP-format validation, timestamps must be real calendar values
with seconds 00 through 59 and a known offset no greater than +/-14:00.
`-0000` and `-00:00` are unknown-offset forms and are rejected. UTC conversion
must be representable with a year from 1970 through 9999; overflow is rejection.
A normalized timestamp is exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ`. Endpoint address
families must agree; normalized addresses use Python `ipaddress` canonical
string form. Non-global addresses remain valid **observations**, not blocking
target approval. Missing data must never be invented to satisfy these rules.

Schemas cannot enforce run-wide uniqueness, file ownership, permissions,
symlink safety, immutable snapshots, total input size, bounded streaming, or
failure atomicity. These remain mandatory separate design/test gates before a
runtime importer. The ordinal bound does not prove enforcement of a 10,000-record
run limit. No source file is read or processed by a production path in this slice.

## 4. Normalization and action separation

`external-alert-v1` is separate from `PacketEvent`, `FlowRecord`, and the existing
fixed-detector result. Its counted unit is exactly `alert`, not packets, flows,
malware instances, or independent corroborations.

Normalization MUST first validate the entire input, including forbidden-field
rejection, then preserve `source` and `source_record_index` exactly; convert the
timestamp to UTC microseconds; canonicalize both addresses; rename `dest_*` to
`dst_*` and `proto` to `protocol`; and copy only the four bounded numeric rule
fields into `rule`. The fixture pairs specify every output field. A schema-valid
output with different provenance, time, endpoints, rule identity, or action
report is a rejected pair, not successful normalization.

`event.alert.action` becomes **`producer_reported_action`**, never MEGALODON's
`action_status`. Upstream documents distinguish alert action from final packet
or flow verdict [1]. The output must always have:

```json
{"evidence_kind":"signature_match","count_unit":"alert","action_status":"not_attempted"}
```

In particular, producer-reported `blocked` remains `not_attempted` for
MEGALODON. No severity mapping, malware verdict, action request, confirmation,
expiry, command, endpoint, policy object, or execution capability exists here.
The profile does not add an automatic planning or enforcement path.

Repeated alerts may be replays or multiple matches on the same traffic. The
schema intentionally does not claim deduplication, idempotent persistence, or
independent evidence. Source/run/ordinal equality alone is not proof of
non-duplication across runs. A later importer must define run-level identity and
replay behavior before writing any durable store; no content hash is introduced.
Raw addresses and provenance can be sensitive: accepting this local record is
not anonymization, report-sharing approval, or permission for external egress.

## 5. Fixtures, tests, and acceptance boundary

`fixtures/accepted.json` contains three complete input/output pairs, including
IPv6 normalization, offset/day rollover, boundary integers, loopback observation,
and a producer-reported block that does not become a MEGALODON action.
`fixtures/rejected.json` contains data-only mutations of named positive seeds,
with explicit expected schema/semantic/pair rejection layers and fixed codes.
`fixtures/rejected-framing.json` covers raw synthetic parser failures. No
upstream rules, captures, malware samples, or production logs are bundled.

From the repository root, with the existing test extra installed:

```bash
python -m pytest -q tests/test_suricata_contract.py
python -m compileall -q megalodon tests
python -m pytest -ra
```

The focused tests refuse socket creation and subprocess launch, keep schema
resolution local, assert closed objects, and exercise the conformance examples.
Passing them proves these fixtures and guards in the tested environment only.
It does not prove a production ingestion boundary, sensor detection quality,
rule authenticity, compatibility, privacy on arbitrary EVE logs, or deployment
safety. The existing full suite and safe CI smoke checks remain required and
unchanged; green tests are not independent human review.

## 6. Next gate, not enabled by this contract

The schema, fixtures, and tests are present on `main`. Their merge does not
supply the independent review or repository-control evidence still tracked in
issue #3, and it grants no installation, capture, ruleset, or enforcement
authority.

A later, separately authorized change may implement a bounded local importer
after reviewing the source-file/privacy boundary, a pinned supported producer
profile, resource limits, failure behavior, and replay semantics. Installed-tool
compatibility, rule acquisition, local reports, SQLite integration, dashboard
projection, host context, scheduler execution, and response remain out of scope.
Existing dashboard work tracked by issue #7 is not a dependency of this contract.

## References

[1] OISF, Suricata 8.0.1 EVE JSON format, especially alert/action/verdict:
https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-format.html

[2] OISF, Suricata 8.0.1 EVE output configuration and content options:
https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-output.html

[3] JSON Schema, numeric types and integer semantics:
https://json-schema.org/understanding-json-schema/reference/numeric

Repository authority: [SPECIFICATION.md](../../../SPECIFICATION.md) and
[SECURITY_REVIEW.md](../../../SECURITY_REVIEW.md); existing offline implementation
contract: [offline-analysis.md](../../../docs/offline-analysis.md).
These references are documentation; tests do not fetch them.
