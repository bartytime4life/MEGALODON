# Zeek conn.log producer profile — PLACEHOLDER scaffold, not a qualified profile

Status: **Scaffold only.** This directory is a stand-in structure for the
producer-profile and schema-drift evidence that
[issue #327](https://github.com/bartytime4life/MEGALODON/issues/327) asks
for. It does **not** close #327, does not select a supported Zeek producer,
and must not be cited as evidence that one has been qualified. Every
identifier in [`schema.json`](schema.json) that looks like a version or
profile name (`zeek-PLACEHOLDER-UNSELECTED-conn-json-v1`, declared version
`0.0.0`) is a deliberately unmistakable placeholder, not a real Zeek release.
Earlier planning mentioned Zeek 8.0.10 and 9.0.0 as candidates; #327 selects
neither, and neither is referenced here.

This mirrors the structural shape of the existing, actually-qualified
[Suricata raw-EVE producer profile](../../../suricata-eve/v1/producer/README.md)
(a `schema.json` plus `fixtures/accepted.json` and `fixtures/rejected.json`)
so that replacing the placeholder with a real owner-selected profile later is
a content change, not a new contract shape.

## What is scaffolded here

- [`schema.json`](schema.json): a per-record JSON Schema (`connJsonRecord`)
  covering the same field set as the already-implemented
  [`megalodon/offline/zeek.py`](../../../../megalodon/offline/zeek.py)
  parser's `TYPES`/`REQUIRED` tables, plus a placeholder `admission` block
  naming the stand-in profile/version.
- [`fixtures/accepted.json`](fixtures/accepted.json): synthetic conn.log-shaped
  JSON records that are schema-valid and that the real
  `megalodon.offline.zeek.parse_flow` /
  `megalodon.offline.zeek.json_object` pipeline actually accepts.
- [`fixtures/rejected.json`](fixtures/rejected.json): negative cases for an
  unknown/package-added field, a missing required field, an unsupported
  protocol value, a declared-protocol/`ip_proto`-number unit mismatch, a
  non-printable field, a wrong-typed boolean field, an out-of-range port, a
  negative count, and a non-numeric timestamp. Each names the exact
  `megalodon.offline.common.OfflineError` code the real adapter raises for
  it, not just "invalid." One finding from building this scaffold: a bad
  numeric literal caught during `json_object`'s own decode (for example a
  negative count, or a duplicate key caught by its object hook) surfaces as
  the single collapsed `INVALID_JSON` code, not the more specific code that
  fired internally — `json_object` catches every `ValueError` raised while
  `json.loads` runs, including its own hooks'. A value that instead survives
  JSON decoding and is only rejected by `parse_flow`'s later field checks
  (for example an out-of-range port, or a non-numeric timestamp) keeps its
  specific code. Both behaviors are asserted by name in the test harness.
- [`tests/test_zeek_producer_contract.py`](../../../../tests/test_zeek_producer_contract.py):
  validates every fixture against the schema **and** re-parses it through the
  real `zeek.json_object`/`zeek.parse_flow` pipeline (the same call sequence
  `zeek.replay()` uses for the `json` format), so a fixture cannot pass by
  being schema-shaped alone while the real parser would behave differently.

## Deliberate scope limits

- **TSV is not covered.** `zeek.py`'s `_tsv_records` path has its own header
  grammar (`#separator`, `#fields`, `#types`, `#close`, …) that a per-record
  JSON Schema cannot express. A TSV fixture set needs its own scaffold, not a
  JSON Schema reuse.
- **Duplicate-key and truncation drift are not fixture-file cases.** A
  duplicate top-level JSON key cannot survive round-tripping through Python's
  own `json` module as a dict fixture — the second value silently wins before
  a test ever sees it — so that case is exercised directly against raw text
  in the test file instead. Byte-level truncation and the input/record/line
  size ceilings are already covered by `tests/test_offline.py` against
  `megalodon/offline/common.py`; this scaffold does not duplicate that
  coverage.
- **Cross-field unit consistency is only partly schema-expressible.** The
  `ip-proto-protocol-unit-mismatch` fixture is schema-valid by itself (a
  per-field schema cannot see that the declared transport protocol and the
  numeric `ip_proto` disagree) but the real adapter still refuses it. The
  fixture and test harness both say so explicitly (`"schema_valid": true` and
  a `"note"` field) rather than silently passing an ineffective check.
- **Community ID grouping is a separate, already-delivered concern.** See
  [`docs/zeek-community-id-correlation.md`](../../../../docs/zeek-community-id-correlation.md)
  and [`megalodon/offline/community_id.py`](../../../../megalodon/offline/community_id.py)
  for the pure, non-authoritative grouping hint; this scaffold does not
  change or depend on that code.

## What remains before #327 can close

- An owner-selected exact Zeek producer version, build/package
  configuration, and field set — replacing every placeholder identifier in
  `schema.json` with the real one.
- Real positive and negative JSON **and TSV** fixtures captured against (or
  reviewed against the documented output of) that exact selected build, not
  synthetic records shaped to match the existing parser's own expectations.
- The package-added-field and schema-drift cases re-validated against that
  exact producer's actual optional/vendor fields, which this placeholder
  cannot anticipate.
- Installed-producer parity, NAT/asymmetry/loss behavior, and CLI/report
  integration evidence, per the issue's stated remaining scope — none of
  which this scaffold attempts.
- Exact-head owner or independent disposition before any M02 closure claim.

## Authority boundary

This scaffold adds no Zeek installation, launch, service management, network
feed, database mutation, firewall action, remote API, release, or deployment
authority. It does not change `megalodon/offline/zeek.py`,
`megalodon/offline/community_id.py`, or any other runtime code. Passing these
tests proves internal consistency between a placeholder schema, placeholder
fixtures, and the existing parser; it proves nothing about an installed Zeek
producer.
