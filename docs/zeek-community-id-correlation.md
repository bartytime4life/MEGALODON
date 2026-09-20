# Zeek Community ID grouping hint

Status: adds a pure, offline Community ID v1 implementation and a read-only
cross-source correlation index. Advances
[issue #258](https://github.com/bartytime4life/MEGALODON/issues/258); keep it
open. This is not the closed multi-profile Zeek producer qualification packet,
a schema-drift fixture set, or an owner-approved producer version decision —
those remain separate, unaddressed parts of #258's bounded scope.

## What this adds

[`megalodon/offline/community_id.py`](../megalodon/offline/community_id.py)
computes the published [Community ID v1](https://github.com/corelight/community-id-spec)
string for a `FlowRecord` already accepted by the existing Zeek `conn.log`
importer (`megalodon/offline/zeek.py`), and a `correlate()` function that
groups `FlowRecord`s sharing a Community ID across independently supplied
`Batch` objects (for example a Zeek batch and a Suricata EVE batch).

Neither function launches Zeek, reads a file, contacts a network, mutates the
SQLite store, or grants detection/action authority. `correlate()` never
mutates, reorders, or merges the `Batch`/`FlowRecord` objects it is given; it
only reads already-validated fields and returns a new, derived index.

## What a shared Community ID does and does not mean

A shared identifier means two records hash the same normalized 5-tuple
(source/destination address, source/destination port, transport protocol)
under the same seed. It is:

- **not** identity, attribution, or proof that two records describe the same
  real connection;
- **not** deduplication proof — independent observations of the same flow
  from two vantage points can legitimately show different packet/byte counts
  or connection states without changing the identifier, and this is exercised
  as a positive case (`test_capture_loss_does_not_change_identity`);
- **not** NAT-aware — an address rewritten between two vantage points changes
  the hash, so translated and pre-translation legs of the same real
  connection will *not* correlate (`test_nat_translation_breaks_correlation`);
- **not** an action or detection trigger. `correlate()` reports
  `"action_status": "not_attempted"` and performs no network access.

## Scope: TCP and UDP only

The reference algorithm remaps ICMP type/code pairs through a request/reply
table (defined by the reference implementation, mirroring Zeek's own ICMP
handling) before hashing. This module does not implement that table. Rather
than guess at an unverified mapping, `community_id()` fails closed with
`OfflineError('COMMUNITY_ID_UNSUPPORTED_PROTOCOL')` for any protocol other
than TCP or UDP, and `correlate()` counts such records under
`excluded_unsupported_protocol` instead of raising. ICMP support, if ever
added, needs its own vector-qualified change.

## Test vector provenance

[`tests/test_community_id.py`](../tests/test_community_id.py) checks the
implementation against literal TCP (IPv4 and IPv6) and UDP (IPv4) vectors at
seed 0 and seed 1, reproduced as constants from the
`corelight/community-id-spec` repository's `baseline/baseline_deflt.json` and
`baseline/baseline_seed1.json` reference fixtures — the same dataset
third-party consumers such as Suricata's `community_id` EVE field cite. These
values were retrieved over HTTPS during development and are pinned here as
literal test constants; this repository does not re-fetch them at test time,
and their retrieval was not independently re-verified against a locally built
copy of the reference tool. Every vector is checked in both flow directions to
confirm the ordering rule produces one identifier per flow regardless of which
side is treated as source.

## Reproduction

```bash
python -m compileall -q megalodon tests
python -m pytest tests/test_community_id.py tests/test_offline.py
```

## What remains before #258 is addressed

- Pin one or more owner-approved Zeek `conn.log` producer profiles (for
  example a qualified 8.0.10 build) as a closed, versioned schema-drift
  fixture packet; this change does not adopt or reference a specific
  producer version.
- Add the unknown-field, package-schema-drift, timestamp, unit, and
  truncation fixture cases the issue calls for.
- Decide whether and how `correlate()` output is surfaced through the
  existing offline CLI/report contract (`megalodon/offline/__main__.py`,
  `megalodon/offline/reports.py`); this change intentionally leaves that
  wiring, and those files, untouched.
