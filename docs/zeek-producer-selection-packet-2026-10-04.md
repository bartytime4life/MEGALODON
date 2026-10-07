# Zeek conn.log producer selection packet — 2026-10-04

Historical status on 2026-10-04: **candidate for owner decision; NOT_SELECTED / NOT_QUALIFIED**. The owner selected the documented 8.0.10 build on 2026-10-07; its output remains **NOT_QUALIFIED**. Issue [#445](https://github.com/bartytime4life/MEGALODON/issues/445) remains open. The original packet was based on MEGALODON `main@664ee48b2731b38641b68585fb81913ca81285b5`; the 2026-10-07 inventory was read against `main@fce8dc5ba89624c4420f8956d1a02918a667d19a`. This packet changes no importer, schema admission, fixture assertion, service, or host setting.

## Owner choice and read-only inventory — 2026-10-07

The owner selected the documented Zeek 8.0.10 private source build as the one
producer to qualify under #445. Selection does not qualify its emitted output or
authorize Zeek execution. The current read-only inventory found:

- `~/src/zeek-build/zeek-8.0.10.tar.gz` SHA-256
  `dbb1cb6c1eac27a8883ee4bd229a378b2f1253fa18e16cdeaaef8a00f124ddf1`,
  matching the README recipe;
- installed `~/.local/zeek-8.0.10/bin/zeek` SHA-256
  `9a373fa2f32469432273af0c793455af59a34195a88beb9963c8d2e0e648f161`;
- the build `CMakeCache.txt` SHA-256
  `f6a73802a870a526528ddda446669bf73f2e56e0eeb133d3b958e2cfb328ca12`,
  naming the selected private install prefix.

The inventory did not find a retained signature verification transcript or
establish an authenticated archive-to-installed-binary build chain. The checked
source declares `use_conn_size_analyzer = T` by default and marks the four packet
and IP-byte counters optional. Actual loaded scripts and writer settings still
need source-bound evidence.

A pre-existing local `case001` TSV `conn.log` has SHA-256
`fe46f9eeb2f943001da0f2bc557bfb03f4c5204615745d5073620078f2322dd5`.
Its 22-column `#fields`/`#types` header matches the current parser's closed
field table. It contains 27 connection rows: 13 TCP, 11 UDP, two ICMP and one
`unknown_transport`. The parser refuses the entire original as
`UNSUPPORTED_ZEEK_PROTOCOL`; it does not publish a healthy 26-row prefix.
The observed field order is `ts`, `uid`, `id.orig_h`, `id.orig_p`,
`id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`,
`resp_bytes`, `conn_state`, `local_orig`, `local_resp`, `missed_bytes`,
`history`, `orig_pkts`, `orig_ip_bytes`, `resp_pkts`, `resp_ip_bytes`,
`tunnel_parents`, `ip_proto`. The header declares `ts` as `time` and
`duration` as `interval`; these are schema observations, not proof of the
selected executable's writer settings or producer provenance.
A pre-existing filtered copy has SHA-256
`5c109047d64dff5fe8d472a60190b0a0cdebd1c1eb9dc8a6c386a818bfcecca9`
and parses as 26 rows, but is derived input, not native producer output. Its
prior report labels the version `operator_declared_unverified`. The original
capture is not in an owner-private input root, so the direct in-memory parser
readback is not a successful offline file-admission receipt. These observations
do not authenticate which installed binary wrote the log. No corresponding
native JSON `conn.log` was found in that case directory.

The existing synthetic fixtures and placeholder schema remain unqualified. No
Zeek process, live capture, service, database, or host action was started by
this inventory.

Post-review correction: the TSV refusal claim below covers malformed **cell escape syntax**. Zeek's ASCII escaping uses `\xXX` for non-printable bytes and `\\` for a literal backslash ([Zeek 8.0.10 `escape_string` reference](https://docs.zeek.org/en/v8.0.10/scripts/base/bif/strings.bif.zeek.html)). The parser now validates those forms in every cell, including discarded optional fields. It does not decode escaped bytes into field values; producer-specific value parity remains part of #445. The synthetic parser fixtures in `tests/fixtures/zeek_tsv_escape/` are not output from an owner-selected producer and do not satisfy the digest-bound fixture inventory below.

## Historical candidate comparison (before owner selection)

| Decision input | Zeek 8.0.10 | Zeek 9.0.0 |
| --- | --- | --- |
| Repository provenance | The [README private Ubuntu build recipe](../README.md) pins `ZEEK_VERSION=8.0.10`, source SHA-256 `dbb1cb6c1eac27a8883ee4bd229a378b2f1253fa18e16cdeaaef8a00f124ddf1`, primary signing fingerprint `962FD2187ED5A1DD82FC478A33F15EAEF8CB8019`, and signing fingerprint `E9690B2B7D8AC1A19F921C4AC68B494DF56ACC7E`. These are recipe assertions, not proof of the installed binary or its log output. | Named as a candidate in the [placeholder producer scaffold](../contracts/zeek-conn-log/v1/producer/README.md); no equivalent pinned source/build packet or owner-selected field inventory is checked in. |
| Field semantics | The repository already cites the [8.0.10 Conn::Info reference](https://docs.zeek.org/en/v8.0.10/scripts/base/protocols/conn/main.zeek.html) for ICMP and `ip_proto` consistency. | The [9.0.0 Conn::Info reference](https://docs.zeek.org/en/v9.0.0/scripts/base/protocols/conn/main.zeek.html) is a separate candidate. Similar names do not establish identical emitted fields, policies, or package options. |
| Current importer fit | `megalodon/offline/zeek.py` has a closed field table and JSON/TSV import paths. Required packet/IP-byte columns are optional in Zeek's Conn::Info description and depend on the connection size analyzer; the selected build must demonstrate them in actual output. | The same importer constraints apply; no checked-in 9.0.0 output shows parity. |
| Qualification cost | Better supported **candidate** because source identity and a private build recipe are already recorded; actual build fingerprint, emitted JSON/TSV field sets, and owner selection are still missing. | Requires a new exact source/package pin and independent emitted-output evidence before the same qualification tests. |

**The recommendation above preceded the owner's 2026-10-07 selection of the documented 8.0.10 build.** Do not replace `zeek-PLACEHOLDER-UNSELECTED-conn-json-v1` or `0.0.0` merely because the build was selected: output and fixture qualification remain open. The [current scaffold](../contracts/zeek-conn-log/v1/producer/schema.json) and [tests](../tests/test_zeek_producer_contract.py) deliberately retain the placeholder admission contract.

## Contract and measurement decisions

- Pin an exact source release/tag, upstream source archive digest/signature, package origin, configure/CMake options, installed executable path and digest, loaded scripts/plugins, `use_conn_size_analyzer`, ASCII writer settings, and the observed `#fields`/`#types` order for TSV. Record the exact JSON object key set separately. A declared `--producer-version` in a MEGALODON run is currently `operator_declared_unverified`; it does not attest to an executable.
- For JSON, verify the selected writer's `LogAscii::use_json`, optional-field behavior, timestamp format, and whether package policy adds columns. The [ASCII writer reference](https://docs.zeek.org/en/v8.0.10/scripts/base/frameworks/logging/writers/ascii.zeek.html) describes epoch seconds as the default JSON timestamp mode; the chosen configuration and actual output must establish the value and fractional precision. For TSV, retain literal header bytes, `#separator`, `#set_separator`, `#empty_field`, `#unset_field`, `#path conn`, `#fields`, `#types`, and `#close`; do not normalize away a mismatch before testing.
- `ts` is observation time in Unix seconds, with decimal fractional seconds; `duration` is an interval in seconds. `orig_pkts`/`resp_pkts` count packets, `orig_ip_bytes`/`resp_ip_bytes` count IP-level bytes, and `orig_bytes`/`resp_bytes` describe payload bytes. The importer creates **flow** records and sums the two IP-byte fields as its byte count. It must not infer missing counters, transform milliseconds into seconds, or count a flow as a packet.
- The importer requires `ts`, five-tuple fields, `proto`, `conn_state`, and four packet/IP-byte counters. `Conn::Info` documents several as optional, so a normal producer configuration or record with unset counters can be incompatible. Do not claim every standard Zeek log is accepted. Unknown keys (including policy-added `community_id`, `vlan`, or other extensions) refuse with `ZEEK_SCHEMA_MISMATCH`; Community ID remains only a non-authoritative correlation hint.
- JSON uses a closed per-record schema and adapter validation. Duplicate keys and integer-hook errors currently surface as `INVALID_JSON`; schema-valid `proto`/`ip_proto` contradictions fail in the adapter. TSV additionally requires its closed header/type grammar and terminal `#close`. Malformed escape, nonfinite number, missing/invalid time, wrong unit, schema reset, unknown package field, byte truncation, and extra data after close must fail the **whole** import or yield an explicit unavailable/failed receipt, never a healthy accepted prefix. Existing bounded input/line/record limits still apply.

## Prepared change set after the decision and producer evidence

The following paths and cases are the reviewable implementation inventory, **not** an assertion that the data has been captured:

1. Replace the two placeholder admission constants and comments in `contracts/zeek-conn-log/v1/producer/schema.json` with an owner-selected exact profile/version and digest-bound provenance. Keep the parser field allowlist closed; if observed selected output needs any added field, review its type, privacy and interpretation before changing `TYPES` or the schema.
2. Replace synthetic JSON cases in `fixtures/accepted.json` and `fixtures/rejected.json` with a minimized, digest-linked packet derived from the same declared build. Keep raw private source bytes and their custody/digest outside public fixtures; use documentation-safe addresses only in checked-in examples. Preserve explicit IDs, expected error codes, and schema-valid-but-adapter-rejected exceptions.
3. Add `fixtures/accepted.tsv` and `fixtures/rejected-*.tsv` with exact header/body/close bytes. Include a valid minimal TCP/UDP/ICMP sample when emitted, absent optional counters, unknown `#fields`, mismatched `#types`, missing/duplicate header, malformed escape, wrong timestamp units, missing `#close`, truncated row, post-close data, and a header reset. Some cases are parser mutations of a producer output, not claims that Zeek emitted malformed data.
4. Extend `tests/test_zeek_producer_contract.py` to bind fixture digests and declared source identity, exercise JSON through `json_object` then `parse_flow`, and TSV through the actual bounded file/replay path under a private non-root fixture environment. Assert complete success or named finite refusal and no partial report. Verify input bytes are unchanged and no socket, live capture, Zeek process, service, watcher, model, database writer, or host action is reached. Keep the installed-producer parity lane marked `NOT_RUN` until separately executed and recorded.
5. Update the producer README and currentness document only after exact-head fixture/schema tests pass. Preserve the historical placeholder packet as history and state the exact selected field inventory, source digests, test head, independently reviewed limitations, and owner disposition.

| Fixture group | Expected boundary |
| --- | --- |
| JSON and TSV known-good from the selected build | Same normalized flow fields and timestamp microseconds, with exact provenance and source bytes accounted for |
| Unknown/package-added field | Explicit schema mismatch, with no silently dropped enrichment |
| Missing optional-but-importer-required count | Deterministic refusal; no invented zero or healthy report |
| Invalid epoch, milliseconds used as seconds, negative or nonfinite interval/count | Time/unit or typed-field refusal |
| Malformed JSON escape/duplicate key, TSV header drift, truncation/missing close | Finite failure with no published accepted prefix |
| `ip_proto` contradiction, IPv4/IPv6 ICMP type/code mismatch | Explicit incompatibility; no transport-port comparison from ICMP |
| Input mutation, limit/deadline exhaustion | Refusal with unchanged source; report completeness not inferred |

## Outstanding decision and proof

The owner selected the documented 8.0.10 build. The installed binary and a pre-existing TSV capture were inventoried read-only, but their producer relationship is unauthenticated. No native JSON capture was found in the case directory or the bounded Analysis/Projects/Documents filename search; files in test temporary directories are synthetic and do not supply producer evidence. The positive/negative JSON and TSV fixture packet is therefore `NOT_RUN`, as is installed-producer parity: no Zeek executable was launched, no package was installed, and no selected-build output was generated. The current synthetic contract tests prove importer consistency only. Independent exact-head review must examine timestamps, emitted optional fields, package additions, privacy, deterministic failure, and source custody before #445 can be accepted. Installation, background sensor operation, network access, release, deployment, and host authority require separate decisions.
