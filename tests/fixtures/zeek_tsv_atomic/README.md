# Synthetic TSV atomic-failure fixture

Evidence level: **▽ Synthetic**. `mixed-protocol.tsv` is fabricated test data
using documentation-range IPv4 addresses, invented identifiers, fixed times,
and invented counters. It contains 13 TCP, 11 UDP and two ICMP connection rows,
followed by one `unknown_transport` row and a closing header. No bytes were
copied from a native capture or the filtered native log.

SHA-256: `eb66f58142f8a2f2dd033b1f55e7ad67896d3085f2d6343c82481b0172d58739`.
The test pins this synthetic fixture's integrity; this is not producer provenance.

The row counts reproduce the failure shape recorded in merged [PR #519](https://github.com/bartytime4life/MEGALODON/pull/519).
`tests/test_zeek_tsv_atomic.py` first proves that the 26-row synthetic prefix
parses and produces reports with `operator_declared_unverified` version basis.
It then checks the complete file through both `zeek.replay()` and the actual
offline CLI/report path: `UNSUPPORTED_ZEEK_PROTOCOL`, zero accepted records,
and only a failed manifest, with unchanged input bytes and file identity.

Additional finite controls cover a missing closing header, a truncated terminal
row, a reader `OSError`, and `KeyboardInterrupt` after all valid rows. The
interrupt propagates and leaves an empty output directory without a manifest or
success summary. DNS, sockets, subprocesses, host command/signaling entry points,
database connections and background thread/process starts are tripwires; allowed
report writes are inspected. The Linux privilege precondition is stubbed, as in
the existing offline tests. This is path-level synthetic evidence, not native
OS containment, operational sensor loss/asymmetry or a whole-host no-I/O claim.

The owner-selected private **Zeek 8.0.10** build and the historical inventory
remain recorded in [the producer selection packet](../../../docs/zeek-producer-selection-packet-2026-10-04.md).
The test's `8.0.10` argument is an unverified operator declaration. It does not
bind that build to a log, replace the placeholder producer schema/fixtures,
or qualify native JSON or TSV output. [Issue #445](https://github.com/bartytime4life/MEGALODON/issues/445)
remains open: authenticated producer-to-log provenance, the native digest-bound
JSON/TSV qualification packet, exact-head independent review and separate owner
acceptance/disposition remain held. No Zeek, Qwen, live interface, service,
package installation or host-control operation is needed to run these tests.

```bash
python -m unittest discover -s tests -p test_zeek_tsv_atomic.py -v
```
