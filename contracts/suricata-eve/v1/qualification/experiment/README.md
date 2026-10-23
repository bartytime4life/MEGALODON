# Suricata synthetic fixture-and-oracle packet

Status: **fixtures and oracles supplied; native experiment not run**.

The follow-up [`harness`](harness/README.md) adds deterministic controls and a
standalone opt-in Linux offline runner. It is separate from MEGALODON's EVE
consumer and does not establish native execution or installed acceptance. Its
whole-process PCRE timing observations remain explicitly inconclusive about
algorithmic complexity.

This directory advances two research candidates without launching Suricata. It
contains four independently generated synthetic PCAPs, two dedicated rules, a
candidate minimal configuration, exact artifact hashes, fixed result oracles,
and a fail-closed receipt schema plus deterministic semantic validator. It
original packet contains no Suricata binary, engine output, launcher, downloader, live capture,
interface name, private address, model input, or host-control path.

## Verified facts

- `fixture_source.py` deterministically constructs Ethernet/IPv4/TCP captures
  using only RFC 5737 TEST-NET-1 addresses and locally administered MAC
  addresses. It performs no network or process operation.
- The TLS capture divides the four-byte ClientHello handshake header across
  two TLS records and carries the synthetic SNI `fragmented.example`.
- The PCRE captures contain 32, 64, and 128 completed 512-byte to-server
  segments. A deterministic midpoint ACK advances the advertised receive
  window before the second half, including the final `mc` suffix. The
  dedicated rule uses the PCRE-only expression recorded in the upstream ticket
  8684 fix description; it has no content prefilter.
- `manifest.json` binds the generator, captures, rules, and configuration by
  SHA-256 and fixes all packet counts, byte counts, resource ceilings, and
  oracles.
- `receipt_validator.py` is bound by the manifest. It validates the closed
  schema after verifying its embedded SHA-256, verifies the receipt's packet
  digest against the actual manifest, recomputes the three process-CPU medians,
  checks the two recorded integer ratios against those medians, and enforces
  each 3.0 bound. It has no network, process, or host-control capability.
- `receipt-template.json` validates only as `not_run`. Changing it to `pass`
  is rejected unless an exact producer digest, the baseline version or exact
  candidate ancestry declared by the manifest, verified input hashes, nine
  individually bounded and alert-producing PCRE runs, zero exit, nonempty
  complete output, and both passing oracles are present.

The TLS sticky-buffer syntax is grounded in the upstream Suricata rule guide.
The two upstream engine commits and documentation are linked in the manifest.
No upstream source file or real traffic capture is vendored. The synthetic
artifacts are contributed under the repository's Apache-2.0 license; Suricata
itself is a separately licensed external program and is not redistributed.

## Predeclared oracles

The TLS oracle requires a receipt record for exactly one alert with SID
9900001 and application protocol `tls`. Its interpretation is narrow: the
complete synthetic SNI was available after the split header. It does not prove
general TLS correctness.

The PCRE oracle uses the median process CPU time of three repetitions at each
stream size. Each doubling must remain at or below a 3.0 ratio, each run must
produce at least one SID 9900002 alert and finish within ten seconds, and the
packet/output/address-space ceilings must hold. All nine constituent run
measurements are required in a passing receipt so the claimed medians and
ratios can be independently recomputed. Schema validation alone is not
sufficient for a `pass`; `receipt_validator.py` must also return no errors. The
ratio is a deliberately generous discriminator below the approximately
four-times growth expected from quadratic rescanning. It is an engineering
threshold, not a verified claim about either producer.

## Remaining native hold

The candidate configuration is structurally parsed in repository tests but
has not been accepted by a native Suricata parser. No installed or candidate
binary identity is available. The separate opt-in harness still requires both
binaries bound by SHA-256, independently verified artifact digests, a new
private output directory, and a fixed direct argument vector without a
shell. It must process only one completed local PCAP at a time with one packet-processing thread,
the configuration-bound `single` runmode, no interface, no network, no rule
update, no service, and no watcher. A passing receipt must attest `single` and
exactly one packet-processing thread.

Timeout, output limit, unavailable prerequisite, identity mismatch, nonzero
exit, and oracle failure are explicit non-pass receipt states. Even a valid
`pass` receipt has `acceptance_authority=false`; it cannot establish installed
producer acceptance, deployment safety, capture completeness, rule quality,
operational privacy, release authority, or automatic response authority.
