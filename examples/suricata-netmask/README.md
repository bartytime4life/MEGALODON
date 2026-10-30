# Suricata 8.0.8 netmask-equivalence fixture

Prepared October 30, 2026. **Engine not run; expected results are not observations.**
Upstream target: https://redmine.openinfosecfoundation.org/issues/9171

This independent Apache-2.0 synthetic fixture contains four Ethernet/IPv4/UDP
packets with no application payload, documentation-only addresses, fixed
timestamps, locally administered MACs and valid IP/UDP checksums. No captured
traffic or upstream exploit corpus is included. Both rules are alert-only IP
rules without content matchers. Distinct UDP tuples avoid same-flow suppression.

| Packet | Source | Destination | Expected SIDs |
| --- | --- | --- | --- |
| 1 | 192.0.2.1 | 203.0.113.200 | 9900101, 9900102 |
| 2 | 192.0.2.254 | 203.0.113.200 | 9900101, 9900102 |
| 3 | 198.51.100.1 | 203.0.113.200 | none |
| 4 | 203.0.113.1 | 203.0.113.200 | none |

The oracle requires exactly four alerts as an unordered multiset, not merely
equal counts between rules. Missing, extra or duplicate alerts fail. Expected
semantics come from the intended subnet membership, not an executed engine.

`generate.py` deterministically generates the PCAP, rules, expected matrix and
manifest into a NEW directory only. `test_fixture.py` uses standard-library
unittest to verify committed bytes, packet boundaries, checksums, the matrix
and hashes. Neither script imports or invokes Suricata, sockets or subprocesses.
From this directory, `python3 test_fixture.py` runs preparation checks only.
`python3 generate.py /absolute/new/directory` regenerates artifacts only.

Native validation remains separately authorized. Use an already isolated,
non-root, no-egress environment and a reviewed alert-only EVE configuration.
Bind exact binary, configuration, fixture, rules and validator hashes. Proposed
ceilings in manifest.json must be enforced externally: one processing thread,
10 seconds, 512 MiB address space and 1 MiB output. Timeout, truncation, invalid
checksums, unexpected fields, nonzero exit or unknown prerequisites cannot pass.
No live capture, shell action, service, firewall, model, updater or host control.
There is deliberately no execution runner or authorization receipt here.

8.0.8 is a separate candidate, not a relabeling of admitted 8.0.7 evidence.
Do not modify producer-version gates to admit results. Retain only allowlisted
alert metadata and private receipts; record raw-output hashes separately from
the order-insensitive oracle. Exact binary/dependency licenses, provenance and
native rule/configuration validity remain unverified. A four-packet success
would establish only this case, not general engine safety or detection coverage.
