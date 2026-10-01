# Compact packet history

MEGALODON's managed capture records packet metadata, not packet payloads or PCAP files. At the measured October 1 rate, packet rows occupied more than 99% of the managed store. The existing Home policy remains **14 days maximum and 20 GiB total**. The age is an upper limit; traffic and the cap determine actual coverage.

## Automatic lifecycle

1. Ordinary observations continue to be evaluated immediately and committed through Balanced recording. Findings and action receipts keep their prompt-commit behavior.
2. A background worker reads only a **closed** packet segment. In bounded transactions it writes five-minute **directional** conversation fragments keyed by interface, source/destination IP and port, and protocol. Each fragment carries first/last observation time, packet count, byte count and original event range. Source identity remains explicit.
3. The worker also copies every linked detector finding with its original event, every action record, and every ingestion-run receipt into the compact segment. The batch checkpoint commits atomically with its derived rows. Interrupted builds resume from the committed cursor.
4. The worker verifies packet count, byte total, finding count, action count, run count, SQLite integrity and source relationships. The original packet segment remains protected until the compact segment closes and its catalog relationship is saved. If the derived file is not smaller, it is discarded and the original remains under the existing policy.
5. At the existing capacity or age limit, verified packet detail is the first capacity candidate. Its compact history and saved evidence have later capacity priority. All managed categories still share the cap and age maximum; none is guaranteed 14 days.

Daily and on-demand reports use one qualified representation per source segment. Once a compact copy is verified, reports use that copy instead of adding its counts to the original packet rows. Boundary-crossing five-minute fragments are excluded from selected-range totals and identified as a coverage limit. Packet and Zeek/Suricata flow totals remain separate. Individual packet fields cannot be reconstructed after detail rotates.

The Evidence tab shows separate time bounds for packet detail and compact conversation history, plus the amount of verified detail actually reclaimed. The gross write-growth estimate is labeled as a pre-compaction benchmark; it is not a forecast of compact-history duration. Actual tier coverage is authoritative. Failed conversion is visible and can pause recording rather than silently remove uncertain evidence.

## Sizing and limits

One read-only local sample of a closed segment contained **49,941 packet records** and **704 distinct five-minute conversations**. The implementation's 1,024-event batch grouping would create **1,076 summary fragments**, or about **46 packet records per fragment** in that sample. This is a row-count measurement, not a guaranteed disk-size reduction or a claim about future traffic. High-cardinality sources can compress less and may remain in original form.

After activating the local service, its first completed live conversion occupied **913,408 bytes** for the compact segment versus **12,619,776 bytes** for its original packet segment, including present SQLite sidecars: about **92.8% smaller for that one segment**. Independent read-only checks matched packet, byte, finding, and action counts, and SQLite quick-check passed. The original remains present until normal age or capacity rotation; this is not yet a reduction in total occupied storage. Other segments can compress differently.

The first rollout does not shorten the configured retention period or delete current evidence merely because a summary was prepared. It saves space as the existing 20-GiB/14-day rotation reaches a verified packet segment. A failed or incomplete build retains its source. The one-time backfill writes new summary segments, so short-term storage can rise before any raw detail rotates. Keep at least the existing admission and free-disk reserves during backfill.

## Validation

`tests/test_packet_compaction.py` exercises verified counts and byte totals, findings/actions/run receipts, report deduplication before and after raw rotation, high-cardinality fallback, and interrupted-build restart. Existing storage and reporting tests cover age/cap eviction, file identity, readers and report boundaries. Rendered browser acceptance remains a separate gate.
