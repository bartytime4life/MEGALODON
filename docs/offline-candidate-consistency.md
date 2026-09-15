# Candidate support in offline dashboard summaries

At inspected main `ccc7b5a8ef7912d31fb076ccd030d7074d6bfd2c`, the offline
dashboard validated each candidate's shape and run-level count independently.
A candidate could therefore name a port absent from the same run's baseline,
claim more observations than that port contained, or be duplicated to inflate
the displayed candidate count. A complete manifest did not resolve these
contradictions.

The dashboard now checks the entire candidate list against the full validated
baseline before returning any summary. The twelve-port display limit is applied
only to presentation; support checks use every accepted destination port.

| Candidate | Required aggregate support |
| --- | --- |
| NEW_DESTINATION_PORT | Its protocol/port exists and its record count equals the baseline's complete count for that pair. |
| REGULAR_INTERVAL | The sum of unique observations across distinct source/destination groups for a protocol/port cannot exceed its baseline count. |
| PORT_53_BURST | The sum across source groups in each relative minute cannot exceed that minute's count; the total across all bursts cannot exceed TCP/UDP destination-port-53 records. |

Candidate identities are unique within a rule: protocol/port for new ports,
source/destination/protocol/port for regular intervals, and source/minute for
port-53 bursts. Equivalent numeric representations do not bypass uniqueness.
Host rank labels must be between one and twice the admitted record count.
Counts are accounted within each rule; the same observation may legitimately
support a new port, regular interval and burst at the same time.

The existing `INVALID_OFFLINE_CANDIDATE` refusal prevents the complete snapshot
from being published. No partial successful list, warning-only fallback,
automatic edit, or deletion of source reports occurs. Output shape, privacy
projection, size limits, file reads and startup-only behavior stay the same.
Correct contradictory exports from their source evidence, not by changing
counts merely to satisfy the validator.

## Source basis and remaining limits

This follows the supplied Advancement Blueprint's evidence-integrity and
unit-preservation requirements and the Command Center Blueprint's comparable
read model and honest degraded states. The statistical/AI references reviewed
in [the 24-document decision record](document-review-2026-09-15.md) support
checking the evidence before interpretation. The Repository Research Analysis
Framework guides tracing the actual input-to-consumer path; its placeholders
are not repository evidence. No source text or executable book example is
redistributed.

These are necessary consistency checks, not re-analysis of individual records.
The dashboard still does not read `records.jsonl` or `records.csv` contents.
It cannot verify host-label membership, actual cadence, membership of records
in an absolute capture window, or whether a claimed port was absent from a
reference that is not included in the report set. Consistent fabricated files
can still pass. Producer authenticity, atomic multi-file snapshots and detection
accuracy remain separate questions.

Tests use generated private report sets and then make bounded synthetic
contradictions. They cover per-row and cross-row overclaims, absent ports/minutes,
duplicate identities, host-rank bounds, successful same-rule groups and
cross-rule overlap, ports beyond UI truncation, unchanged report bytes and
continued exclusion of source addresses/candidate details from the projection.
No model invocation, network access, sensor operation, database migration,
detector threshold, host action or dependency is introduced.
