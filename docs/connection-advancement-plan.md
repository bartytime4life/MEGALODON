# Local command center: connection advancement plan

Status: **PROPOSED architecture and acceptance sequence**, not a runtime integration
or source-admission decision. Prepared 2026-09-11. This plan complements the
separate [Reference Library recovery candidate in PR #91](https://github.com/bartytime4life/MEGALODON/pull/91);
it neither incorporates that code nor claims its behavior is on main. It does not
install, connect, scan, capture, acknowledge, notify, or apply anything.

## Design decision

Advance connections through **completed local evidence first**, not through a
catalog that executes tools. Keep the existing static Integration Map useful as
a description of documented workflows. Add a runtime connection only after its
input, ownership, lifetime, privacy, failure, and read-model contracts are
separately reviewed and executable. The two MEGALODON blueprints support this
sequence: evidence integrity and resource containment precede broader adapters;
file import precedes local read connectors; active control remains a separate
future product phase. [1, 2]

A useful operator interface must distinguish three questions:

| Question | Evidence required | Current interpretation |
| --- | --- | --- |
| Is this capability implemented? | Repository code and its tests | The static map can describe it |
| Is evidence from this source actually loaded? | A source-qualified accepted run/receipt and read projection | Cannot be inferred from catalog presence |
| Is any operation authorized or running? | Explicit operator authority and execution/terminal receipt | No dashboard control or catalog label can establish it |

Do not collapse these into one green “connected” light. A program might be
installed but unsupported; a completed imported report might be available while
its producer is absent; a local API might respond while evidence is stale. The
interface should display exactly the claim backed by the relevant read model.

## Preserve the existing trust kernel

The first integration should reuse the project's bounded validation and receipt
principles without widening `PacketEvent` into a generic dictionary. Packet,
flow, alert, inventory, and vulnerability units remain distinct. A source count
is not a packet count. A source's severity is not automatically MEGALODON's rule
severity, and neither is action authorization. [1, 2]

Capture producer cleanup and CLI ownership are separate work. A reference UI
recovery button does not fix asynchronous sniffer death, stop/join deadlines,
kernel loss accounting, resource-pressure ingestion, or persistence boundaries.
Do not mix those changes into a connection-card implementation merely because
they share the word “health.” The current resource work remains associated with
issue #68; eligible review remains controlled by issue #3. [3]

## Phase A: accepted-run presentation before a new connector

**Proposed smallest read-model slice:** expose one already recorded source run,
using the existing read-only store seam, with a closed response schema and
synthetic failure fixtures. Begin with source unit, adapter identity, accepted
and rejected counts where actually stored, terminal state/reason, and explicitly
qualified time fields. Do not invent fields by deriving them from a label or by
substituting the current time.

Acceptance must establish an existing compatible database, one bounded read,
no writer construction, no migration, no telemetry ingestion, and no filesystem
browser. A missing field is `not_recorded`, not a fabricated zero. A running or
orphaned record is not success. The response must carry a cardinality and byte
ceiling and distinguish unavailable from an empty successful result.

The browser should consume that response independently of the static map. Its
panel needs initial, loading, available, unavailable, malformed, and stale states;
it must identify the last successful run and preserve the original time basis.
A successful fetch proves only that the read endpoint responded with accepted
content—not sensor liveness, source completeness beyond the receipt, or effective
protection. Use synthetic records until that boundary is reviewed.

## Phase B: one bounded completed-file reader

The first runtime sensor family should remain the already contracted Suricata
EVE alert subset, not a broad multi-tool import framework. That choice leverages
existing schema and negative fixtures. It does not permit a generic EVE firehose,
payload fields, live tailing, IPS, sensor management, or launching Suricata. [1, 2]

The reader's unit is an alert. Accept one operator-selected existing private
regular file using a fixed versioned input contract. Its scope must include
framing, exact allowed fields, maximum line/file/record sizes, safe file identity,
finite processing, producer version basis, partial-final-record handling, and a
truthful terminal receipt. Unknown keys and unsupported event types must not be
silently passed through or interpreted as successful clean traffic.

Before persistence, decide the batch semantics explicitly. A malformed suffix
must not create a completed receipt for an unread file. A prior committed prefix,
where the selected contract allows one, must remain distinguishable from a
complete batch. An uncertain commit cannot be blindly retried. A later dashboard
projection must not collapse different source units into a shared total.

Required negative controls include path replacement, symlink/device/FIFO input,
identity changes while reading, oversized lines, excessive nesting, forbidden
payload/body/hash fields, duplicate keys, invalid timestamps, record-limit stop,
truncation, interruption, storage failure, and replay ambiguity. Tests must deny
socket/DNS/subprocess activity in the importer. Installing a producer or observing
a green parser test is not installed-tool compatibility evidence.

## Phase C: source-qualified integration receipts

Every later integration proposal should answer this minimum record specification
before implementing a connection button or a new data store:

| Group | Required meaning |
| --- | --- |
| Identity | Versioned adapter/contract; record unit; run ID; producer name and version basis |
| Input | Explicitly selected bounded local input; private identifier, not a public raw path |
| Time | Observed time, ingestion time, completion time, and their respective provenance |
| Counts | Accepted, rejected, omitted, partial, duplicate, and unknown counts only when supported |
| Integrity | Descriptor-bound input identity and change checks, byte size, framing/completeness, parser/contract identity, verified versus asserted provenance; no raw-input or payload-derived hash |
| Privacy | Allowed fields, removed/rejected fields, display/export policy, and known limitations |
| Completion | Exact terminal state/reason; uncertain outcomes remain uncertain |
| Authority | No action attempted unless a separately authorized action path produced its own receipt |

This is a documentation checklist, not a new schema version. Do not allocate a
competing migration or promote an unstored field to “implemented.” Use the live
specification and existing schema as the authority when designing each slice.
The integrity checklist deliberately does not hash captured or imported raw
bytes: raw input may contain forbidden payloads or secrets. Bounded descriptor
identity/change checks are not an atomic filesystem snapshot. Hashes of separately
reviewed public reference artifacts and synthetic fixtures remain a different,
existing integrity mechanism; they do not authorize hashing raw telemetry.

## Phase D: investigations without execution authority

Once accepted runs are visible, add small, source-qualified investigation pivots:
select an exact run; compare compatible windows and units; inspect why a record
is partial; explain a fixed rule; reveal reference registration context without
mutating the finding. Avoid a dashboard-wide “scan,” “connect,” “fix,” or “block”
button. That vocabulary promises control the MVP deliberately does not expose.

Filters should apply to an explicit bounded returned set or a reviewed server
query grammar. The interface must disclose which applies. Changing filters must
not silently change source authority, stored data, or the selected run. A saved
view is configuration, not evidence, and its persistence needs its own reviewed
scope. Cross-source links must keep their derivation and uncertainty visible;
shared addresses alone do not prove identical assets or duplicate observations.

For alerts, keep the existing high/critical stored-count signal honest. A count
increase is not a unique incident. A future durable alert lifecycle or outbox
requires its own identity, deduplication, ordering, retries, acknowledgement,
privacy, and delivery contract. Do not disguise browser notifications or a
background notifier as a styling improvement.

## Documentation and packaging obligations

For every implemented slice, update its operator runbook, HTTP/input contract,
known limitations, and test commands together. Add compact source-qualified
examples using synthetic metadata, not private captures or cloud-synced output.
A package must include the runtime asset and the source distribution must retain
its regression fixtures/harnesses. Verify the installed package outside the
checkout rather than only importing from a developer tree.

The [Reference Library recovery candidate in PR #91](https://github.com/bartytime4life/MEGALODON/pull/91)
is one pattern: a bounded
contract, exact query identity, visible provenance, request guards, explicit
recovery, text-only rendering, failure classification, and documented verification
limits. Reuse those principles, not the IANA-specific constants, in another
source panel. A rejected response is a failure, not proof of malicious input.

## Gate sequence and ownership

| Gate | Owner/evidence | Advancement condition |
| --- | --- | --- |
| Current baseline | Repository source, open PR comparison, exact commits | No overlapping stale patch or unreviewed schema assumption |
| Contract | Source owner and security/privilege review | Closed schema, source unit, provenance, bounds, and negative fixtures |
| Implementation | One `agent/*` draft | No hidden execution, storage widening, egress, or automatic integration |
| Local checks | Supported development environment | Compile, focused/full tests, byte/readback checks, safe smokes |
| Hosted checks | Exact-head jobs and logs | Actual results recorded; failures and skips classified |
| Native acceptance | Prepared authorized platform | Browser and installed-tool/runtime behavior actually exercised |
| Independent review | Eligible reviewer under #3 | Review applies to exact current head; CI is not approval |
| Release/deployment | Explicit separate authority | No release or host operation follows automatically from a merge |

No date substitutes for these gates. Resolve the current delivery's independent
review and browser acceptance first. The next implementation after that should
be the smallest truthful accepted-run projection, while resource/cleanup work
continues in its own issue-owned slices. Runtime integration expansion must wait
for the relevant trust-kernel gates or remain explicitly release-excluded.

## Sources and currentness

1. User-provided *MEGALODON Advancement Blueprint*, especially the evidence-first architecture, Phase 2B resource work, and phased integration/release gates. Its repository snapshots are historical.
2. *MEGALODON Local Command Center Integration Blueprint*, [Drive coordination source](https://docs.google.com/document/d/1cSJaOGFF9b_J0LJ7gswnQvwTtWnPcodg3GN_gTU5yk0/edit), especially file-import-first, local read-only UI, distinct units, and staged adapters. Proposed routes and tooling in that blueprint are not current implementation.
3. [MEGALODON at the delivery base](https://github.com/bartytime4life/MEGALODON/tree/f6df35421798b0eb6b1931b9ebc38a1407349eb1); [issue #3](https://github.com/bartytime4life/MEGALODON/issues/3); [issue #68](https://github.com/bartytime4life/MEGALODON/issues/68). Refresh live state before action.
