# Automation contract v1 fixtures

**Status:** normative draft data contract; no scheduler or execution implementation.

This directory is the dependency-closed Stage 0 slice described by
[`docs/automation-contract.md`](../../../docs/automation-contract.md). The schema
defines three inert JSON shapes:

- `draftCreate`: the minimum create-time payload; it does not activate anything.
- `activatedDefinition`: the fields a future activation boundary must resolve.
- `runSnapshot`: the immutable-by-contract input record a future ledger would preserve.

The fixtures and tests establish field names, enums, size limits, UTC run
timestamps, explicit schedule zones, bounded policies, and the empty
`requested_actions` boundary. They do **not** implement RRULE occurrence
calculation, DST resolution, persistence, claiming, retries, model invocation,
output publication, a CLI/API, or any scheduler loop.

Policy capabilities are a closed allowlist of metadata observation, permitted
local-fixture reads, and local report writes. Network and firewall access are
constant `false`. There is no arbitrary command, path, endpoint, or tool field.

JSON Schema can enforce structural constraints but is not the future recurrence
parser. Full RFC 5545 canonicalization, rule-part uniqueness/density checks,
DTSTART alignment, IANA-zone resolution, DST behavior, and idempotent database
claims remain later, separately reviewed stages.

## Fixture format

Each file is a small harness envelope:

```json
{"schema": "draftCreate", "value": {...}}
```

Files under `fixtures/accepted` must validate. Files under
`fixtures/rejected` must fail validation. Rejected fixtures are named for the
boundary they prove and are never execution inputs.
