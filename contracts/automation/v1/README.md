# Automation contract v1

**Status:** normative draft, data-only Stage 0 contract. No scheduler, runtime
adapter, persistence layer, model invocation, or execution authority is
implemented here.

This directory is the first dependency-closed slice of the proposed
[MEGALODON automation design](../../../docs/automation-contract.md). It defines
bounded JSON shapes and deterministic conformance fixtures without changing the
MVP service, SQLite schema, dashboard, offline analyzer, or firewall boundary.

Validation means only that a JSON value satisfies this draft structural
contract. It does not activate a schedule, prove that a recurrence is
semantically valid, resolve a model or folder, execute a prompt, publish output,
or authorize any host or network action.

## Directory contents

| Path | Purpose |
| --- | --- |
| [`schema.json`](schema.json) | JSON Schema Draft 2020-12 definitions |
| [`fixtures/accepted/`](fixtures/accepted/) | Small values expected to pass the named definition |
| [`fixtures/rejected/`](fixtures/rejected/) | Negative boundary examples expected to fail |
| [`../../../tests/test_automation_contract.py`](../../../tests/test_automation_contract.py) | Schema, fixture, and closed-authority regression tests |

The schema contains three externally useful data shapes:

- `draftCreate`: a minimum create-time request that remains inert;
- `activatedDefinition`: a fully resolved definition shape for a future
  activation boundary;
- `runSnapshot`: an immutable-by-contract record a future ledger could preserve.

Supporting definitions provide the RRULE string boundary, logical identifiers,
UTC timestamps, and the closed execution-policy object.

## Contract overview

### `draftCreate`

| Field | Required | Structural boundary |
| --- | --- | --- |
| `name` | Yes | 1–120 characters; not blank; no leading/trailing whitespace or ASCII control characters |
| `prompt` | Yes | 1–16,384 characters |
| `rrule` | Yes | 10–512 characters; uppercase restricted RRULE shape |
| `model_id` | No | 1–128 character logical identifier; not a URL or command |
| `folder_id` | No | 1–128 character logical identifier; not a filesystem path |

Omitting `model_id` or `folder_id` from a draft does not resolve a default. A
future activation boundary must resolve and authorize both identifiers before
producing an `activatedDefinition`.

### `activatedDefinition`

Every field is required and unknown fields are rejected.

| Field | Structural boundary |
| --- | --- |
| `id` | Logical identifier |
| `name`, `prompt`, `rrule` | Same bounds as the draft shape |
| `dtstart` | JSON Schema `date-time` string |
| `schedule_timezone` | `UTC` or a bounded slash-qualified zone-shaped string |
| `dst_policy` | `reject`, `skip`, `shift_forward`, `fold_earlier`, or `fold_later` |
| `model_id`, `folder_id` | Required logical identifiers |
| `status` | Constant `active` |
| `revision` | Integer greater than or equal to 1 |
| `policy` | Closed `executionPolicy` object |

The timezone pattern is not an IANA time-zone database lookup. A matching string
can still name an unavailable or invalid zone and must be resolved by a future
parser/activation layer.

### `executionPolicy`

| Field | Allowed value |
| --- | --- |
| `timeout_seconds` | Integer 1–900 |
| `max_output_bytes` | Integer 1–1,048,576 |
| `retry_max_attempts` | Integer 1–3 |
| `concurrency_policy` | Constant `skip_if_running` |
| `capabilities` | Unique subset of `observe_metadata`, `read_local_fixture`, and `write_local_report` |
| `network_access` | Constant `false` |
| `firewall_access` | Constant `false` |

There is no shell capability, arbitrary subprocess, endpoint, credential,
filesystem path, tool name, live-capture permission, or firewall permission in
the policy shape. A prompt or model response cannot widen this allowlist.

### `runSnapshot`

The snapshot requires run and automation identifiers, automation revision,
occurrence time, idempotency key, status, attempt, prompt and prompt digest,
resolved model/folder identifiers, a complete policy snapshot, creation/update
timestamps, and `requested_actions`.

| Field | Structural boundary |
| --- | --- |
| `status` | `scheduled`, `claimed`, `running`, `succeeded`, `failed`, `timed_out`, `cancelled`, `skipped`, or `blocked` |
| `attempt` | Integer 1–3 |
| `prompt_sha256` | Exactly 64 lowercase hexadecimal characters |
| `occurrence_at`, `created_at`, `updated_at` | JSON Schema `date-time` strings ending in `Z` |
| `requested_actions` | Array with `maxItems: 0`; it must remain empty |
| `policy_snapshot` | Complete closed `executionPolicy` |

The snapshot is called immutable because a future ledger is expected to preserve
it unchanged. JSON Schema does not itself provide storage immutability,
transactionality, or lifecycle enforcement.

## RRULE boundary

The current structural pattern permits an uppercase `FREQ` of `MINUTELY`,
`HOURLY`, `DAILY`, `WEEKLY`, `MONTHLY`, or `YEARLY`, followed by bounded
uppercase rule parts. `SECONDLY` is rejected.

The structural schema rejects a rule that contains both `COUNT` and `UNTIL`,
regardless of their order. Accepted fixtures preserve the neighboring
`COUNT`-only and `UNTIL`-only cases, while rejected fixtures cover both mixed
orderings. This is only a closed structural exclusion; the Stage 1 parser must
still validate the individual values and the full RFC 5545 semantics.

This regex boundary is not an RFC 5545 recurrence engine. It does not establish:

- canonical rule-part ordering or uniqueness;
- valid values for each named rule part;
- occurrence density or expansion limits;
- `DTSTART` alignment;
- IANA-zone existence or daylight-saving behavior;
- first/next occurrence calculation; or
- missed-occurrence, restart, or clock-change behavior.

Those checks belong to the separately reviewed Stage 1 parser. Consumers must
not schedule from a value merely because it passes this schema.

## Fixture harness

Fixture files are test envelopes, not automation API payloads:

```json
{
  "schema": "draftCreate",
  "value": {
    "name": "Hourly local health summary",
    "prompt": "Summarize bounded local metadata counts and state limitations.",
    "rrule": "FREQ=HOURLY;INTERVAL=1"
  }
}
```

The test harness selects `schema` and validates only `value` against the named
definition. Production code must not infer authorization from the envelope.

Current accepted fixtures cover:

| Fixture | Boundary demonstrated |
| --- | --- |
| `draft-minimum.json` | Minimum inert create request |
| `draft-count-bounded.json` | A `COUNT`-only recurrence remains structurally valid |
| `draft-until-bounded.json` | An `UNTIL`-only recurrence remains structurally valid |
| `activated-utc.json` | Resolved UTC definition with bounded read/report capabilities |
| `run-snapshot.json` | Scheduled snapshot with an empty action request |

Current rejected fixtures cover:

| Fixture | Boundary demonstrated |
| --- | --- |
| `activation-missing-zone.json` | Activation requires an explicit schedule zone |
| `blank-name.json` | Blank names fail |
| `count-before-until.json` | `COUNT` and `UNTIL` cannot appear together |
| `firewall-access.json` | Firewall access cannot be enabled |
| `requested-action.json` | A run snapshot cannot request an action |
| `secondly-rule.json` | Sub-minute frequency is outside the contract |
| `shell-capability.json` | Shell capability is outside the allowlist |
| `until-before-count.json` | The `COUNT`/`UNTIL` exclusion is order-independent |

Rejected fixtures contain inert synthetic values. They are negative tests, not
executable requests, sensor data, firewall instructions, or examples to replay.

## Validation

Install the repository test extra and run the focused contract suite:

```bash
python -m pip install -e ".[test]"
python -m pytest -q tests/test_automation_contract.py
```

The tests:

- validate `schema.json` as JSON Schema Draft 2020-12;
- validate every accepted fixture;
- require every rejected fixture to fail through `jsonschema`;
- assert the fixed-false network and firewall fields;
- assert the exact capability allowlist and empty action boundary; and
- require both fixture sets to remain nonempty.

The suite uses `jsonschema.FormatChecker`. Consumers that omit equivalent format
checking may not enforce `date-time` formats in the same way. Passing the suite
proves conformance of these checked files and assertions only; it is not runtime,
scheduler, security-review, or deployment evidence.

## Relationships the schema does not prove

Application code must separately verify relationships that JSON Schema does not
currently establish, including:

- `prompt_sha256` actually hashes `prompt`;
- `idempotency_key` is derived from the correct automation revision and
  occurrence;
- `attempt` does not exceed the policy snapshot's retry limit;
- timestamps are ordered consistently with the run lifecycle;
- `dtstart`, `schedule_timezone`, and `dst_policy` describe one valid schedule;
- model and folder identifiers exist and are authorized;
- a snapshot exactly matches the activated revision it references; and
- concurrent claims, retries, and restarts cannot duplicate logical work.

No SQLite migration, uniqueness constraint, claim transaction, or output record
is delivered in this directory.

## Change discipline

- Keep `schema.json`, fixtures, tests, and this README aligned in one bounded
  review when a contract claim changes.
- Add an accepted fixture for each newly supported shape and a rejected fixture
  for each security or validation boundary.
- Preserve `additionalProperties: false` on closed objects and the fixed-false
  network/firewall fields.
- Do not add commands, arbitrary paths/endpoints/tools, secrets, packet payloads,
  or response authority to this version.
- Treat incompatible field or semantic changes as a new versioned contract
  rather than silently redefining `v1`.
- Keep parser, ledger, scheduler, model adapter, remote API, and enforcement work
  in separate dependency-closed changes with independent review.

The next planned dependency is the Stage 1 recurrence parser and deterministic
occurrence fixtures. It remains proposed and is not authorized or implemented by
this README.
