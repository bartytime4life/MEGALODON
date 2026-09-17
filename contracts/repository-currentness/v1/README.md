# Repository currentness capture and manifest v1

`schema.json` defaults to the input capture contract. Its `$defs/manifest` and
`$defs/failure` specify generated success and refusal objects. All objects are
closed; collections and identifiers are bounded. Semantic cross-references,
capture windows and source-byte checks are enforced by
`tools/repository_currentness.py`, not JSON Schema alone.

Accepted fixtures use synthetic pins and deterministic synthetic source blobs
in a temporary test checkout. Rejected fixtures each violate an acceptance
condition. They are not live repository evidence. The existing pytest gate
exercises every fixture plus adversarial I/O and privacy cases.

See [the capture runbook](../../../docs/repository-currentness.md) for exact
scope, evidence limits, and the required post-merge receipt.
