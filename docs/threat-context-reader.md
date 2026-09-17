# Offline threat-context reader v1

Source delivery: merged PR #269, present at the 2026-09-17 repository baseline
`77f082a0548e64f97090c94dd11503a68ca05d99`. Native operator acceptance remains
separate from source delivery and synthetic validation.

`megalodon.threat_context.read_completed_bundle(path, expected_digest)` reads
one explicitly selected STIX 2.1 bundle from a completed private file. It
returns an immutable tuple of bounded context objects and an immutable receipt.
It performs no network request, TAXII discovery, persistence, scheduling,
pattern evaluation, detection, attribution, model request, or response action.

## Admission boundary

The API is Linux-only through the existing non-root, capability-free admission
gate. The selected path must be absolute. Every path component is opened
descriptor-relative without following symlinks, and the final file must be a
single-link regular file owned by the effective user with mode `0400` or
`0600`. The reader accepts 1 byte through 16 MiB and verifies descriptor
identity again after the bounded read. The caller supplies an exact lowercase
`sha256:<64 hex>` digest; a mismatch publishes no context.

Parsing is UTF-8 and JSON-only. Duplicate keys, floats, non-finite values,
integers beyond 20 digits, more than 32 nesting levels, an empty bundle, more
than 4,096 objects, duplicate object identities, non-STIX 2.1 objects, and
invalid timestamps or identifiers fail with fixed path-free diagnostics. The
operation has a cooperative 15-second deadline and a 16 MiB normalized-output
ceiling.

## Retained context

The projection keeps only bounded fields required for context and provenance:

- type, STIX version, object ID, and optional creator identity;
- created/modified time, revocation, confidence, name, and labels;
- supported object-marking references and their in-bundle marking definitions;
- bounded external references as untrusted text; and
- indicator pattern text, type/version, and validity interval.

Granular markings are refused in v1 because silently dropping their selectors
would weaken handling restrictions. Every retained object marking must resolve
to a marking definition in the same bundle. The reader supports bounded TLP or
statement definitions and never interprets a reference URL as a destination.

Indicator patterns are preserved verbatim within the 8,192-character field
limit. They are not parsed or executed and never become a query, command,
target, endpoint, detection, or authorization decision.

## Receipt meaning

Success reports the bundle and artifact identities, counts by object type,
marking and indicator counts, normalized byte count, and the fixed facts
`runtime_fetch=false`, `taxii=false`, `attribution_authority=false`,
`detection_authority=false`, `action_authority=none`, and
`persistence_status=not_attempted`.

The digest proves only that the bytes matched the caller's expected value. It
does not authenticate the publisher, validate intelligence accuracy, establish
freshness, prove threat coverage, or authorize enrichment or response. Source
snapshot status is `metadata_unchanged_not_atomic`: descriptor metadata stayed
stable during this read, but no claim is made about an upstream publication
transaction.

## Verification

```bash
python -m pytest -q tests/test_threat_context.py tests/test_external_exchange_contract.py
python -m compileall -q megalodon/threat_context.py
```

The focused suite includes accepted context plus adversarial file, framing,
digest, schema, marking, resource, immutability, and zero-external-work cases.
Native operator acceptance, feed provenance, independent review, release, and
deployment remain separate gates.
