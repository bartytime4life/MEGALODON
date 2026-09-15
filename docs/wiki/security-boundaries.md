# Security Boundaries

MEGALODON is evidence and decision support, not autonomous host control.

## Defaults that must remain true

- **Observe only by default.** Installation does not activate a scheduler, service, sensor, or firewall mutation.
- **Metadata only.** Packet payloads, payload-derived hashes, credentials, raw bodies, and arbitrary protocol trees do not enter core models, SQLite, reports, dashboards, prompts, or collaboration artifacts.
- **Closed inputs.** Sources have versioned schemas, bounded fields, explicit units, time basis, quotas, and rejection behavior.
- **No untrusted control plane.** Events, prompts, documents, and model output cannot select an executable, argv, endpoint, credential, SQL statement, tool, or action.
- **Evidence is not proof.** Detections, severity, and recommendations do not authorize a response.
- **Local read-only UI.** The dashboard is numeric-loopback-bound and has no write endpoint.
- **Bounded resources.** Limits apply at input, detector state, subprocess pipes, runtime, SQLite capacity, API results, and report output.

## Firewall status

Planning is deliberately separate from application. The retained `--apply` paths are refused in the evaluation-release candidate before configuration, executable lookup, privilege checks, or process work. A plan or an audit receipt does not authorize a live firewall change.

## When to stop

Fail closed when source identity, input validity, privacy classification, authority, provenance, or safety is ambiguous. Do not weaken these controls to make an integration appear available.

Read the complete [security review](../../SECURITY_REVIEW.md) and [MVP safety invariants](../../SPECIFICATION.md#2-safety-invariants) before changing these boundaries.
