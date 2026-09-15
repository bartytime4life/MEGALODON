# Operator Guide

The command center is for reading bounded evidence, not controlling the host.

## Evidence order

1. Check freshness and availability before interpreting results.
2. Read run/source identity, time basis, completeness, and limits.
3. Treat detections as hypotheses from fixed rules.
4. Keep action records separate from any real application state.
5. Preserve uncertainty, rejection, loss, and stale conditions in handoff notes.

## Dashboard

The dashboard binds to loopback and serves read-only routes. It provides summary counts, a bounded recent-detection projection, local filters, pause/resume polling, offline-summary availability, the static Integration Map, and the bundled Reference Library.

The page cannot start capture, run analysis, browse files, change settings, apply a firewall action, or select an arbitrary local path. Summary and recent-event responses are separate reads; do not describe them as one transactional snapshot.

A failed or malformed refresh preserves prior display data but marks it stale. A healthy dashboard response is not proof that capture, ingestion, external tools, or the host itself is healthy.

## Reference Library

IANA port/protocol registrations are context only. They do not prove that a service was observed, safe, malicious, endorsed, or related to a detection. The library has no update or external-network path at runtime.

Use the full [operator and acceptance runbook](../dashboard-operations.md) for safe local acceptance and troubleshooting.
