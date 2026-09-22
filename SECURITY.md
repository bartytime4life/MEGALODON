# Security policy

This policy defines how to report a suspected vulnerability in MEGALODON. It
does not replace [`SECURITY_REVIEW.md`](SECURITY_REVIEW.md), which is the
architecture threat assessment and open control register, or
[`SPECIFICATION.md`](SPECIFICATION.md), which is the implemented MVP
contract. Filing a report here does not itself constitute an accepted
finding, a fix commitment, a release, or independent security review.

## Supported scope

MEGALODON is a local-first defensive MVP. The current CI reference is Ubuntu
24.04 / Python 3.11; native Windows core use is an unverified evaluation
target. Only the current `main` branch receives security attention. There is
no released version, backport policy, or long-term-support branch yet; see
[issue #260](https://github.com/bartytime4life/MEGALODON/issues/260) for the
open release-evidence gate.

## How to report a vulnerability

[MAINTAINER: fill in a disclosure contact — a private security-advisory
channel, a dedicated email address, or a documented equivalent. Do not
publish a personal address here without the maintainer's explicit choice.]

Until that contact is recorded, use GitHub's private
[report a vulnerability](https://github.com/bartytime4life/MEGALODON/security/advisories/new)
flow on this repository so the report is not made public before triage, and
avoid filing a public issue for an unpatched vulnerability. Do not include
credentials, private paths, real captures, or personal telemetry in a report;
redact first, per [`CONTRIBUTING.md`](CONTRIBUTING.md).

## What to include

- The affected commit or exact revision, and whether it reproduces on `main`
  or only on a fork.
- Reproduction steps using synthetic or redacted data only.
- The specific claim in `SECURITY_REVIEW.md`, `SPECIFICATION.md`, or the
  README that the observed behavior contradicts, if applicable.
- Whether the finding concerns the core Python package, the optional Scapy
  capture path, the offline TShark/Zeek adapters, the firewall planner, the
  dashboard, or the local AI advisory path. Each has a separate trust
  boundary in `SECURITY_REVIEW.md`.

## Response expectations

[MAINTAINER: fill in an acknowledgement and triage-time target, for example
an initial acknowledgement within N business days.] There is currently no
committed service-level target. A private report does not by itself create a
coordinated-disclosure embargo; agree on a disclosure timeline with the
maintainer before any public write-up.

## Out of scope

- Findings that require an already-compromised kernel, a malicious root
  user, or direct database-file tampering. `SECURITY_REVIEW.md`'s threat
  model explicitly excludes these.
- A report that a proposed or contract-only surface (for example, the
  automation contract or the Suricata reader contract) is not yet a runtime
  capability. That is documented behavior, not a defect.
- Denial-of-service reports against a developer's own local loopback
  dashboard with no described remote-reachable path; the dashboard binds to
  `127.0.0.1` by default and rejects non-loopback `Host` headers.

## Safe harbor

Good-faith testing against your own local installation, using synthetic or
your own redacted data, and reported privately per this policy, is welcome
research rather than unauthorized access. This policy does not authorize
testing against infrastructure, accounts, or data you do not own or control.
