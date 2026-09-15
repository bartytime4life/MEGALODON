# Roadmap and Current Limits

MEGALODON is a defensive MVP, not a finished enterprise IDS/IPS.

## Current limits

The project does not currently provide an authenticated remote UI, arbitrary rule authoring, threat-feed or SIEM/SOAR integration, distributed sensor management, automatic retention, production rollback orchestration, active scheduler, unattended response, or a Suricata runtime importer.

Operational JSONL/stdin replay and optional Scapy capture require an explicit
positive accepted-event `--max-events` ceiling from 1 through 10,000,000. The
built-in sample source may omit it because the repository owns its finite
generator. JSONL iterators also refuse the first blank/comment line beyond a
fixed 65,536-line skipped-input budget, bounding physical line work after reads
return. An optional Linux `--max-seconds` value from 1 through 86,400 bounds
source acquisition, iteration, processing, and cleanup with a fixed failed
receipt; unsupported runtimes, unavailable `/proc/self/task`, signal-mask, or
pending-signal inspection, blocked or pending `SIGALRM`, and processes with more than one OS thread refuse
the option before configuration or I/O because the timer/handler are process-wide;
the mask and OS-thread count are rechecked inside protected setup before handler
or timer installation, with pending alarms checked before and after arming. Existing and
concurrently armed process timers are preserved and refused while `SIGALRM` is
blocked across the handler/timer swap, and prior-handler restoration remains
conditional on confirmed timer inactivity when cancellation raises. Teardown
blocks `SIGALRM` before cancellation and keeps the deadline handler until the
original mask is restored. Threaded
Scapy capture refuses the deadline.
Without that option, blocking work remains unbounded. The deadline does not
interrupt kernel-level uninterruptible sleep, supply a Windows control, or
establish installed-capture loss handling, sustained native capacity, or
continuous-monitoring acceptance.

The bundled IANA reference data is not service discovery or a vulnerability feed. The synthetic corpus verifies deterministic boundary behavior; it is not representative production traffic, a product benchmark, or proof an alert is malicious.

Native Windows remains an evaluation path until its ACL, SQLite, process-cleanup, and browser acceptance work is proven. Installed-tool compatibility and browser/operator acceptance are distinct evidence classes.

## Order of operations

1. Preserve independent review and lifecycle evidence.
2. Maintain fail-closed firewall containment.
3. Prove private read-only dashboard access and honest degraded behavior.
4. Preserve atomic evidence and bounded resource behavior.
5. Add one versioned, privacy-reviewed adapter at a time.
6. Obtain environment-specific and independent acceptance before any release or expansion claim.

Review the [open control register](../../SECURITY_REVIEW.md#open-control-register) and [development status](../../README.md#development-status-and-remaining-evidence) before treating an implemented slice as operational authorization.
