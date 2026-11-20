# Suspension recovery evidence and acceptance

This document separates source regression evidence from actual scheduled-service
acceptance. The synthetic checks exercise the enforcement command without
signaling a native process, launching a subprocess, controlling a service, or
activating workstation enforcement.

## Confirmed rejection before SIGSTOP

A new suspension is journaled as `pending` before its signal can occur. When
the executor rejects it before invoking SIGSTOP, the failed outcome also records
`stop_attempted = false`. A complete matching outcome removes only that pending
intent from the active view. When the append completes successfully, the
rejection remains a failed action in command output and makes the command exit 1.

The matching record must identify the same action, target, and decision. It
cannot cancel a confirmed applied hold or a failed recovery attempt. Legacy
failures without this explicit evidence stay uncertain. An error during the
signal invocation or afterward also stays uncertain. If no complete matching
outcome is readable, its pending intent remains available for recovery. A
complete line can affect the active view even if a later synchronization fails;
readback does not establish durability. The absence of an outcome is not proof
that no stop happened.

This distinction prevents a rejected indefinite attempt from holding a later
successful finite suspension indefinitely. The signal boundary also rejects
SIGSTOP of the enforcing process itself before opening a pidfd, so it cannot
stop itself while retaining the recovery lock.

These checks do not establish ownership of a stop requested independently by a
debugger or operator, and do not add cross-boot identity to legacy records.

## Synthetic scheduled-command checks

[`test_enforcement_scheduled_cli.py`](../tests/test_enforcement_scheduled_cli.py)
extracts the enforcement arguments from a generated service's `ExecStart` and
passes them through the real CLI parser and dispatcher. The fixture uses:

* A private temporary `HOME`, real policy/journal files, and a fake procfs tree.
* The production identity, locking, journal, expiry, and CLI result code paths.
* Fake pidfd operations and signal outcomes for one explicitly synthetic PID.
* Tripwires on native process launches, signals, sockets, and service operations.
* A controlled clock and in-process invocations, with no scheduler started.

The controlled launcher is parsed as test input. This does not validate every
systemd command-line quoting rule or start an installed interpreter.

| Scenario | Required observation |
| --- | --- |
| Disabled or missing policy | Existing due hold recovers; no new action or cursor is created. |
| Invalid policy | Recovery results remain visible with `policy_error` and exit 2. |
| Failed SIGCONT then a later invocation | Exit 1 and a retained hold, followed by one successful recovery. |
| Omitted invocations | No background recovery occurs; the next invocation records late recovery. |
| Two due holds for one target | One synthetic signal attempt, separate hold outcomes, one notice submission. |
| Unavailable, reused, or exited identity | Unavailable identity stays retryable; confirmed replacement/exit causes no signal. |
| Failed journal write after recovery | The signal outcome and audit failure remain distinct; new actions are refused. |
| Stage 0 | CLI refusal precedes journal locks and process work. |
| Different account `HOME` | Its command does not discover the original account's journal. |
| Alternate XDG directories | Existing enforcement defaults still resolve under `HOME`; XDG settings do not redirect them. |

Run the new synthetic checks from the repository root in the prepared test
environment:

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=. python -m pytest -q \
  tests/test_enforcement_no_stop.py \
  tests/test_enforcement_scheduled_cli.py
```

The existing identity, admission, journal, overlap, and persistence tests provide
additional coverage. Native child-process fixtures are a separate test tier and
must not be included in a run authorized only for synthetic process operations.

## Evidence that remains separate

Passing these tests does not demonstrate a real kernel SIGCONT, a systemd timer
activation, installed-wheel resolution, or workstation recovery. The repository's
SQLite backup/restore rehearsal and installed-wheel recovery workflows also have
their own scope; they are not scheduled-enforcement acceptance.

The generated service's failure classification is covered by the correction in
[PR #846](https://github.com/bartytime4life/MEGALODON/pull/846). Generated settings
do not update an installed service. Actual service results still need readback
from the approved native environment.

The generated timer uses `RandomizedDelaySec=60`. Systemd 255 also defaults
`AccuracySec` to one minute, and a timer does not launch another instance of an
already active service. A oneshot service has no default start timeout;
`RuntimeMaxSec` does not bound that service type. These are reasons to measure
actual delay and interruption recovery, not promise a one-minute deadline.
See the primary [timer](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html)
and [service](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html)
documentation, and verify the approved environment's version and effective units.

## Proposed native acceptance slice — not executed

Execution requires an identified disposable Linux VM with systemd as PID 1,
an exact candidate revision and installed interpreter, and explicit approval of
the controller and unit contents. An installed `systemctl` executable alone does
not establish that a systemd manager is available.

The proposed scope is one synthetic child owned by the acceptance controller,
with its pidfd held for identity-safe setup and cleanup. The service opens its
own pidfd for that same child through the production identity checks. The
controller must have an
independent deadline and cleanup path; it must not depend on the service under
test to resume or reap that child. Enforcer policy remains disabled while a
private fixture journal supplies the due recovery obligation.

| Operation requiring approval | Proposed exact scope |
| --- | --- |
| Temporary account data | `/run/megalodon-suspension-acceptance/home`, mode 0700; policy and journal paths resolved within it. |
| Temporary unit files | `/run/systemd/system/megalodon-suspension-acceptance.service` and `.timer`. |
| Generated service adaptations | Rename the unit pair; explicitly bind `HOME` to the temporary directory and `ExecStart` to the approved candidate interpreter. Review the complete contents before use. |
| Service-manager operations | `systemctl daemon-reload`; start/stop only `megalodon-suspension-acceptance.timer` and `.service`; read only those units' results and journal. |
| Process signals | Controller setup and cleanup use its held pidfd; service SIGCONT uses its own verified pidfd. Both may target only the controller's synthetic child. |
| Teardown | Stop the named unit pair, remove only the listed temporary unit files and fixture directory, reload the manager, and verify the child is reaped. |

Before approval, produce the exact controller, complete unit files, candidate
SHA/interpreter path, and cleanup commands for that VM. This table is an operation
proposal, not authorization or an executable acceptance receipt.

Required native observations are: service and controller resolve the same
journal; a due stopped child resumes with enforcement disabled or its policy
removed; an interruption leaves recoverable state; subsequent invocation can
retry; failed recovery is an unsuccessful service result; and teardown leaves
neither the child nor the temporary unit pair running. Keep the observed timer
delay, failure history, and any untested scenario in the receipt.
