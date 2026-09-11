# Capture failure reporting

This document covers a narrow failure-reporting slice of
[issue #68](https://github.com/bartytime4life/MEGALODON/issues/68) in
[`iter_scapy`](../megalodon/capture.py). Optional Scapy remains outside the
proposed evaluation artifact under the [specification](../SPECIFICATION.md).
Nothing here enables capture or establishes an installed-tool receipt.

## Iterator diagnostic contract

| Failure boundary | Result |
| --- | --- |
| Import unavailable | Existing fixed optional-extra hint; import exception context is suppressed for standard display |
| Sniffer construction or synchronous start raises an ordinary exception | `CaptureError("unable to start live capture")`; interface and upstream exception text are not interpolated |
| Iterator fails or is interrupted, then stop also raises | Preserve the original exception object and arguments; add only `live capture cleanup failed; shutdown is unverified` |
| Explicit generator close, then stop raises an ordinary exception | `CaptureError("unable to stop live capture; shutdown is unverified")`; do not silently report successful close |
| Start or close is interrupted without an earlier primary failure | Preserve `KeyboardInterrupt` or `SystemExit`, rather than converting it to an ordinary capture error |
| Stop returns without error | No new cleanup diagnostic; this alone is not proof of native resource release |

The primary-error rule covers exceptions raised while advancing the iterator
and exceptions explicitly thrown into it at a yield. `GeneratorExit` from an
ordinary close is not treated as a primary failure that could hide a failed
stop. No automatic retry, restarted capture, or success receipt is added.

The fixed cleanup note is an exception note, not a log, a SQLite field, or a
new CLI response. Python's standard traceback formatter displays notes; a
caller that reports only `str(error)` does not. The current CLI maps a surfaced
`CaptureError` to its existing `CAPTURE_ERROR` run failure category and preserves
its interruption path. This slice changes neither the CLI nor the run schema.

## Explicit limits and next lifecycle work

`AsyncSniffer.stop()` is still synchronous and has no new deadline. A call that
never returns cannot reach this failure handler. Async startup/death detection,
partial-start cleanup, stop/join deadlines, native thread/resource release, and
producer/kernel loss accounting remain unproved. A synchronous start exception
does not establish that no native work began.

Errors in a consumer's processing code happen outside this generator. Closing
or garbage-collecting it does not automatically pass that consumer exception
back into the iterator. In particular, the CLI's event-limit break does not
explicitly own and check generator closure; cleanup failure can be unraisable
there instead of entering its run receipt. Deterministic caller-owned closure
and terminalization after cleanup need a separate current-main lifecycle slice.
Do not claim this iterator correction fixes the whole service's cleanup path.

`raise ... from None` suppresses chained context in standard diagnostic display;
it does not erase the original in-memory exception or its traceback locals.
Debuggers and nonstandard formatters may still inspect them. Existing primary
errors are preserved, not sanitized. Do not serialize exception internals, raw
Scapy diagnostics, packet objects, or callback locals into evidence or logs.

## Synthetic acceptance

`tests/test_capture_failure_reporting.py` replaces Scapy with an inert module
and uses a synthetic queue. It checks constructor/start errors, import failure,
normal close, failed close, interruption precedence, twelve primary/cleanup
failure combinations, and pre-start platform/interface refusal. Socket, DNS,
and subprocess entry points are guarded. No real packet or installed Scapy is
needed; the callback is not exercised by this orchestration suite.

From the repository root in the development environment:

```bash
python -m compileall -q megalodon tests
python -m pytest -q tests/test_capture.py tests/test_capture_failure_reporting.py
python -m pytest -q
```

Retain the full repository and wheel/sdist checks. These tests are not capture
compatibility, shutdown timing, memory-pressure, signal-race, platform privacy,
or production acceptance. Issue #68 and the independent-review gate remain open.

## Language references

Python 3.11 documents [exception context and notes](https://docs.python.org/3.11/library/exceptions.html#exception-context),
including the display-only effect of `from None` and the distinction between
`GeneratorExit` and an ordinary failure. The [`finally` rules](https://docs.python.org/3.11/reference/compound_stmts.html#finally-clause)
explain why an unhandled cleanup exception would otherwise replace the primary
exception as the one propagated to the caller.
