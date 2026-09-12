# Capture failure reporting

This document covers a narrow failure-reporting slice of
[issue #68](https://github.com/bartytime4life/MEGALODON/issues/68) in
[`iter_scapy`](../megalodon/capture.py). Optional Scapy remains outside the
proposed evaluation artifact under the [specification](../SPECIFICATION.md).
Nothing here enables capture or establishes an installed-tool receipt.

The three-path capture lifecycle change is present on current `main` at
`fb2563ba97ee05526c60c45cadbd68f790a5236c` through merged PR #106. The
recorded candidate workflow run `34664505722` passed `1058` tests with `1`
skip, including wheel-smoke; the merge and hosted result are delivery evidence,
not independent approval under issue #3. The change adds observability and
fail-closed handling around the optional Scapy adapter; it does not activate
capture or create a live-capture receipt.

## Iterator diagnostic contract

| Failure boundary | Result |
| --- | --- |
| Import unavailable | Existing fixed optional-extra hint; import exception context is suppressed for standard display |
| Sniffer construction or synchronous start raises an ordinary exception | `CaptureError("unable to start live capture")`; interface and upstream exception text are not interpolated |
| Iterator fails or is interrupted, then stop also raises | Preserve the original exception object and arguments; add only `live capture cleanup failed; shutdown is unverified` |
| Explicit generator close, then stop raises an ordinary exception | `CaptureError("unable to stop live capture; shutdown is unverified")`; do not silently report successful close |
| Start or close is interrupted without an earlier primary failure | Preserve `KeyboardInterrupt` or `SystemExit`, rather than converting it to an ordinary capture error |
| Stop returns without error | No new cleanup diagnostic; this alone is not proof of native resource release |
| The background sniffer reports an exception | Fixed `CaptureError("live capture failed during startup")` or `CaptureError("live capture failed after startup")`; upstream text is not exposed |
| The sniffer thread exits before a requested stop | Fixed startup or unexpected-stop `CaptureError`; a normal exhausted capture is not inferred |
| Startup does not reach a running state before five seconds | Fixed `CaptureError("live capture startup timed out")` |
| The bounded stop wait still sees a live thread after two seconds | Fixed `CaptureError("unable to stop live capture; shutdown deadline exceeded")`; shutdown is not reported as successful |
| Thread state cannot be verified after the bounded join | Fixed `CaptureError("unable to verify live capture shutdown; shutdown is unverified")` |

The primary-error rule covers exceptions raised while advancing the iterator
and exceptions explicitly thrown into it at a yield. `GeneratorExit` from an
ordinary close is not treated as a primary failure that could hide a failed
stop. No automatic retry, restarted capture, or success receipt is added.

The queue keeps bounded in-memory `offered`, `accepted`, `dropped`, `queued`,
`capacity`, and `overflowed` diagnostics. These counters are diagnostic state,
not a durable receipt, packet-loss guarantee, or new dashboard field; the
current CLI and SQLite schema do not persist them.

The fixed cleanup note is an exception note, not a log, a SQLite field, or a
new CLI response. Python's standard traceback formatter displays notes; a
caller that reports only `str(error)` does not. The current CLI maps a surfaced
`CaptureError` to its existing `CAPTURE_ERROR` run failure category and preserves
its interruption path. This slice changes neither the CLI nor the run schema.

## Explicit limits and next lifecycle work

`iter_scapy` now polls Scapy's `running` and (where available) `exception`
state after each bounded queue wait. It applies a five-second startup deadline,
attempts cleanup for every constructed sniffer, calls Scapy's non-joining stop
form, and waits at most two seconds for the native thread. A timeout or
unverifiable thread state fails closed; it is not reported as successful
shutdown. These bounds cover the adapter's explicit wait/join operations; they
cannot interrupt a third-party implementation that blocks inside
`stop(join=False)`, prove native socket release, or measure kernel-level packet
loss. Pinned installed-Scapy profiles and stronger producer/kernel accounting
remain separate acceptance work.

The queue counters are exposed only through the private in-memory diagnostic
object; they are not included in exceptions or audit rows. A later service-level
slice must decide how to persist loss/health receipts without treating a local
queue count as proof of loss-free capture.

Errors in a consumer's processing code happen outside this generator. The CLI
now owns and checks closure before run terminalization; cleanup errors remain
subject to the separate ingestion receipt contract. Do not claim this iterator
slice fixes the whole service's cleanup path or provides exactly-once capture.

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
