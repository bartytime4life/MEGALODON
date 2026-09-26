"""Command-line entry point."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import sys
import time

from . import __version__
from .capabilities import catalog
from .posture import local_posture
from .capture import CaptureError, iter_jsonl, iter_sample, iter_scapy
from .config import load_settings
from .firewall import FirewallError, LIVE_APPLY_UNSUPPORTED, NftablesFirewall
from .models import ActionRecord
from .service import MegalodonService
from .dashboard_traffic import TrafficDashboardStore as DashboardStore
from .storage import (
    StorageSchemaError,
    IngestionRunError,
    migrate_database,
    RECONCILIATION_REQUIRED,
    Store,
    DEFAULT_MAX_DATABASE_BYTES,
)
from .validation import parse_timestamp, safe_text, ValidationError


MAX_RUN_EVENTS = 10_000_000
MAX_RUN_SECONDS = 86_400
_LIMITED_RUN_SOURCES = frozenset({"jsonl", "scapy"})
_AI_SUCCESS_STATES = frozenset({"observed", "applied", "awaiting_confirmation"})


def _ai_receipt_path(db_path: Path) -> Path:
    """Keep telemetry outside the AI ledger's main and SQLite sidecar namespace."""
    candidate = db_path.with_name("megalodon-ai-receipts.db")
    reserved_names = {
        candidate.name.casefold(),
        (candidate.name + "-wal").casefold(),
        (candidate.name + "-shm").casefold(),
        (candidate.name + "-journal").casefold(),
    }
    if db_path.name.casefold() in reserved_names:
        return db_path.with_name("megalodon-ai-receipts-ledger.db")
    return candidate


def _ai_result_succeeded(result: object) -> bool:
    """Treat a validated proposal as CLI success without implying application."""
    return type(result) is dict and result.get("state", result.get("execution_state")) in _AI_SUCCESS_STATES


def _bounded_cli_integer(name: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        candidate = value.strip()
        if not candidate.isascii() or not candidate.isdecimal():
            raise argparse.ArgumentTypeError(f"{name} must be a decimal integer")
        # Bound conversion independently of Python's configurable integer digit
        # limit, while retaining the existing acceptance of leading zeroes.
        digits = candidate.lstrip("0") or "0"
        if len(digits) > len(str(maximum)):
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        parsed = int(digits)
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="megalodon", description="Local-first defensive network telemetry")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ai = sub.add_parser("ai", help="bounded local AI doctor, question and tool broker")
    ai.add_argument("operation", choices=("doctor", "ask", "tool"))
    ai.add_argument("--config", help="explicit TOML settings file")
    ai.add_argument("--question", choices=("seeing", "changed", "alerts", "integrations", "model", "safe", "plan", "report"))
    ai.add_argument("--request", help="one closed JSON tool request; no commands or paths")

    capabilities = sub.add_parser("capabilities", help="print the static platform and free-software catalog")
    capabilities.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="show one documented profile; defaults to the current runtime family",
    )

    sub.add_parser(
        "readiness",
        help="print a bounded local executable-presence receipt without running tools",
    )

    posture = sub.add_parser(
        "posture",
        help="print a bounded package-level posture receipt without probing the host",
    )
    posture.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="select a documented static profile; defaults to the runtime platform family",
    )

    hub = sub.add_parser("hub-plan", help="print the static, non-executing integration workflow plan")
    hub.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="show one documented profile; defaults to the current runtime family",
    )
    from .hub import WORKFLOW_IDS
    hub.add_argument("--workflow", choices=WORKFLOW_IDS, help="show one closed workflow")

    automation_preview = sub.add_parser(
        "automation-preview", help="preview a bounded recurrence without scheduling a job",
    )
    automation_preview.add_argument("--dtstart", required=True, help="local start time, YYYY-MM-DDTHH:MM:SS")
    automation_preview.add_argument("--timezone", required=True, help="IANA time zone for the local start time")
    automation_preview.add_argument("--rrule", required=True, help="bounded recurrence rule")
    automation_preview.add_argument(
        "--dst-policy", choices=("reject", "skip", "shift_forward", "fold_earlier", "fold_later"),
        default="reject", help="how to handle ambiguous or nonexistent local times",
    )
    automation_preview.add_argument(
        "--limit", type=_bounded_cli_integer("limit", 1, 366), default=10,
        help="maximum number of preview occurrences (1-366; default 10)",
    )

    run = sub.add_parser("run", help="process metadata events")
    run.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    run.add_argument("--source", choices=("sample", "jsonl", "scapy"), default=None)
    run.add_argument("--input", type=Path, help="JSONL input file; stdin is used when omitted")
    run.add_argument("--interface", help="capture interface for --source scapy")
    run.add_argument("--demo-threat", action="store_true", help="add synthetic detections to sample data")
    run.add_argument(
        "--max-events",
        type=_bounded_cli_integer("max-events", 1, MAX_RUN_EVENTS),
        default=None,
        help=(
            "stop after N events; required for jsonl and scapy sources "
            f"(maximum {MAX_RUN_EVENTS})"
        ),
    )
    run.add_argument(
        "--max-seconds",
        type=_bounded_cli_integer("max-seconds", 1, MAX_RUN_SECONDS),
        default=None,
        help=(
            "fail closed after N seconds while acquiring, consuming, processing, "
            "or closing the event source on supported Linux runtimes "
            f"(maximum {MAX_RUN_SECONDS})"
        ),
    )

    migrate = sub.add_parser(
        "database-migrate",
        help="explicitly back up and migrate the configured audit database",
    )
    migrate.add_argument(
        "--config",
        help="explicit TOML settings file; safe built-in defaults are used when omitted",
    )

    backup = sub.add_parser(
        "database-backup",
        help="back up the configured audit database to a new local artifact",
    )
    backup.add_argument("destination", type=Path)
    backup.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="new path for the bounded recovery manifest",
    )
    backup.add_argument("--operation-id", required=True)
    backup.add_argument(
        "--config",
        help="explicit TOML settings file; safe built-in defaults are used when omitted",
    )

    restore = sub.add_parser(
        "database-restore",
        help="restore a reviewed backup into a new, inactive database",
    )
    restore.add_argument("source", type=Path)
    restore.add_argument("destination", type=Path)
    restore.add_argument("--manifest", type=Path, required=True)
    restore.add_argument("--artifact-sha256", required=True)
    restore.add_argument("--operation-id", required=True)

    reconciliation_status = sub.add_parser(
        "database-reconciliation-status",
        help="list bounded run receipts that require operator reconciliation",
    )
    reconciliation_status.add_argument("--config")

    reconcile = sub.add_parser(
        "database-reconcile",
        help="mark one pinned orphaned run as requiring reconciliation",
    )
    reconcile.add_argument("run_id", type=_bounded_cli_integer("run-id", 1, 2**63 - 1))
    reconcile.add_argument(
        "--started-at",
        required=True,
        help="exact started_at value shown by database-reconciliation-status",
    )
    reconcile.add_argument("--config")

    dashboard = sub.add_parser("dashboard", aliases=["hud"], help="serve the local dashboard; hud also checks tool presence and supports first launch")
    dashboard.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    dashboard.add_argument("--host")
    dashboard.add_argument("--port", type=_bounded_cli_integer("port", 1, 65535))
    dashboard.add_argument("--allow-remote", action="store_true", help="removed unsafe option; supplying it refuses startup")
    dashboard.add_argument(
        "--enable-tool-management", action="store_true",
        help="hud only: enable token-gated fixed Install/Start actions for a non-root Linux launch",
    )
    dashboard.add_argument(
        "--refresh-seconds",
        type=_bounded_cli_integer("refresh-seconds", 2, 300),
        help="live refresh interval from 2 to 300 seconds; overrides configuration",
    )
    dashboard.add_argument(
        "--event-limit",
        type=_bounded_cli_integer("event-limit", 1, 200),
        help="newest detections loaded per refresh, from 1 to 200; overrides configuration",
    )
    dashboard.add_argument(
        "--offline-run",
        type=Path,
        help="absolute path to one complete private offline run; loaded read-only at startup",
    )
    dashboard.add_argument(
        "--suricata-db",
        type=Path,
        help="existing private Suricata store; bounded read-only startup snapshot",
    )
    dashboard.add_argument(
        "--open-browser",
        action="store_true",
        help="open the loopback HUD in the default browser after the server binds",
    )

    plan = sub.add_parser("firewall-plan", help="print a non-mutating nftables plan")
    plan.add_argument("ip")
    plan.add_argument("--reason", default="manual review")
    plan.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")

    install = sub.add_parser("firewall-install", help="print MEGALODON's isolated nftables table plan")
    install.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    install.add_argument(
        "--apply",
        action="store_true",
        help="unsupported compatibility flag; always fails closed without changing the host",
    )
    install.add_argument("--confirm", help="retained for compatibility; live application is unsupported")

    block = sub.add_parser("block", help="print one non-mutating, time-limited block plan")
    block.add_argument("ip")
    block.add_argument("--reason", required=True)
    block.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    block.add_argument(
        "--apply",
        action="store_true",
        help="unsupported compatibility flag; always fails closed without changing the host",
    )
    block.add_argument("--confirm", help="retained for compatibility; live application is unsupported")

    return parser


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(levelname)s %(message)s")


def _capabilities(args: argparse.Namespace) -> int:
    print(json.dumps(catalog(args.platform), sort_keys=True))
    return 0


def _readiness(args: argparse.Namespace) -> int:
    from .readiness import readiness_json

    print(readiness_json())
    return 0


def _posture(args: argparse.Namespace) -> int:
    print(json.dumps(local_posture(args.platform), sort_keys=True))
    return 0


def _hub_plan(args: argparse.Namespace) -> int:
    from .hub import integration_plan

    print(json.dumps(integration_plan(args.platform, args.workflow), sort_keys=True))
    return 0


def _automation_preview(args: argparse.Namespace) -> int:
    from .automation_schedule import AutomationScheduleError, next_occurrences

    try:
        occurrences = next_occurrences(
            dtstart=args.dtstart, schedule_timezone=args.timezone,
            rrule=args.rrule, dst_policy=args.dst_policy, limit=args.limit,
        )
    except (AutomationScheduleError, ValueError, OverflowError) as exc:
        print(f"megalodon automation-preview: {getattr(exc, 'code', 'PREVIEW_UNAVAILABLE')}", file=sys.stderr)
        return 2
    print(json.dumps({
        "schema_version": "megalodon-automation-preview-v1",
        "status": "preview_only",
        "occurrences": [dict(item) for item in occurrences],
    }, sort_keys=True, allow_nan=False))
    return 0


def _load(config: str | None):
    try:
        settings = load_settings(config)
    except OSError as exc:
        raise ValueError("configuration file could not be read") from exc
    _configure_logging(settings.log_level)
    return settings


@contextmanager
def _owned_source(source):
    """Close a CLI-owned iterator/stream without hiding a primary failure."""

    primary_error: BaseException | None = None
    try:
        yield source
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        try:
            close = getattr(source, "close", None)
            if close is not None:
                close()
        except BaseException as exc:
            if primary_error is not None and not isinstance(primary_error, GeneratorExit):
                BaseException.add_note(
                    primary_error,
                    "event source cleanup failed; shutdown is unverified",
                )
            elif isinstance(exc, Exception):
                raise CaptureError(
                    "event source cleanup failed; shutdown is unverified"
                ) from None
            else:
                raise


def _jsonl_file_events(path: Path):
    # Lazy open: closing an unstarted iterator must not acquire a file.
    # Preserve terminators so CRLF bytes count toward both JSONL byte budgets.
    with _owned_source(path.open("r", encoding="utf-8", newline="")) as stream:
        yield from iter_jsonl(stream)


def _events_for(args: argparse.Namespace, settings):
    source = _source_for(args, settings)
    if source == "sample":
        return iter_sample(include_demo_threat=args.demo_threat)
    if source == "jsonl":
        if args.input:
            return _jsonl_file_events(args.input)
        return iter_jsonl(sys.stdin)
    if source == "scapy":
        return iter_scapy(args.interface or settings.interface)
    raise CaptureError(f"unsupported source: {source}")


def _source_for(args: argparse.Namespace, settings) -> str:
    return args.source or settings.capture_source


def _require_finite_run_limit(source: str | None, max_events: int | None) -> None:
    if source in _LIMITED_RUN_SOURCES and max_events is None:
        raise ValueError(
            "jsonl and scapy sources require --max-events between "
            f"1 and {MAX_RUN_EVENTS}"
        )


def _require_run_deadline_source(
    source: str | None, max_seconds: int | None
) -> None:
    if source == "scapy" and max_seconds is not None:
        raise ValueError(
            "max-seconds is unavailable for threaded scapy capture"
        )


def _run_deadline_supported() -> bool:
    return (
        sys.platform.startswith("linux")
        and hasattr(signal, "SIGALRM")
        and hasattr(signal, "ITIMER_REAL")
        and hasattr(signal, "SIG_BLOCK")
        and hasattr(signal, "SIG_SETMASK")
        and callable(getattr(signal, "getitimer", None))
        and callable(getattr(signal, "setitimer", None))
        and callable(getattr(signal, "pthread_sigmask", None))
        and callable(getattr(signal, "sigpending", None))
        and callable(getattr(os, "scandir", None))
    )


def _require_single_threaded_run_deadline() -> None:
    try:
        with os.scandir("/proc/self/task") as tasks:
            task_count = 0
            for _task in tasks:
                task_count += 1
                if task_count > 1:
                    raise ValueError(
                        "max-seconds requires a single-threaded process"
                    )
    except OSError:
        raise ValueError(
            "max-seconds could not inspect the OS thread set"
        ) from None
    if task_count != 1:
        raise ValueError("max-seconds could not inspect the OS thread set")


def _require_run_deadline_support(max_seconds: int | None) -> None:
    if max_seconds is None:
        return
    if not _run_deadline_supported():
        raise ValueError(
            "max-seconds requires a Linux runtime with SIGALRM, ITIMER_REAL, "
            "pthread_sigmask, sigpending, and procfs thread inspection"
        )
    _require_single_threaded_run_deadline()
    try:
        blocked_signals = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not inspect the POSIX signal mask"
        ) from None
    if signal.SIGALRM in blocked_signals:
        raise ValueError("max-seconds requires SIGALRM to be unblocked")
    try:
        pending_signals = signal.sigpending()
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not inspect pending POSIX signals"
        ) from None
    if signal.SIGALRM in pending_signals:
        raise ValueError("max-seconds cannot start with a pending SIGALRM")
    try:
        active_timer = signal.getitimer(signal.ITIMER_REAL)
    except (OSError, ValueError):
        raise ValueError("max-seconds could not inspect the POSIX run timer") from None
    if active_timer != (0.0, 0.0):
        raise ValueError("max-seconds cannot replace an active POSIX process timer")


def _storage_limit(settings) -> int:
    storage = getattr(settings, "storage", None)
    return getattr(storage, "max_database_bytes", DEFAULT_MAX_DATABASE_BYTES)


def _run_failure_code(exc: Exception) -> str:
    if isinstance(exc, CaptureError):
        return "CAPTURE_ERROR"
    if isinstance(exc, sqlite3.Error):
        return "STORAGE_ERROR"
    if isinstance(exc, OSError):
        return "IO_ERROR"
    return "VALIDATION_ERROR"


class _RunInterrupted(KeyboardInterrupt):
    def __init__(self, signum: int):
        super().__init__()
        self.signum = signum


@contextmanager
def _scoped_run_deadline(max_seconds: int | None):
    """Bound single-threaded Linux source ownership with a process alarm."""

    if max_seconds is None:
        yield
        return
    _require_run_deadline_support(max_seconds)

    alarm_signal = signal.SIGALRM
    timer_kind = signal.ITIMER_REAL
    previous_handler = signal.getsignal(alarm_signal)

    def deadline_exceeded(_signum, _frame):
        raise CaptureError("ingestion deadline exceeded")

    try:
        setup_previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not inspect POSIX run deadline setup"
        ) from None
    try:
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {alarm_signal})
    except (OSError, ValueError):
        raise ValueError(
            "max-seconds could not protect POSIX run deadline setup"
        ) from None
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, setup_previous_mask)
        raise
    if alarm_signal in previous_mask:
        raise ValueError("max-seconds requires SIGALRM to be unblocked")
    try:
        pending_signals = signal.sigpending()
    except (OSError, ValueError):
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise ValueError(
            "max-seconds could not inspect pending POSIX signals"
        ) from None
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    if alarm_signal in pending_signals:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise ValueError("max-seconds cannot start with a pending SIGALRM")

    handler_installed = False
    timer_started = False
    mask_restored = False
    competing_timer = None
    try:
        _require_single_threaded_run_deadline()
        try:
            signal.signal(alarm_signal, deadline_exceeded)
        except ValueError:
            raise ValueError(
                "max-seconds requires the interpreter main thread"
            ) from None
        except BaseException:
            # Python signal dispatch occurs after the handler swap returns from
            # the OS. Restore conservatively during cleanup before re-raising.
            handler_installed = True
            raise
        else:
            handler_installed = True
        # Treat an interrupted arming call as live until cleanup proves
        # otherwise; setitimer may have succeeded before Python dispatch.
        timer_started = True
        try:
            previous_timer = signal.setitimer(timer_kind, max_seconds)
        except (OSError, ValueError):
            raise ValueError(
                "max-seconds could not arm the POSIX run deadline"
            ) from None
        if previous_timer != (0.0, 0.0):
            competing_timer = previous_timer
            restore_started = time.monotonic()
            try:
                signal.setitimer(timer_kind, *previous_timer)
            except (OSError, ValueError):
                raise ValueError(
                    "max-seconds could not restore a competing POSIX process timer"
                ) from None
            except BaseException:
                # Dispatch can occur immediately before or after the timer
                # syscall. Read back the process timer instead of assuming
                # that the competing timer was restored. Cleanup will cancel
                # our timer and restore the displaced timer when it was not.
                try:
                    active_timer = signal.getitimer(timer_kind)
                except BaseException:
                    pass
                else:
                    elapsed = max(0.0, time.monotonic() - restore_started)
                    expected_delay, expected_interval = previous_timer
                    active_delay, active_interval = active_timer
                    tolerance = elapsed + 0.01
                    if (
                        active_interval == expected_interval
                        and max(0.0, expected_delay - tolerance)
                        <= active_delay
                        <= expected_delay + tolerance
                    ):
                        timer_started = False
                        competing_timer = None
                raise
            else:
                timer_started = False
                competing_timer = None
            raise ValueError(
                "max-seconds cannot replace an active POSIX process timer"
            )
        try:
            pending_signals = signal.sigpending()
        except (OSError, ValueError):
            raise ValueError(
                "max-seconds could not inspect pending POSIX signals"
            ) from None
        if alarm_signal in pending_signals:
            # The protected boundary was clear immediately before arming. Keep
            # our handler installed while releasing a post-arm pending alarm so
            # an already-expired deadline remains a CaptureError.
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            except (OSError, ValueError):
                raise ValueError(
                    "max-seconds could not restore the POSIX signal mask"
                ) from None
            except BaseException:
                mask_restored = True
                raise
            else:
                mask_restored = True
            raise CaptureError("ingestion deadline exceeded")
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        except (OSError, ValueError):
            raise ValueError(
                "max-seconds could not restore the POSIX signal mask"
            ) from None
        except BaseException:
            # Python dispatch occurs after the mask syscall returns. Record
            # the unblocked state so teardown first blocks the alarm again.
            mask_restored = True
            raise
        else:
            mask_restored = True
        yield
    finally:
        try:
            if handler_installed:
                cleanup_mask = None
                cleanup_mask_error = None
                cleanup_entry_error = None
                if mask_restored:
                    try:
                        cleanup_mask = signal.pthread_sigmask(
                            signal.SIG_BLOCK, {alarm_signal}
                        )
                    except (OSError, ValueError):
                        cleanup_mask_error = ValueError(
                            "max-seconds could not protect POSIX run deadline cleanup"
                        )
                    except BaseException as exc:
                        # Python signal dispatch occurs after the masking syscall
                        # completes. Preserve that interruption, finish teardown
                        # under the now-blocked mask, then re-raise it.
                        cleanup_mask = previous_mask
                        cleanup_entry_error = exc
                timer_inactive = not timer_started
                cancellation_error = None
                timer_inspection_error = None
                competing_restore_error = None
                try:
                    if timer_started:
                        signal.setitimer(timer_kind, 0.0)
                        timer_inactive = True
                except BaseException as exc:
                    cancellation_error = exc
                    try:
                        timer_inactive = (
                            signal.getitimer(timer_kind) == (0.0, 0.0)
                        )
                    except (OSError, ValueError):
                        timer_inactive = False
                    except BaseException as exc:
                        # Preserve signal dispatch from the inspection, but do
                        # not skip mask/handler restoration decisions.
                        timer_inactive = False
                        timer_inspection_error = exc
                if competing_timer is not None and timer_inactive:
                    try:
                        signal.setitimer(timer_kind, *competing_timer)
                    except BaseException as exc:
                        competing_restore_error = exc
                    else:
                        competing_timer = None
                try:
                    if cleanup_mask is not None:
                        # Keep the deadline handler installed while unblocking so
                        # a just-pending MEGALODON alarm cannot reach the prior
                        # handler. Python dispatches it here as CaptureError.
                        signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
                finally:
                    if timer_inactive and competing_timer is None and (
                        not mask_restored or cleanup_mask is not None
                    ):
                        signal.signal(alarm_signal, previous_handler)
                if cleanup_entry_error is not None:
                    raise cleanup_entry_error
                if timer_inspection_error is not None:
                    raise timer_inspection_error
                if cancellation_error is not None:
                    raise cancellation_error
                if competing_restore_error is not None:
                    raise competing_restore_error
                if cleanup_mask_error is not None:
                    raise cleanup_mask_error
        finally:
            if not mask_restored:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


@contextmanager
def _scoped_sigterm_interrupt():
    """Turn SIGTERM into a bounded run receipt while this command is active."""

    previous = signal.getsignal(signal.SIGTERM)

    def interrupt(signum, _frame):
        raise _RunInterrupted(signum)

    try:
        signal.signal(signal.SIGTERM, interrupt)
    except ValueError:
        # Signal handlers can only be installed by the interpreter's main thread.
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


def _reconciliation_message() -> str:
    return (
        "megalodon: ingestion reconciliation required; stop all ingestion, "
        "then inspect database-reconciliation-status"
    )


def _run(args: argparse.Namespace) -> int:
    try:
        # Refuse an explicit unbounded source before configuration, store, or
        # source acquisition. A configuration-selected source is checked again
        # immediately after the one necessary configuration read.
        _require_finite_run_limit(args.source, args.max_events)
        _require_run_deadline_source(args.source, args.max_seconds)
        _require_run_deadline_support(args.max_seconds)
        settings = _load(args.config)
        source = _source_for(args, settings)
        _require_finite_run_limit(source, args.max_events)
        _require_run_deadline_source(source, args.max_seconds)
        with Store(
            settings.db_path,
            max_database_bytes=_storage_limit(settings),
        ) as store:
            service = MegalodonService(settings, store)
            run_id = store.start_ingestion_run(source)
            processed = 0
            termination_reason = "source_exhausted"
            try:
                with (
                    _scoped_sigterm_interrupt(),
                    _scoped_run_deadline(args.max_seconds),
                    _owned_source(_events_for(args, settings)) as events,
                ):
                    for event in events:
                        service.process(event, run_id=run_id)
                        processed += 1
                        if (
                            args.max_events is not None
                            and processed >= args.max_events
                        ):
                            termination_reason = "event_limit_reached"
                            break
            except KeyboardInterrupt as exc:
                try:
                    receipt = store.finish_ingestion_run(run_id, "interrupted")
                except IngestionRunError as finish_error:
                    if str(finish_error) == RECONCILIATION_REQUIRED:
                        print(_reconciliation_message(), file=sys.stderr)
                        return 2
                    raise
                if receipt["status"] == "reconciliation_required":
                    print(_reconciliation_message(), file=sys.stderr)
                    return 2
                print("megalodon: ingestion interrupted", file=sys.stderr)
                return 143 if isinstance(exc, _RunInterrupted) else 130
            except (CaptureError, OSError, ValueError, sqlite3.Error) as exc:
                if isinstance(exc, IngestionRunError) and str(exc) == RECONCILIATION_REQUIRED:
                    print(_reconciliation_message(), file=sys.stderr)
                    return 2
                failure_code = _run_failure_code(exc)
                try:
                    receipt = store.finish_ingestion_run(
                        run_id, "failed", failure_code=failure_code
                    )
                except IngestionRunError as finish_error:
                    if str(finish_error) == RECONCILIATION_REQUIRED:
                        print(_reconciliation_message(), file=sys.stderr)
                        return 2
                    raise
                if receipt["status"] == "reconciliation_required":
                    print(_reconciliation_message(), file=sys.stderr)
                    return 2
                print(
                    f"megalodon: ingestion failed ({failure_code})",
                    file=sys.stderr,
                )
                return 2
            receipt = store.finish_ingestion_run(run_id, termination_reason)
            if receipt["status"] == "reconciliation_required":
                print(_reconciliation_message(), file=sys.stderr)
                return 2
            print(json.dumps({**receipt, "totals": store.summary()}, sort_keys=True))
    except sqlite3.Error:
        print("megalodon: storage operation failed", file=sys.stderr)
        return 2
    except OSError:
        print("megalodon: I/O operation failed", file=sys.stderr)
        return 2
    except IngestionRunError as exc:
        if str(exc) == RECONCILIATION_REQUIRED:
            print(_reconciliation_message(), file=sys.stderr)
        else:
            print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    except (CaptureError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    from .dashboard import loopback_host, serve, UnconfiguredDashboardReader, validate_tool_management_mode
    from .offline_projection import load_offline_projection
    from .config import AISettings, BlockingSettings

    try:
        settings = _load(args.config)
        host = args.host if args.host is not None else settings.dashboard.host
        port = args.port if args.port is not None else settings.dashboard.port
        host = loopback_host(host, allow_remote=args.allow_remote)
        enabled = getattr(settings.dashboard, "enabled", True)
        if not enabled:
            raise ValueError("dashboard is disabled by configuration")
        first_launch = getattr(args, "command", "dashboard") == "hud"
        enable_tool_management = getattr(args, "enable_tool_management", False)
        validate_tool_management_mode(enable_tool_management, inspect_tools=first_launch)
        offline_summary = load_offline_projection(args.offline_run) if args.offline_run else None
        with _dashboard_reader(settings.db_path, allow_missing=first_launch) as store:
            serve(
                store,
                host,
                port,
                enabled=enabled,
                allow_remote=args.allow_remote,
                offline_summary=offline_summary,
                suricata_db=getattr(args, "suricata_db", None),
                inspect_tools=first_launch,
                enable_tool_management=enable_tool_management,
                source_available=not isinstance(store, UnconfiguredDashboardReader),
                refresh_seconds=(
                    args.refresh_seconds if args.refresh_seconds is not None else settings.dashboard.refresh_seconds
                ),
                event_limit=args.event_limit if args.event_limit is not None else settings.dashboard.event_limit,
                open_browser=getattr(args, "open_browser", False),
                ai_settings=getattr(settings, "ai", AISettings()),
                ai_receipt_path=_ai_receipt_path(settings.db_path),
                ai_blocking=getattr(settings, "blocking", BlockingSettings()),
            )
    except KeyboardInterrupt:
        print("\nMEGALODON dashboard stopped.")
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            print(
                "megalodon: dashboard address is already in use; stop the existing "
                "server or choose another port with --port 8788",
                file=sys.stderr,
            )
        else:
            print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


@contextmanager
def _dashboard_reader(path: Path, *, allow_missing: bool = False):
    """First launch may lack a store; an unsafe or invalid store still refuses."""
    from .dashboard import UnconfiguredDashboardReader

    try:
        store = DashboardStore(path)
    except StorageSchemaError as exc:
        if not allow_missing or str(exc) not in {
            "DASHBOARD_STORE:NO_DIRECTORY", "DASHBOARD_STORE:NO_DATABASE",
        }:
            raise
        yield UnconfiguredDashboardReader()
        return
    with store:
        yield store


def _ai(args: argparse.Namespace) -> int:
    from uuid import uuid4
    from .ai_broker import Broker, BrokerError, ReceiptStore
    from .ai_interface import ask
    from .ai_provider import AIProviderError, inventory, status
    from .provider_containment import qwen_provider_posture
    import shutil
    import subprocess

    try:
        settings = _load(args.config)
        receipt_path = _ai_receipt_path(settings.db_path)
        if args.operation == "doctor":
            posture = qwen_provider_posture()
            bound_uids = [binding["uid"] for binding in posture["bindings"]]
            model_status = status(settings.ai, probe=True)
            model_inventory = inventory(settings.ai)
            try:
                gpu = subprocess.run(["/usr/bin/nvidia-smi", "--query-gpu=name,driver_version,compute_cap",
                                      "--format=csv,noheader"], capture_output=True, text=True,
                                     timeout=3, check=False)
                driver_usable = gpu.returncode == 0 and bool(gpu.stdout.strip())
            except (OSError, subprocess.TimeoutExpired):
                driver_usable = False
            try:
                unit = subprocess.run(["/usr/bin/systemctl", "show", "ollama",
                                       "-p", "IPAddressDeny", "-p", "IPAddressAllow",
                                       "--no-pager"], capture_output=True, text=True,
                                      timeout=3, check=False)
                unit_fields = dict(line.split("=", 1) for line in unit.stdout.splitlines() if "=" in line) if unit.returncode == 0 else {}
                deny = unit_fields.get("IPAddressDeny", "")
                allow = unit_fields.get("IPAddressAllow", "")
                egress_restricted = ("any" in deny or ("0.0.0.0/0" in deny and "::/0" in deny)) and "127.0.0.0/8" in allow
            except (OSError, subprocess.TimeoutExpired):
                egress_restricted = False
            checks = {
                "ollama_installed": shutil.which("ollama") is not None,
                "ollama_loopback_only": posture["loopback_only"] is True,
                "ollama_egress_restricted": egress_restricted,
                "ollama_service_non_root": bool(bound_uids) and all(uid != 0 for uid in bound_uids),
                "nvidia_gpu_detected": Path("/proc/driver/nvidia/version").exists() and Path("/dev/nvidia0").exists(),
                "nvidia_driver_usable": driver_usable,
                "qwen_model_installed": model_inventory["model_present"] is True and model_inventory["digest_matches"] is True,
                "qwen_inference_healthy": model_status["state"] == "model_ready",
                "adapter_connected": model_status["state"] == "model_ready",
                "tool_broker_available": True,
                "audit_database_writable": False,
                "firewall_authority_disabled": True,
            }
            try:
                with ReceiptStore(receipt_path) as receipts:
                    receipts.append(str(uuid4()), {"state": "observed", "tool": "megalodon.ai.doctor",
                                                  "authority_level": 0, "authorization_source": "operator_cli",
                                                  "model": settings.ai.model, "model_request": "none",
                                                  "validated_arguments": {}, "result": {"checked": True},
                                                  "error_code": None, "duration_ms": 0,
                                                  "evidence_references": []})
                checks["audit_database_writable"] = True
            except (OSError, ValueError, sqlite3.Error):
                pass
            print(json.dumps({"schema": "megalodon-ai-doctor-v1", "checks": checks,
                              "model_status": model_status, "model_inventory": model_inventory,
                              "operator_action": "Review the operator setup gates in docs/ai-control-plane.md; no host change was applied" if (posture["loopback_only"] is not True or not egress_restricted) else None},
                             sort_keys=True))
            return 0 if all(checks.values()) else 1
        with ReceiptStore(receipt_path) as receipts, _dashboard_reader(settings.db_path, allow_missing=True) as reader:
            broker = Broker(reader, receipts, settings.ai, settings.blocking)
            if args.operation == "tool":
                if args.request is None or len(args.request.encode()) > 2048:
                    raise BrokerError("INVALID_REQUEST")
                try:
                    from .ai_provider import _strict_pairs
                    request = json.loads(args.request, object_pairs_hook=_strict_pairs)
                except ValueError:
                    request = None
                result = broker.dispatch(request, authorization_source="operator_cli")
            else:
                if args.question is None:
                    raise BrokerError("UNKNOWN_QUESTION")
                result = ask(args.question, broker)
            print(json.dumps(result, sort_keys=True, allow_nan=False))
            return 0 if _ai_result_succeeded(result) else 1
    except (AIProviderError, BrokerError, OSError, ValueError, sqlite3.Error) as exc:
        print(f"megalodon ai: {getattr(exc, 'code', 'UNAVAILABLE')}", file=sys.stderr)
        return 2


def _database_migrate(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        print(json.dumps(migrate_database(settings.db_path), sort_keys=True))
    except (OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _database_backup(args: argparse.Namespace) -> int:
    from .sqlite_recovery_workflow import backup_database

    try:
        settings = _load(args.config)
    except (OSError, ValueError):
        source: object = object()
    else:
        source = settings.db_path
    receipt = backup_database(
        source,
        args.destination,
        args.manifest,
        operation_id=args.operation_id,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "completed" else 2


def _database_restore(args: argparse.Namespace) -> int:
    from .sqlite_recovery_workflow import restore_database

    receipt = restore_database(
        args.source,
        args.manifest,
        args.destination,
        artifact_sha256=args.artifact_sha256,
        operation_id=args.operation_id,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["status"] == "completed" else 2


def _database_reconciliation_status(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        with Store(
            settings.db_path,
            create=False,
            max_database_bytes=_storage_limit(settings),
        ) as store:
            pending = store.pending_ingestion_reconciliation()
        print(json.dumps({"pending": pending}, sort_keys=True))
    except (OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _database_reconcile(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        started_at = parse_timestamp(args.started_at)
        with Store(
            settings.db_path,
            create=False,
            max_database_bytes=_storage_limit(settings),
        ) as store:
            receipt = store.mark_ingestion_run_reconciliation_required(
                args.run_id, expected_started_at=started_at
            )
        print(json.dumps(receipt, sort_keys=True))
    except (OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _record_firewall_action(settings, mode: str, operation) -> None:
    action = "firewall_install" if mode == "install" else "block"
    details = operation.to_dict()
    try:
        safe_text(details["message"], "operation message", 256)
    except ValidationError:
        details["message"] = "multiline or oversized operation plan omitted from audit details"
    with Store(
        settings.db_path,
        max_database_bytes=_storage_limit(settings),
    ) as store:
        store.record_action(
            ActionRecord(
                created_at=datetime.now(timezone.utc),
                action=action,
                target=operation.target,
                status=operation.status,
                reason=operation.reason,
                expires_at=operation.expires_at,
                details=details,
            )
        )


def _firewall(args: argparse.Namespace, mode: str) -> int:
    if getattr(args, "apply", False):
        print(f"megalodon: {LIVE_APPLY_UNSUPPORTED}", file=sys.stderr)
        return 2
    try:
        settings = _load(args.config)
        firewall = NftablesFirewall(
            allowlist=settings.blocking.allowlist,
            public_only=settings.blocking.public_only,
            timeout_seconds=settings.blocking.timeout_seconds,
            dry_run=True,
        )
        if mode == "plan":
            operation = firewall.plan_block(args.ip, args.reason)
        elif mode == "install":
            operation = firewall.install(apply=args.apply, confirm=args.confirm)
        else:
            operation = firewall.block(args.ip, args.reason, apply=args.apply, confirm=args.confirm)
        _record_firewall_action(settings, mode, operation)
        print(json.dumps(operation.to_dict(), indent=2, sort_keys=True))
    except (FirewallError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _live_apply_requested(argv: list[str]) -> bool:
    """Detect the retained apply flag before argparse validates route arguments."""
    if not argv:
        return False
    command_index = 1 if argv[0] == "--" else 0
    if (
        command_index >= len(argv)
        or argv[command_index] not in {"block", "firewall-install"}
    ):
        return False
    for argument in argv[command_index + 1 :]:
        if argument == "--":
            break
        if argument.startswith("--a") and "--apply".startswith(argument):
            return True
    return False


def main(argv: list[str] | None = None) -> None:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if _live_apply_requested(raw_argv):
        print(f"megalodon: {LIVE_APPLY_UNSUPPORTED}", file=sys.stderr)
        raise SystemExit(2)
    args = build_parser().parse_args(raw_argv)
    if args.command == "capabilities":
        code = _capabilities(args)
    elif args.command == "ai":
        code = _ai(args)
    elif args.command == "readiness":
        code = _readiness(args)
    elif args.command == "posture":
        code = _posture(args)
    elif args.command == "hub-plan":
        code = _hub_plan(args)
    elif args.command == "automation-preview":
        code = _automation_preview(args)
    elif args.command == "run":
        code = _run(args)
    elif args.command in {"dashboard", "hud"}:
        code = _dashboard(args)
    elif args.command == "database-migrate":
        code = _database_migrate(args)
    elif args.command == "database-backup":
        code = _database_backup(args)
    elif args.command == "database-restore":
        code = _database_restore(args)
    elif args.command == "database-reconciliation-status":
        code = _database_reconciliation_status(args)
    elif args.command == "database-reconcile":
        code = _database_reconcile(args)
    elif args.command == "firewall-plan":
        args.reason = args.reason
        code = _firewall(args, "plan")
    elif args.command == "firewall-install":
        args.reason = "install isolated table"
        code = _firewall(args, "install")
    elif args.command == "block":
        code = _firewall(args, "block")
    else:
        code = 2
    raise SystemExit(code)
