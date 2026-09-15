"""Command-line entry point."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import signal
import sqlite3
import sys

from . import __version__
from .capabilities import catalog
from .posture import local_posture
from .capture import CaptureError, iter_jsonl, iter_sample, iter_scapy
from .config import load_settings
from .firewall import FirewallError, LIVE_APPLY_UNSUPPORTED, NftablesFirewall
from .models import ActionRecord
from .service import MegalodonService
from .storage import (
    DashboardStore,
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


def _bounded_cli_integer(name: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        candidate = value.strip()
        if not candidate.isascii() or not candidate.isdecimal():
            raise argparse.ArgumentTypeError(f"{name} must be a decimal integer")
        parsed = int(candidate)
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

    capabilities = sub.add_parser("capabilities", help="print the static platform and free-software catalog")
    capabilities.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="show one documented profile; defaults to the current runtime family",
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

    dashboard = sub.add_parser("dashboard", help="serve the read-only local dashboard")
    dashboard.add_argument("--config", help="explicit TOML settings file; safe built-in defaults are used when omitted")
    dashboard.add_argument("--host")
    dashboard.add_argument("--port", type=_bounded_cli_integer("port", 1, 65535))
    dashboard.add_argument("--allow-remote", action="store_true", help="removed unsafe option; supplying it refuses startup")
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


def _posture(args: argparse.Namespace) -> int:
    print(json.dumps(local_posture(args.platform), sort_keys=True))
    return 0


def _hub_plan(args: argparse.Namespace) -> int:
    from .hub import integration_plan

    print(json.dumps(integration_plan(args.platform, args.workflow), sort_keys=True))
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
    with _owned_source(path.open("r", encoding="utf-8")) as stream:
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
    if alarm_signal in pending_signals:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise ValueError("max-seconds cannot start with a pending SIGALRM")

    handler_installed = False
    timer_started = False
    mask_restored = False
    try:
        _require_single_threaded_run_deadline()
        try:
            signal.signal(alarm_signal, deadline_exceeded)
        except ValueError:
            raise ValueError(
                "max-seconds requires the interpreter main thread"
            ) from None
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
            try:
                signal.setitimer(timer_kind, *previous_timer)
            except (OSError, ValueError):
                raise ValueError(
                    "max-seconds could not restore a competing POSIX process timer"
                ) from None
            timer_started = False
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
            mask_restored = True
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            raise CaptureError("ingestion deadline exceeded")
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
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
                try:
                    if cleanup_mask is not None:
                        # Keep the deadline handler installed while unblocking so
                        # a just-pending MEGALODON alarm cannot reach the prior
                        # handler. Python dispatches it here as CaptureError.
                        signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
                finally:
                    if timer_inactive and (
                        not mask_restored or cleanup_mask is not None
                    ):
                        signal.signal(alarm_signal, previous_handler)
                if cleanup_entry_error is not None:
                    raise cleanup_entry_error
                if cancellation_error is not None:
                    raise cancellation_error
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
    from .dashboard import loopback_host, serve
    from .offline_projection import load_offline_projection

    try:
        settings = _load(args.config)
        host = args.host if args.host is not None else settings.dashboard.host
        port = args.port if args.port is not None else settings.dashboard.port
        host = loopback_host(host, allow_remote=args.allow_remote)
        enabled = getattr(settings.dashboard, "enabled", True)
        if not enabled:
            raise ValueError("dashboard is disabled by configuration")
        offline_summary = load_offline_projection(args.offline_run) if args.offline_run else None
        with DashboardStore(settings.db_path) as store:
            serve(
                store,
                host,
                port,
                enabled=enabled,
                allow_remote=args.allow_remote,
                offline_summary=offline_summary,
                refresh_seconds=(
                    args.refresh_seconds if args.refresh_seconds is not None else settings.dashboard.refresh_seconds
                ),
                event_limit=args.event_limit if args.event_limit is not None else settings.dashboard.event_limit,
            )
    except (OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _database_migrate(args: argparse.Namespace) -> int:
    try:
        settings = _load(args.config)
        print(json.dumps(migrate_database(settings.db_path), sort_keys=True))
    except (OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


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
    elif args.command == "posture":
        code = _posture(args)
    elif args.command == "hub-plan":
        code = _hub_plan(args)
    elif args.command == "run":
        code = _run(args)
    elif args.command == "dashboard":
        code = _dashboard(args)
    elif args.command == "database-migrate":
        code = _database_migrate(args)
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
