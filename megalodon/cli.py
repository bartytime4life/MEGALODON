"""Command-line entry point."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys

from .capabilities import catalog
from .capture import CaptureError, iter_jsonl, iter_sample, iter_scapy
from .config import load_settings
from .firewall import FirewallError, NftablesFirewall
from .models import ActionRecord
from .service import MegalodonService
from .storage import Store
from .validation import safe_text, ValidationError


MAX_RUN_EVENTS = 10_000_000


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
    sub = parser.add_subparsers(dest="command", required=True)

    capabilities = sub.add_parser("capabilities", help="print the static platform and free-software catalog")
    capabilities.add_argument(
        "--platform",
        choices=("linux", "windows", "other"),
        help="show one documented profile; defaults to the current runtime family",
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
    run.add_argument("--config", default="config/settings.toml")
    run.add_argument("--source", choices=("sample", "jsonl", "scapy"), default=None)
    run.add_argument("--input", type=Path, help="JSONL input file; stdin is used when omitted")
    run.add_argument("--interface", help="capture interface for --source scapy")
    run.add_argument("--demo-threat", action="store_true", help="add synthetic detections to sample data")
    run.add_argument(
        "--max-events",
        type=_bounded_cli_integer("max-events", 0, MAX_RUN_EVENTS),
        default=0,
        help=f"stop after N events (0 means no limit; maximum {MAX_RUN_EVENTS})",
    )

    dashboard = sub.add_parser("dashboard", help="serve the read-only local dashboard")
    dashboard.add_argument("--config", default="config/settings.toml")
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
    plan.add_argument("--config", default="config/settings.toml")

    install = sub.add_parser("firewall-install", help="install MEGALODON's isolated nftables table")
    install.add_argument("--config", default="config/settings.toml")
    install.add_argument("--apply", action="store_true")
    install.add_argument("--confirm", help="must be MEGALODON when applying")

    block = sub.add_parser("block", help="plan or explicitly apply one time-limited block")
    block.add_argument("ip")
    block.add_argument("--reason", required=True)
    block.add_argument("--config", default="config/settings.toml")
    block.add_argument("--apply", action="store_true")
    block.add_argument("--confirm", help="must exactly match the target IP when applying")

    return parser


def _configure_logging(level: str) -> None:
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(levelname)s %(message)s")


def _capabilities(args: argparse.Namespace) -> int:
    print(json.dumps(catalog(args.platform), sort_keys=True))
    return 0


def _hub_plan(args: argparse.Namespace) -> int:
    from .hub import integration_plan

    print(json.dumps(integration_plan(args.platform, args.workflow), sort_keys=True))
    return 0


def _load(config: str):
    settings = load_settings(config)
    _configure_logging(settings.log_level)
    return settings


def _events_for(args: argparse.Namespace, settings):
    source = args.source or settings.capture_source
    if source == "sample":
        return iter_sample(include_demo_threat=args.demo_threat)
    if source == "jsonl":
        if args.input:
            return iter_jsonl(args.input.open("r", encoding="utf-8"))
        return iter_jsonl(sys.stdin)
    if source == "scapy":
        return iter_scapy(args.interface or settings.interface)
    raise CaptureError(f"unsupported source: {source}")


def _run(args: argparse.Namespace) -> int:
    settings = _load(args.config)
    processed = 0
    detections = 0
    try:
        with Store(settings.db_path) as store:
            service = MegalodonService(settings, store)
            for event in _events_for(args, settings):
                detections += len(service.process(event))
                processed += 1
                if args.max_events and processed >= args.max_events:
                    break
            print(json.dumps({"processed": processed, "detections": detections, **store.summary()}, sort_keys=True))
    except (CaptureError, OSError, ValueError) as exc:
        print(f"megalodon: {exc}", file=sys.stderr)
        return 2
    return 0


def _dashboard(args: argparse.Namespace) -> int:
    settings = _load(args.config)
    host = args.host if args.host is not None else settings.dashboard.host
    port = args.port if args.port is not None else settings.dashboard.port
    from .dashboard import loopback_host, serve
    from .offline_projection import load_offline_projection

    try:
        host = loopback_host(host, allow_remote=args.allow_remote)
        offline_summary = load_offline_projection(args.offline_run) if args.offline_run else None
        with Store(settings.db_path) as store:
            serve(
                store,
                host,
                port,
                enabled=settings.dashboard.enabled,
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


def _record_firewall_action(settings, mode: str, operation) -> None:
    action = "firewall_install" if mode == "install" else "block"
    details = operation.to_dict()
    try:
        safe_text(details["message"], "operation message", 256)
    except ValidationError:
        details["message"] = "multiline or oversized operation plan omitted from audit details"
    with Store(settings.db_path) as store:
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
    settings = _load(args.config)
    firewall = NftablesFirewall(
        allowlist=settings.blocking.allowlist,
        public_only=settings.blocking.public_only,
        timeout_seconds=settings.blocking.timeout_seconds,
        dry_run=not getattr(args, "apply", False),
    )
    try:
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


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if args.command == "capabilities":
        code = _capabilities(args)
    elif args.command == "hub-plan":
        code = _hub_plan(args)
    elif args.command == "run":
        code = _run(args)
    elif args.command == "dashboard":
        code = _dashboard(args)
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
