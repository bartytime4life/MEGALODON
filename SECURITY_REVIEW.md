# MEGALODON architecture security review

## Executive result

The supplied architecture is a useful decomposition for a defensive product,
but its example implementation is not safe to deploy. The highest-risk defects
are command injection, unrestricted automatic blocking, lack of rollback, and
an unauthenticated remote-capable dashboard. The MVP in this folder retains the
capture â†’ analysis â†’ policy â†’ audit â†’ dashboard shape while making observation
the default. For the evaluation-release candidate, firewall response is
plan-only and every retained live-apply route fails closed before it can inspect
or change the host.

This review separates three evidence levels: implemented safeguards in the
current code, adopted but inert contracts, and controls still required before
operational use. Passing CI or closing a contract/test issue does not promote a
proposal into a runtime capability or satisfy independent review.

## Findings and corrections

| Severity | Original design issue | Consequence | MVP correction |
| --- | --- | --- | --- |
| Critical | `subprocess.Popen(..., shell=True)` builds a capture command from interface/filter input | Shell injection and ambiguous tshark argument parsing | No shell; optional Scapy adapter and typed JSONL input |
| Critical | Firewall commands interpolate an IP into shell strings | Command injection and malformed rules | Plan-only output uses fixed `nft` argv built from validated `ipaddress` values; live application is unsupported in the evaluation-release candidate |
| High | Critical findings permanently auto-block an IP | False positives can cut off users, services, or an upstream network | Automatic and operator-requested live blocking are unsupported; proposed blocks remain time-limited plans only |
| High | No allowlist precedence or protected-network policy | A detector can block loopback, private ranges, or management paths | Allowlist precedence and non-global rejection are enforced while producing plans; no live action follows |
| High | No rollback, expiry, or action ledger | Operators cannot explain or safely undo a response | Supported plans are recorded in SQLite and block plans are time-limited; an unsupported apply request produces no false `applied` receipt, and live mutation stays disabled until the restoration gate below is met |
| High | GUI design does not define authentication or bind address | A dashboard could expose threat data and controls on the LAN/WAN | Read-only dashboard binds to `127.0.0.1`, has no control endpoints, bounds its polling and recent-row budget, rejects ambiguous event queries, projects only the five live detection fields used by the UI, and serves same-origin assets under a no-inline CSP |
| High | A loopback listener trusts any HTTP `Host` value | DNS rebinding could let a foreign browser origin read local telemetry | Every dashboard `GET` requires one exact bound-loopback `Host` value and is rejected before routing or SQLite access when the value is missing, repeated, foreign, non-canonical, or names the wrong port |
| High | A read-only UI opens the mutable database store | Dashboard startup can create or migrate state and mixed-query summaries can misstate one moment | A separate `mode=ro`, `query_only` reader requires an existing compatible database in a private boundary, selects only public fields, and reads summary counts in one transaction; live-WAL sidecars remain a disclosed SQLite behavior |
| High | Offline reports could become a path-driven disclosure or analyzer trigger | A web request could expose case data, traverse local files, or start hostile-input processing | One operator-selected private report set is checked and its summary inputs are validated at startup; paths, records, evidence details, remote binds, uploads, and analyzer controls are excluded |
| High | Raw payload hash/contents are part of the capture concept | Payload-derived identifiers can still disclose sensitive data; storage creates a forensic liability | Metadata-only event model; payloads are not represented or stored |
| Medium | Promiscuous capture is treated as a convenience | Requires privilege and may capture traffic outside the operatorâ€™s authority | Optional live capture is explicit, interface-specific, and documented as privileged |
| Medium | External feeds are called synchronously with no privacy contract | IP/domain disclosure, rate-limit failures, stale reputation, and API-key leakage | Feeds are out of-xç¯-¢G§²ÚîÆ­yÚ    if getattr(args, "apply", False):
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
    elif args.command == "hub-plan":
        code = _hub_plan(args)
    elif args.command == "run":
        code = _run(args)
    elif args.command == "dashboard":
        code = _dashboard(args)
    elif args.command == "database-migrate":
        code = _database_migrate(args)
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
