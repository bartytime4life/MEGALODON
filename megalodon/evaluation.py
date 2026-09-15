"""Read-only CLI for pinned IANA hints and synthetic detector evaluation."""

from __future__ import annotations

import argparse
import json

from .reference import (
    ReferenceDataError,
    evaluate_corpus,
    load_iana,
    lookup_port,
    lookup_protocol,
)


def _failure(error: str) -> dict[str, object]:
    return {
        "schema": "reference-operation-error-v1",
        "status": "failed",
        "error": error,
        "network_access_performed": False,
        "persistence_status": "not_attempted",
        "action_status": "not_attempted",
    }


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, json.dumps(_failure("INVALID_ARGUMENTS"), sort_keys=True) + "\n")


def _port(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or not 0 <= int(value) <= 65_535:
        raise argparse.ArgumentTypeError("invalid port")
    return int(value)


def _protocol_number(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or not 0 <= int(value) <= 255:
        raise argparse.ArgumentTypeError("invalid protocol number")
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="megalodon-evaluate",
        description="Offline, read-only IANA context and synthetic detector evaluation.",
        allow_abbrev=False,
    )
    groups = parser.add_subparsers(dest="group", required=True)

    reference = groups.add_parser("reference", allow_abbrev=False)
    reference_commands = reference.add_subparsers(dest="operation", required=True)
    reference_commands.add_parser("verify", allow_abbrev=False)
    port = reference_commands.add_parser("port", allow_abbrev=False)
    port.add_argument("transport", choices=("tcp", "udp", "sctp", "dccp"))
    port.add_argument("port", type=_port)
    protocol = reference_commands.add_parser("protocol", allow_abbrev=False)
    protocol.add_argument("number", type=_protocol_number)

    corpus = groups.add_parser("corpus", allow_abbrev=False)
    corpus.add_argument("--scenario")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.group == "reference" and args.operation == "verify":
            result = load_iana().summary()
        elif args.group == "reference" and args.operation == "port":
            result = lookup_port(args.transport, args.port)
        elif args.group == "reference" and args.operation == "protocol":
            result = lookup_protocol(args.number)
        else:
            result = evaluate_corpus(args.scenario)
    except ReferenceDataError as exc:
        print(json.dumps(_failure(str(exc)), sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("all_match", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
