"""Read-only CLI for reference data, detector checks and hypothetical workload."""

from __future__ import annotations

import argparse
import json

from .alert_workload import MAX_POPULATION, RATE_SCALE, UNITS, project_alert_workload
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


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error("duplicate assumption")
        setattr(namespace, self.dest, values)


def _bounded_decimal(value: str, minimum: int, maximum: int) -> int:
    # Bound before int conversion, and admit only canonical ASCII decimals.
    if (
        not 1 <= len(value) <= len(str(maximum))
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value[0] == "0")
    ):
        raise argparse.ArgumentTypeError("invalid assumption")
    number = int(value)
    if not minimum <= number <= maximum:
        raise argparse.ArgumentTypeError("invalid assumption")
    return number


def _population(value: str) -> int:
    return _bounded_decimal(value, 1, MAX_POPULATION)


def _rate(value: str) -> int:
    return _bounded_decimal(value, 0, RATE_SCALE)


def _unit(value: str) -> str:
    if len(value) > 13 or value not in UNITS:
        raise argparse.ArgumentTypeError("invalid unit")
    return value


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
        description="Offline reference context, synthetic checks and hypothetical alert workload.",
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

    workload = groups.add_parser(
        "base-rate",
        allow_abbrev=False,
        help="Project hypothetical alert burden; does not measure detector accuracy.",
    )
    workload.add_argument(
        "--population", type=_population, required=True, action=_Once,
        help="Number of hypothetical evaluation units (1..1000000000).",
    )
    workload.add_argument("--unit", type=_unit, choices=UNITS, required=True, action=_Once)
    for option, help_text in (
        ("--prevalence-ppm", "Condition-present share of all units"),
        ("--sensitivity-ppm", "Alert share of condition-present units"),
        ("--false-positive-ppm", "Alert share of condition-absent units"),
    ):
        workload.add_argument(
            option, type=_rate, required=True, action=_Once,
            help=f"{help_text}, in parts per million (0..1000000).",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.group == "base-rate":
            result = project_alert_workload(
                population=args.population, unit=args.unit,
                prevalence_ppm=args.prevalence_ppm,
                sensitivity_ppm=args.sensitivity_ppm,
                false_positive_ppm=args.false_positive_ppm,
            )
        elif args.group == "reference" and args.operation == "verify":
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
