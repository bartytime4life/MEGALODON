"""Read-only comparison of two explicitly selected local metadata baselines."""

from __future__ import annotations

import argparse
import json

from .baseline import read_reference, validate_baseline
from .common import Limits, OfflineError, require_unprivileged_linux

MAX_CHANGED_PORTS = 256
MAX_CHANGED_MINUTES = 256
MAX_RECEIPT_BYTES = 64 * 1024
BYTE_BAND_NAMES = ('small', 'medium', 'large')
LIMITATIONS = (
    'Counts describe only the accepted records in the selected baselines.',
    'Absence in a sample does not establish absence on the network.',
    'Shares use accepted records, not elapsed time or source-hours.',
    'Byte bands count records by size, not byte volume or bandwidth.',
    'Relative-minute bins use each sample\'s own earliest record; wall-clock windows are not aligned.',
    'Collection windows, capture loss, provenance and representativeness are not attested.',
    'Structural compatibility does not establish statistical comparability.',
    'No threat probability, significance, calibration or response authority is inferred.',
)


def _receipt(status: str) -> dict:
    return {'schema': 'offline-baseline-comparison-v1', 'status': status,
            'network_access_performed': False, 'persistence_status': 'not_attempted',
            'action_status': 'not_attempted'}


def _change(before: int, after: int, reference_size: int, current_size: int) -> str:
    if before == 0 and after == 0:
        return 'share_unchanged'
    if before == 0:
        return 'not_in_reference'
    if after == 0:
        return 'not_in_current'
    # Cross multiplication preserves exact fractions, without rounding thresholds.
    delta = after * reference_size - before * current_size
    return 'share_increased' if delta > 0 else 'share_decreased' if delta < 0 else 'share_unchanged'


def compare_baselines(reference: object, current: object) -> dict:
    """Compare aggregate distributions in memory; never rank threats or run tools."""
    before, after = validate_baseline(reference), validate_baseline(current)
    if (before.adapter, before.record_kind) != (after.adapter, after.record_kind):
        raise OfflineError('INCOMPATIBLE_BASELINE')
    if before.record_count < 5:
        raise OfflineError('REFERENCE_BASELINE_TOO_SMALL')
    if after.record_count == 0:
        raise OfflineError('CURRENT_BASELINE_EMPTY')

    def row(reference_count: int, current_count: int) -> dict:
        return {'reference_count': reference_count, 'current_count': current_count,
                'change': _change(reference_count, current_count,
                                  before.record_count, after.record_count)}

    previous_protocols, current_protocols = dict(before.protocols), dict(after.protocols)
    protocols = [dict(protocol=name, **row(previous_protocols.get(name, 0), current_protocols.get(name, 0)))
                 for name in sorted(previous_protocols.keys() | current_protocols.keys())]
    previous_ports = {(name, port): count for name, port, count in before.destination_ports}
    current_ports = {(name, port): count for name, port, count in after.destination_ports}
    changed = []
    for name, port in sorted(previous_ports.keys() | current_ports.keys()):
        counts = row(previous_ports.get((name, port), 0), current_ports.get((name, port), 0))
        if counts['change'] == 'share_unchanged':
            continue
        if len(changed) == MAX_CHANGED_PORTS:
            raise OfflineError('COMPARISON_PORT_LIMIT')
        changed.append(dict(protocol=name, port=port, **counts))

    byte_bands = [dict(band=name, **row(before.byte_bands[index], after.byte_bands[index]))
                  for index, name in enumerate(BYTE_BAND_NAMES)]

    previous_minutes = dict(before.relative_minutes)
    current_minutes = dict(after.relative_minutes)
    changed_minutes = []
    for minute in sorted(previous_minutes.keys() | current_minutes.keys()):
        counts = row(previous_minutes.get(minute, 0), current_minutes.get(minute, 0))
        if counts['change'] == 'share_unchanged':
            continue
        if len(changed_minutes) == MAX_CHANGED_MINUTES:
            raise OfflineError('COMPARISON_MINUTE_LIMIT')
        changed_minutes.append(dict(minute=minute, **counts))

    return dict(_receipt('compared'), adapter=before.adapter, record_kind=before.record_kind,
                reference_records=before.record_count, current_records=after.record_count,
                comparison_basis='accepted_record_share', quality_label='uncalibrated',
                protocols=protocols, changed_destination_ports=changed,
                changed_destination_ports_count=len(changed), byte_bands=byte_bands,
                changed_relative_minutes=changed_minutes,
                changed_relative_minutes_count=len(changed_minutes), truncated=False,
                limitations=list(LIMITATIONS))


def _failure(code: str) -> str:
    return json.dumps(dict(_receipt('failed'), failure_code=code), sort_keys=True)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, _failure('INVALID_ARGUMENTS') + '\n')


class _Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error('duplicate argument')
        setattr(namespace, self.dest, values)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description='Compare two local baselines; bounded JSON to stdout only.',
                     allow_abbrev=False)
    parser.add_argument('--input-root', required=True, action=_Once)
    parser.add_argument('--reference', required=True, action=_Once)
    parser.add_argument('--current', required=True, action=_Once)
    args = parser.parse_args(argv)
    try:
        require_unprivileged_linux()
        reference = read_reference(args.input_root, args.reference, Limits())
        current = read_reference(args.input_root, args.current, Limits())
        result = compare_baselines(reference, current)
        output = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False)
        if len(output.encode('ascii')) + 1 > MAX_RECEIPT_BYTES:
            raise OfflineError('COMPARISON_RECEIPT_LIMIT')
    except (OfflineError, OSError) as exc:
        # OfflineError contains fixed codes from the bounded local readers only.
        print(_failure(str(exc) if isinstance(exc, OfflineError) else 'LOCAL_IO_ERROR'))
        return 1
    print(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
