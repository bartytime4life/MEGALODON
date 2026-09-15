"""Closed, source-qualified baseline validation shared by offline consumers."""

from __future__ import annotations

from dataclasses import dataclass, replace
import os

from .common import Limits, OfflineError, open_input
from .zeek import json_object

BASELINE_SCHEMA = 'offline-baseline-v1'
PROTOCOLS = frozenset({'TCP', 'UDP', 'ICMP', 'ICMPV6', 'OTHER'})
SOURCE_KINDS = {
    'tshark-fields-v1': 'packet',
    'zeek-conn-json-v1': 'flow',
    'zeek-conn-tsv-v1': 'flow',
}
FIELDS = {'schema', 'adapter', 'record_kind', 'record_count', 'total_bytes',
          'protocols', 'destination_ports', 'byte_bands', 'relative_minutes'}


@dataclass(frozen=True)
class Baseline:
    adapter: str
    record_kind: str
    record_count: int
    total_bytes: int
    protocols: tuple[tuple[str, int], ...]
    destination_ports: tuple[tuple[str, int, int], ...]
    byte_bands: tuple[int, int, int]
    relative_minutes: tuple[tuple[int, int], ...]


def _invalid() -> None:
    raise OfflineError('INVALID_BASELINE')


def _uint(value: object, maximum: int) -> int:
    # Baselines are generated JSON, not text fields from an analyzer.
    if type(value) is not int or not 0 <= value <= maximum:
        _invalid()
    return value


def _items(value: object, fields: set[str], maximum: int) -> list[dict]:
    if type(value) is not list or len(value) > maximum:
        _invalid()
    if any(type(item) is not dict or set(item) != fields for item in value):
        _invalid()
    return value


def validate_baseline(value: object) -> Baseline:
    """Validate all counts before returning an immutable, normalized summary.

    Each supported adapter admits TCP/UDP only with destination-port metadata.
    Its per-protocol port totals must therefore equal its protocol count.
    Structural consistency does not attest the origin or coverage of a file.
    """
    if (type(value) is not dict or set(value) != FIELDS or
            value['schema'] != BASELINE_SCHEMA or
            type(value['adapter']) is not str or value['adapter'] not in SOURCE_KINDS or
            value['record_kind'] != SOURCE_KINDS[value['adapter']]):
        raise OfflineError('INCOMPATIBLE_BASELINE')
    size = _uint(value['record_count'], 10_000)
    total_bytes = _uint(value['total_bytes'], size * (2**41 - 2))
    protocols = {}
    for item in _items(value['protocols'], {'protocol', 'count'}, len(PROTOCOLS)):
        name = item['protocol']
        if type(name) is not str or name not in PROTOCOLS or name in protocols:
            _invalid()
        count = _uint(item['count'], size)
        if count == 0:
            _invalid()
        protocols[name] = count
    if sum(protocols.values()) != size:
        _invalid()
    if value['record_kind'] == 'flow' and set(protocols) - {'TCP', 'UDP', 'ICMP'}:
        _invalid()

    ports = {}
    port_totals = {'TCP': 0, 'UDP': 0}
    for item in _items(value['destination_ports'], {'protocol', 'port', 'count'}, size):
        name = item['protocol']
        if type(name) is not str or name not in port_totals or name not in protocols:
            _invalid()
        port = _uint(item['port'], 65535)
        count = _uint(item['count'], size)
        if (name, port) in ports or count == 0:
            _invalid()
        ports[name, port] = count
        port_totals[name] += count
    if any(port_totals[name] != protocols.get(name, 0) for name in port_totals):
        _invalid()

    bands = value['byte_bands']
    if type(bands) is not dict or set(bands) != {'small', 'medium', 'large'}:
        _invalid()
    byte_bands = tuple(_uint(bands[name], size) for name in ('small', 'medium', 'large'))
    if sum(byte_bands) != size:
        _invalid()
    # Every admitted record must fit its declared size band. Counts that sum
    # correctly can still describe an impossible byte total. Use each adapter's
    # admitted per-record ceiling, not the much larger flow ceiling for packets.
    small, medium, large = byte_bands
    maximum_record_bytes = 262144 if value['record_kind'] == 'packet' else 2**41 - 2
    minimum_bytes = medium * 512 + large * 4096
    maximum_bytes = small * 511 + medium * 4095 + large * maximum_record_bytes
    if not minimum_bytes <= total_bytes <= maximum_bytes:
        _invalid()

    minutes = {}
    for item in _items(value['relative_minutes'], {'minute', 'count'}, size):
        minute = _uint(item['minute'], 68_374_080)
        count = _uint(item['count'], size)
        if minute in minutes or count == 0:
            _invalid()
        minutes[minute] = count
    if sum(minutes.values()) != size:
        _invalid()
    # Offsets are relative to the earliest admitted observation, so every
    # nonempty generated baseline necessarily includes a minute-zero record.
    if size and 0 not in minutes:
        _invalid()

    return Baseline(value['adapter'], value['record_kind'], size, total_bytes,
                    tuple(sorted(protocols.items())),
                    tuple((name, port, count) for (name, port), count in sorted(ports.items())),
                    byte_bands, tuple(sorted(minutes.items())))


def read_reference(root: str, relative: str, limits: Limits) -> dict:
    """Read one existing bounded baseline; never write or hash input bytes."""
    bounded = replace(limits, input_bytes=min(limits.input_bytes, 1024 * 1024))
    data = bytearray()
    with open_input(root, relative, bounded) as (fd, _):
        while True:
            chunk = os.read(fd, min(65536, bounded.input_bytes - len(data) + 1))
            if not chunk:
                break
            if len(data) + len(chunk) > bounded.input_bytes:
                raise OfflineError('BASELINE_SIZE_LIMIT')
            data.extend(chunk)
    try:
        return json_object(data.decode('ascii'))
    except UnicodeDecodeError:
        raise OfflineError('INVALID_BASELINE_ENCODING') from None
