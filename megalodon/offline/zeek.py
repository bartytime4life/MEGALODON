"""Versioned Zeek conn.log import. Flow counts never become packet events."""

from __future__ import annotations

from decimal import Decimal
import json

from .common import (Batch, FlowRecord, Limits, OfflineError, lines, open_input,
                     require_unprivileged_linux, seconds_us, timestamp, uint, version)

TYPES = {
    'ts': 'time', 'uid': 'string', 'id.orig_h': 'addr', 'id.orig_p': 'port',
    'id.resp_h': 'addr', 'id.resp_p': 'port', 'proto': 'enum', 'service': 'string',
    'duration': 'interval', 'orig_bytes': 'count', 'resp_bytes': 'count',
    'conn_state': 'string', 'local_orig': 'bool', 'local_resp': 'bool',
    'missed_bytes': 'count', 'history': 'string', 'orig_pkts': 'count',
    'orig_ip_bytes': 'count', 'resp_pkts': 'count', 'resp_ip_bytes': 'count',
    'tunnel_parents': 'set[string]', 'ip_proto': 'count',
}
REQUIRED = frozenset({'ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p',
                      'proto', 'conn_state', 'orig_pkts', 'resp_pkts',
                      'orig_ip_bytes', 'resp_ip_bytes'})
ADAPTERS = {'json': 'zeek-conn-json-v1', 'tsv': 'zeek-conn-tsv-v1'}


def _object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise OfflineError('DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise OfflineError('NONFINITE_JSON_NUMBER')


def json_object(text: str) -> dict:
    # Bound nesting before decoding, independently of Python's recursion limit.
    if not isinstance(text, str) or len(text) > 1024 * 1024:
        raise OfflineError('JSON_SIZE_LIMIT')
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == chr(92):
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '{[':
            depth += 1
            if depth > 4:
                raise OfflineError('JSON_DEPTH_LIMIT')
        elif char in '}]':
            depth -= 1
    try:
        data = json.loads(text, object_pairs_hook=_object, parse_float=Decimal,
                          parse_int=lambda value: uint(value, 2**63 - 1), parse_constant=_constant)
    except (ValueError, RecursionError):
        raise OfflineError('INVALID_JSON') from None
    if not isinstance(data, dict):
        raise OfflineError('JSON_OBJECT_REQUIRED')
    return data


def parse_flow(data: dict) -> FlowRecord:
    if not REQUIRED <= data.keys() or not data.keys() <= TYPES.keys():
        raise OfflineError('ZEEK_SCHEMA_MISMATCH')
    # Validate all present fields, including those deliberately discarded below.
    for key, value in data.items():
        field_type = TYPES[key]
        if value is None and key not in REQUIRED:
            continue
        if field_type in {'string', 'addr', 'enum'}:
            if not isinstance(value, str) or len(value) > 256 or any(not 32 <= ord(c) <= 126 for c in value):
                raise OfflineError('INVALID_ZEEK_FIELD')
        elif field_type in {'port', 'count'}:
            uint(value, 65535 if field_type == 'port' else 2**40 - 1)
        elif field_type == 'bool':
            if type(value) is not bool:
                raise OfflineError('INVALID_ZEEK_FIELD')
        elif field_type == 'set[string]':
            if (not isinstance(value, list) or len(value) > 16 or
                    any(not isinstance(v, str) or len(v) > 64 or not v.isalnum() for v in value)):
                raise OfflineError('INVALID_ZEEK_FIELD')
    if data['proto'] not in {'tcp', 'udp', 'icmp'}:
        raise OfflineError('UNSUPPORTED_ZEEK_PROTOCOL')
    if data.get('ip_proto') is not None:
        expected = {'tcp': {6}, 'udp': {17}, 'icmp': {1, 58}}[data['proto']]
        if uint(data['ip_proto'], 255) not in expected:
            raise OfflineError('ZEEK_PROTOCOL_MISMATCH')
    duration = data.get('duration')
    return FlowRecord(
        observed_at=timestamp(data['ts']), src_ip=data['id.orig_h'], dst_ip=data['id.resp_h'],
        protocol=data['proto'].upper(), src_port=uint(data['id.orig_p'], 65535),
        dst_port=uint(data['id.resp_p'], 65535),
        duration_us=None if duration is None else seconds_us(duration, 604800),
        orig_packets=uint(data['orig_pkts'], 2**31 - 1),
        resp_packets=uint(data['resp_pkts'], 2**31 - 1),
        byte_count=uint(data['orig_ip_bytes'], 2**40 - 1) + uint(data['resp_ip_bytes'], 2**40 - 1),
        conn_state=data['conn_state'],
    )


def _tsv_value(value: str, field: str) -> object:
    if value == '-':
        return None
    field_type = TYPES[field]
    if field_type == 'bool':
        if value not in {'T', 'F'}:
            raise OfflineError('INVALID_ZEEK_FIELD')
        return value == 'T'
    if field_type == 'set[string]':
        return [] if value == '(empty)' else value.split(',')
    if field_type == 'string' and value == '(empty)':
        return ''
    return value


def _tsv_records(stream, limits: Limits) -> tuple[FlowRecord, ...]:
    headers: dict[str, list[str]] = {}
    records = []
    closed = False
    fixed = {'separator': ['\\x09'], 'set_separator': [','], 'empty_field': ['(empty)'],
             'unset_field': ['-'], 'path': ['conn']}
    for text in stream:
        if any(ord(c) < 32 and c != '\t' or ord(c) > 126 for c in text):
            raise OfflineError('INVALID_ZEEK_TEXT')
        if closed:
            raise OfflineError('DATA_AFTER_ZEEK_CLOSE')
        if text.startswith('#'):
            parts = text[1:].split(' ', 1) if text.startswith('#separator ') else text[1:].split('\t')
            key, values = parts[0], parts[1:]
            if key in headers or key not in {*fixed, 'open', 'close', 'fields', 'types'}:
                raise OfflineError('INVALID_ZEEK_HEADER')
            if key == 'close':
                if len(values) != 1 or not values[0] or len(values[0]) > 64:
                    raise OfflineError('INVALID_ZEEK_HEADER')
                closed = True
            elif records:
                raise OfflineError('ZEEK_SCHEMA_CHANGED')
            elif key in fixed and values != fixed[key]:
                raise OfflineError('INVALID_ZEEK_HEADER')
            elif key == 'open' and (len(values) != 1 or not values[0] or len(values[0]) > 64):
                raise OfflineError('INVALID_ZEEK_HEADER')
            elif key == 'fields':
                if (len(set(values)) != len(values) or not REQUIRED <= set(values) or
                        not set(values) <= TYPES.keys()):
                    raise OfflineError('ZEEK_SCHEMA_MISMATCH')
            elif key == 'types':
                if 'fields' not in headers or values != [TYPES[f] for f in headers['fields']]:
                    raise OfflineError('ZEEK_TYPE_MISMATCH')
            headers[key] = values
            continue
        if not {*fixed, 'fields', 'types'} <= headers.keys():
            raise OfflineError('INCOMPLETE_ZEEK_HEADER')
        if len(records) >= limits.records:
            raise OfflineError('RECORD_LIMIT')
        values = text.split('\t')
        fields = headers['fields']
        if len(values) != len(fields):
            raise OfflineError('ZEEK_COLUMN_MISMATCH')
        records.append(parse_flow({key: _tsv_value(value, key) for key, value in zip(fields, values)}))
    if not closed or not {*fixed, 'fields', 'types'} <= headers.keys():
        raise OfflineError('INCOMPLETE_ZEEK_LOG')
    return tuple(records)


def replay(root: str, relative: str, *, format: str, producer_version: str,
           limits: Limits = Limits()) -> Batch:
    require_unprivileged_linux()
    if format not in ADAPTERS:
        raise OfflineError('UNSUPPORTED_ZEEK_FORMAT')
    tool_version = version(producer_version)
    with open_input(root, relative, limits) as (fd, size):
        stream = lines(fd, limits)
        if format == 'tsv':
            records = _tsv_records(stream, limits)
        else:
            parsed = []
            for text in stream:
                if len(parsed) >= limits.records:
                    raise OfflineError('RECORD_LIMIT')
                parsed.append(parse_flow(json_object(text)))
            records = tuple(parsed)
        result = Batch(ADAPTERS[format], 'flow', records, len(records), 0, size,
                       tool_version, 'operator_declared_unverified')
    return result
