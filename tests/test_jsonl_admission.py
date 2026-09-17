"""Evidence cannot change meaning between a JSONL producer and admission."""
from datetime import datetime, timezone
from io import StringIO
import json

import pytest

from megalodon.capture import CaptureError, iter_jsonl
from megalodon import cli
from megalodon.models import PacketEvent
from megalodon.validation import SQLITE_INTEGER_MAX


EVENT = PacketEvent(datetime(2026, 1, 1, tzinfo=timezone.utc),
                    '192.0.2.1', '198.51.100.2', 'TCP').to_dict()


def record(extra):
    return json.dumps(EVENT)[:-1] + ',' + extra + '}'


@pytest.mark.parametrize('text', [
    record('"src_ip":"203.0.113.9"'),
    record('"src_ip":"192.0.2.1"'),
    record('"src_\\u0069p":"203.0.113.9"'),
    record('"timestamp":"2026-01-01T00:00:00Z"'),
    record('"payload":"PRIVATE_MARKER"'),
    record('"command":"PRIVATE_MARKER"'),
    record('"confidence":0.9'),
    record('"extension":{"private":"PRIVATE_MARKER"}'),
    json.dumps(EVENT).replace('"metadata": {}',
        '"metadata":{"source_adapter":"scapy","source_adapter":"scapy"}'),
    json.dumps(EVENT).replace('"byte_count": 0', '"byte_count":' + '9' * 5000),
    json.dumps(EVENT).replace('"byte_count": 0', '"byte_count":9223372036854775808'),
    json.dumps(EVENT).replace('"metadata": {}', '"metadata":{"a":{"b":1}}'),
    '[' * 2000 + ']' * 2000,
    'null', '[]', '42', '"PRIVATE_MARKER"',
] + [json.dumps(EVENT).replace('"byte_count": 0', '"byte_count":' + number)
     for number in ('NaN', 'Infinity', '-Infinity', '1.0', '1e0', '1e9999', '-1', '-0')])
def test_invalid_records_fail_before_event_construction(text, monkeypatch):
    # Domain constructor is never reached for these lexical/schema failures.
    monkeypatch.setattr(PacketEvent, 'from_mapping',
                        lambda *_: pytest.fail('invalid input reached domain constructor'))
    with pytest.raises(CaptureError, match='^invalid JSONL event at line 3$') as caught:
        list(iter_jsonl(StringIO('# comment\n\n' + text + '\n')))
    assert caught.value.__suppress_context__
    assert 'PRIVATE_MARKER' not in str(caught.value)


@pytest.mark.parametrize('limit', [True, False, 1.0, '100', None, 0, -1, 65537])
def test_invalid_limits_do_not_read_stream(limit):
    class Unreadable:
        def readline(self, *_):
            pytest.fail('invalid limit read stream')
    with pytest.raises(ValueError, match='max_line_bytes must be an integer'):
        list(iter_jsonl(Unreadable(), max_line_bytes=limit))


@pytest.mark.parametrize('timestamp_key', ['observed_at', 'timestamp'])
def test_canonical_and_legacy_timestamp_roundtrip(timestamp_key):
    event = dict(EVENT)
    event[timestamp_key] = event.pop('observed_at')
    event['byte_count'] = SQLITE_INTEGER_MAX
    event['tcp_flags'] = ['ACK', 'SYN']
    event['interface'] = 'quoted " brackets [{}] backslash \\ end'
    parsed = list(iter_jsonl(StringIO(json.dumps(event) + '\n')))[0]
    assert parsed.byte_count == SQLITE_INTEGER_MAX
    assert parsed.tcp_flags == frozenset({'ACK', 'SYN'})
    assert parsed.interface == event['interface']


def test_line_byte_boundary_includes_newline_and_utf8():
    text = json.dumps(EVENT, ensure_ascii=False).replace('"interface": null', '"interface": "é"') + '\n'
    size = len(text.encode('utf-8'))
    assert len(list(iter_jsonl(StringIO(text), max_line_bytes=size))) == 1
    with pytest.raises(CaptureError, match='exceeds'):
        list(iter_jsonl(StringIO(text), max_line_bytes=size - 1))


@pytest.mark.parametrize('ending', ['\n', '\r\n', '\r', ''])
@pytest.mark.parametrize('limit_name', ['max_line_bytes', 'max_input_bytes'])
@pytest.mark.parametrize('interface', ['eth0', 'é'])
def test_file_byte_boundaries_preserve_utf8_and_line_endings(
    tmp_path, monkeypatch, ending, limit_name, interface
):
    event = dict(EVENT, interface=interface)
    raw = (json.dumps(event, ensure_ascii=False) + ending).encode('utf-8')
    source = tmp_path / 'events.jsonl'
    source.write_bytes(raw)
    limit = len(raw)
    monkeypatch.setattr(
        cli, 'iter_jsonl', lambda stream: iter_jsonl(stream, **{limit_name: limit})
    )

    # Equality is admitted; one byte less must refuse even a CRLF record.
    assert len(list(cli._jsonl_file_events(source))) == 1
    limit -= 1
    message = ('^JSONL input-byte limit exceeded at line 1$'
               if limit_name == 'max_input_bytes'
               else f'^JSONL event at line 1 exceeds {limit} bytes$')
    with pytest.raises(CaptureError, match=message):
        list(cli._jsonl_file_events(source))


def test_literal_surrogate_normalizes_to_capture_error():
    with pytest.raises(CaptureError, match='^invalid JSONL event at line 1$'):
        list(iter_jsonl(StringIO('\ud800')))


@pytest.mark.parametrize('field', ['src_port', 'dst_port', 'byte_count', 'dns_query_length'])
def test_oversized_numeric_strings_normalize_to_capture_error(field):
    hostile = dict(EVENT, **{field: '9' * 5000})
    events = iter_jsonl(StringIO(json.dumps(EVENT) + '\n' + json.dumps(hostile) + '\n'))
    assert next(events).src_ip == EVENT['src_ip']
    with pytest.raises(CaptureError, match='^invalid JSONL event at line 2$') as caught:
        next(events)
    assert caught.value.__suppress_context__
    assert list(events) == []


def test_decode_failure_normalizes_to_capture_error():
    class BrokenUtf8:
        def readline(self, *_):
            raise UnicodeDecodeError('utf-8', b'\xff', 0, 1, 'invalid start byte')
    with pytest.raises(CaptureError, match='^invalid JSONL event at line 1$'):
        list(iter_jsonl(BrokenUtf8()))


def test_valid_prefix_is_yielded_but_invalid_record_and_suffix_are_not():
    stream = StringIO(json.dumps(EVENT) + '\n' + record('"src_ip":"203.0.113.9"') + '\n' + json.dumps(EVENT))
    events = iter_jsonl(stream)
    assert next(events).src_ip == EVENT['src_ip']
    with pytest.raises(CaptureError, match='^invalid JSONL event at line 2$'):
        next(events)
    assert list(events) == []
