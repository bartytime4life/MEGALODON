"""Synthetic baseline consistency, exact comparison, and no-action boundaries."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import builtins
import json
import os
import socket
import sqlite3
import subprocess

import pytest

from megalodon import offline_projection
from megalodon.models import PacketEvent
from megalodon.offline import analysis, compare, reports
from megalodon.offline.baseline import validate_baseline
from megalodon.offline.common import Batch, Limits, OfflineError


def _batch(pairs=None):
    pairs = pairs if pairs is not None else [('TCP', 443)] * 3 + [('UDP', 53)] * 2 + [('ICMP', None)]
    records = tuple(PacketEvent(observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                               src_ip='192.0.2.1', dst_ip='198.51.100.1', protocol=name,
                               src_port=1234 if port is not None else None,
                               dst_port=port, byte_count=64) for name, port in pairs)
    return Batch('tshark-fields-v1', 'packet', records, len(records), 0,
                 64 * len(records), '4.6.0', 'subprocess_version')


def _value(pairs=None):
    return analysis.baseline(_batch(pairs))


def _sized_value(byte_counts):
    records = tuple(PacketEvent(observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
                               src_ip='192.0.2.1', dst_ip='198.51.100.1', protocol='TCP',
                               src_port=1234, dst_port=443, byte_count=size)
                    for size in byte_counts)
    batch = Batch('tshark-fields-v1', 'packet', records, len(records), 0,
                 sum(byte_counts), '4.6.0', 'subprocess_version')
    return analysis.baseline(batch)


def _minute_value(minute_counts):
    records = tuple(PacketEvent(
        observed_at=datetime(2026, 9, 1, tzinfo=timezone.utc) + timedelta(minutes=minute, seconds=i),
        src_ip='192.0.2.1', dst_ip='198.51.100.1', protocol='TCP',
        src_port=1234, dst_port=443, byte_count=64)
        for minute, count in minute_counts for i in range(count))
    batch = Batch('tshark-fields-v1', 'packet', records, len(records), 0,
                 64 * len(records), '4.6.0', 'subprocess_version')
    return analysis.baseline(batch)


def _set(field, value):
    return lambda baseline: baseline.__setitem__(field, value)


MALFORMED = [
    _set('protocols', [{'protocol': 'TCP', 'count': 1}, {'protocol': 'UDP', 'count': 4},
                       {'protocol': 'ICMP', 'count': 1}]),  # totals agree; transports contradict
    _set('destination_ports', [{'protocol': 'TCP', 'port': 443, 'count': 4},
                               {'protocol': 'UDP', 'port': 53, 'count': 1}]),
    _set('destination_ports', [{'protocol': 'TCP', 'port': 443, 'count': 2},
                               {'protocol': 'UDP', 'port': 53, 'count': 2}]),
    _set('destination_ports', []),
    lambda value: value['destination_ports'].append(dict(value['destination_ports'][0])),
    lambda value: value['destination_ports'][0].__setitem__('protocol', ['SECRET']),
    lambda value: value['destination_ports'][0].__setitem__('port', True),
    lambda value: value['destination_ports'][0].__setitem__('count', '3'),
    lambda value: value['protocols'][0].__setitem__('count', 0),
    lambda value: value['relative_minutes'][0].__setitem__('count', 5),
    _set('protocols', None), _set('byte_bands', []), _set('total_bytes', -1),
    _set('record_count', True), _set('record_count', 10001),
    _set('raw_payload', 'SECRET'), _set('adapter', 'unknown'), _set('record_kind', 'flow'),
]


@pytest.mark.parametrize('alter', MALFORMED)
def test_all_baseline_consumers_reject_contradictions(alter):
    value = _value()
    alter(value)
    run = {'adapter': 'tshark-fields-v1', 'record_kind': 'packet', 'accepted_records': 6}
    for consume in (validate_baseline, lambda data: analysis.validate_reference(data, _batch()),
                    lambda data: compare.compare_baselines(data, _value())):
        with pytest.raises(OfflineError) as error:
            consume(value)
        assert str(error.value) in {'INVALID_BASELINE', 'INCOMPATIBLE_BASELINE'}
        assert 'SECRET' not in str(error.value)
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_BASELINE$'):
        offline_projection._baseline(value, run)


@pytest.mark.parametrize('value', [None, [], 'SECRET', 1, True])
def test_top_level_json_types_fail_closed(value):
    with pytest.raises(OfflineError, match='^INCOMPATIBLE_BASELINE$'):
        compare.compare_baselines(value, _value())


def test_shared_validator_preserves_empty_and_nontransport_projection():
    empty = validate_baseline(_value([]))
    assert empty.record_count == 0 and empty.destination_ports == ()
    only_icmp = validate_baseline(_value([('ICMP', None)] * 5))
    assert only_icmp.protocols == (('ICMP', 5),) and only_icmp.destination_ports == ()


def test_comparison_is_exact_deterministic_and_does_not_mutate_inputs():
    before = _value([('TCP', 443)] * 3 + [('UDP', 53)] * 3)
    after = _value([('TCP', 443)] * 2 + [('UDP', 53)] + [('TCP', 8443)])
    saved = deepcopy((before, after))
    result = compare.compare_baselines(before, after)
    assert result['reference_records'] == 6 and result['current_records'] == 4
    assert result['comparison_basis'] == 'accepted_record_share'
    assert result['protocols'] == [
        {'protocol': 'TCP', 'reference_count': 3, 'current_count': 3, 'change': 'share_increased'},
        {'protocol': 'UDP', 'reference_count': 3, 'current_count': 1, 'change': 'share_decreased'},
    ]
    assert result['changed_destination_ports'] == [
        {'protocol': 'TCP', 'port': 8443, 'reference_count': 0, 'current_count': 1,
         'change': 'not_in_reference'},
        {'protocol': 'UDP', 'port': 53, 'reference_count': 3, 'current_count': 1,
         'change': 'share_decreased'},
    ]
    assert (before, after) == saved
    for value in (before, after):
        value['protocols'].reverse()
        value['destination_ports'].reverse()
    assert result == compare.compare_baselines(before, after)
    assert result['quality_label'] == 'uncalibrated'
    assert result['truncated'] is False
    encoded = json.dumps(result)
    for private in ('192.0.2.1', '198.51.100.1', '2026-09-01', 'sha256', 'confidence_score'):
        assert private not in encoded


def test_equal_shares_do_not_turn_volume_growth_into_distribution_change():
    before = _value([('TCP', 443)] * 5)
    after = _value([('TCP', 443)] * 10)
    result = compare.compare_baselines(before, after)
    assert result['protocols'][0]['change'] == 'share_unchanged'
    assert result['changed_destination_ports'] == []
    after = _value([('TCP', 8443)])
    changes = compare.compare_baselines(before, after)['changed_destination_ports']
    assert [item['change'] for item in changes] == ['not_in_current', 'not_in_reference']


def test_byte_bands_always_report_all_three_categories():
    before = _sized_value([100] * 5)  # all small
    after = _sized_value([100, 100, 5000, 5000, 5000])  # mixed small/large
    result = compare.compare_baselines(before, after)
    assert result['byte_bands'] == [
        {'band': 'small', 'reference_count': 5, 'current_count': 2, 'change': 'share_decreased'},
        {'band': 'medium', 'reference_count': 0, 'current_count': 0, 'change': 'share_unchanged'},
        {'band': 'large', 'reference_count': 0, 'current_count': 3, 'change': 'not_in_reference'},
    ]


def test_changed_relative_minutes_reports_shifted_minutes_only():
    # Equal totals (15 -> 15) isolate a pure share shift: minute 2 keeps the
    # same count and total, so its share is exactly unchanged, while minutes
    # 0 and 1 trade five records between them.
    before = _minute_value([(0, 5), (1, 5), (2, 5)])
    after = _minute_value([(0, 3), (1, 7), (2, 5)])
    result = compare.compare_baselines(before, after)
    assert result['changed_relative_minutes'] == [
        {'minute': 0, 'reference_count': 5, 'current_count': 3, 'change': 'share_decreased'},
        {'minute': 1, 'reference_count': 5, 'current_count': 7, 'change': 'share_increased'},
    ]
    assert result['changed_relative_minutes_count'] == 2
    assert not any(item['minute'] == 2 for item in result['changed_relative_minutes'])


def test_identical_relative_minutes_report_no_changes():
    before = _minute_value([(0, 4), (1, 4)])
    after = _minute_value([(0, 8), (1, 8)])  # volume doubles; shares stay equal
    result = compare.compare_baselines(before, after)
    assert result['changed_relative_minutes'] == []
    assert result['changed_relative_minutes_count'] == 0


def test_changed_relative_minutes_limit_fails_closed():
    before = _minute_value([(minute, 1) for minute in range(257)])
    after = _minute_value([(minute, 1 + minute % 2) for minute in range(257)])
    with pytest.raises(OfflineError, match='^COMPARISON_MINUTE_LIMIT$'):
        compare.compare_baselines(before, after)


@pytest.mark.parametrize('adapter,kind', [('zeek-conn-json-v1', 'flow'),
                                         ('zeek-conn-tsv-v1', 'flow')])
def test_flows_compare_only_with_the_same_adapter(adapter, kind):
    before = _value()
    before.update(adapter=adapter, record_kind=kind)
    assert compare.compare_baselines(before, before)['record_kind'] == 'flow'
    with pytest.raises(OfflineError, match='^INCOMPATIBLE_BASELINE$'):
        compare.compare_baselines(before, _value())
    other = dict(before, adapter='zeek-conn-tsv-v1' if 'json' in adapter else 'zeek-conn-json-v1')
    with pytest.raises(OfflineError, match='^INCOMPATIBLE_BASELINE$'):
        compare.compare_baselines(before, other)


def test_sample_and_output_bounds_never_return_a_successful_prefix():
    with pytest.raises(OfflineError, match='^REFERENCE_BASELINE_TOO_SMALL$'):
        compare.compare_baselines(_value([('TCP', 443)] * 4), _value())
    with pytest.raises(OfflineError, match='^CURRENT_BASELINE_EMPTY$'):
        compare.compare_baselines(_value(), _value([]))
    before = _value([('TCP', port) for port in range(128)])
    after = _value([('TCP', port) for port in range(128, 256)])
    result = compare.compare_baselines(before, after)
    assert result['changed_destination_ports_count'] == 256
    assert len(json.dumps(result).encode()) < compare.MAX_RECEIPT_BYTES
    with pytest.raises(OfflineError, match='^COMPARISON_PORT_LIMIT$'):
        compare.compare_baselines(before, _value([('TCP', port) for port in range(128, 257)]))


def _files(tmp_path, monkeypatch):
    # Test the reader independently of the separately tested privilege preflight.
    monkeypatch.setattr(compare, 'require_unprivileged_linux', lambda: None)
    for name in ('before.json', 'after.json'):
        (tmp_path / name).write_bytes(reports.json_bytes(_value()))
    return ['--input-root', str(tmp_path), '--reference', 'before.json', '--current', 'after.json']


def test_cli_reads_only_and_never_calls_analyzer_model_database_or_network(tmp_path, monkeypatch, capsys):
    args = _files(tmp_path, monkeypatch)
    snapshots = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    from megalodon.offline import tshark
    from megalodon import firewall, qwen_advisory
    def forbidden(*args, **kwargs):
        raise AssertionError('side effect attempted')
    original_open = os.open
    def readonly_open(path, flags, *args, **kwargs):
        assert not flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return original_open(path, flags, *args, **kwargs)
    with monkeypatch.context() as guard:
        guard.setattr(os, 'open', readonly_open)
        for module, names in ((socket, ('socket', 'getaddrinfo', 'create_connection')),
                              (subprocess, ('Popen', 'run')), (sqlite3, ('connect',)),
                              (os, ('system', 'mkdir', 'unlink', 'rename', 'write')),
                              (builtins, ('open',)), (tshark, ('replay',)),
                              (qwen_advisory, ('invoke_qwen_advisory',)),
                              (firewall, ('NftablesFirewall',))):
            for name in names:
                guard.setattr(module, name, forbidden)
        assert compare.main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == 'compared'
    assert result['network_access_performed'] is False
    assert result['persistence_status'] == result['action_status'] == 'not_attempted'
    assert snapshots == {path.name: path.read_bytes() for path in tmp_path.iterdir()}


@pytest.mark.parametrize('bad', ['{"secret":"SECRET","secret":1}', '{"x":[[[[0]]]]}',
                               '{"n":NaN}', '[]', 'SECRET', '{"n":1e999}',
                               '\xff', 'x' * (1024 * 1024 + 1)])
def test_cli_untrusted_json_has_fixed_non_echoing_failure(tmp_path, monkeypatch, capsys, bad):
    args = _files(tmp_path, monkeypatch)
    (tmp_path / 'before.json').write_bytes(bad.encode('latin1'))
    assert compare.main(args) == 1
    text = capsys.readouterr().out
    assert json.loads(text)['status'] == 'failed'
    assert 'SECRET' not in text and str(tmp_path) not in text and 'Traceback' not in text


@pytest.mark.parametrize('suffix', [['--current', 'SECRET'], ['--cur', 'SECRET'], ['--unknown', 'SECRET']])
def test_cli_ambiguous_arguments_fail_before_file_access(monkeypatch, capsys, suffix):
    monkeypatch.setattr(compare, 'read_reference', lambda *args: pytest.fail('file accessed'))
    with pytest.raises(SystemExit) as error:
        compare.main(['--input-root', '/SECRET', '--reference', 'one', '--current', 'two'] + suffix)
    assert error.value.code == 2
    result = capsys.readouterr()
    assert not result.out and json.loads(result.err)['failure_code'] == 'INVALID_ARGUMENTS'
    assert 'SECRET' not in result.err


def test_cli_root_refusal_precedes_read(monkeypatch, capsys):
    monkeypatch.setattr(os, 'getuid', lambda: 0)
    monkeypatch.setattr(compare, 'read_reference', lambda *args: pytest.fail('file accessed'))
    assert compare.main(['--input-root', '/SECRET', '--reference', 'one', '--current', 'two']) == 1
    assert json.loads(capsys.readouterr().out)['failure_code'] == 'NON_ROOT_REQUIRED'


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'fifo', 'traversal'])
def test_cli_reuses_descriptor_boundary(tmp_path, monkeypatch, capsys, kind):
    args = _files(tmp_path, monkeypatch)
    target = tmp_path / 'bad.json'
    if kind == 'symlink':
        target.symlink_to(tmp_path / 'before.json')
    elif kind == 'hardlink':
        os.link(tmp_path / 'before.json', target)
    elif kind == 'fifo':
        os.mkfifo(target)
    args[args.index('--reference') + 1] = '../SECRET' if kind == 'traversal' else 'bad.json'
    assert compare.main(args) == 1
    assert json.loads(capsys.readouterr().out)['status'] == 'failed'


def test_cli_receipt_size_breach_and_local_io_are_terminal(tmp_path, monkeypatch, capsys):
    args = _files(tmp_path, monkeypatch)
    monkeypatch.setattr(compare, 'MAX_RECEIPT_BYTES', 1)
    assert compare.main(args) == 1
    assert json.loads(capsys.readouterr().out)['failure_code'] == 'COMPARISON_RECEIPT_LIMIT'
    def broken(*args):
        raise OSError('SECRET')
    monkeypatch.setattr(compare, 'read_reference', broken)
    assert compare.main(args) == 1
    assert json.loads(capsys.readouterr().out)['failure_code'] == 'LOCAL_IO_ERROR'


@pytest.mark.parametrize('minute_count', [256, 257])
def test_cli_combined_port_and_minute_bounds(tmp_path, monkeypatch, capsys, minute_count):
    args = _files(tmp_path, monkeypatch)
    before = _value([('TCP', port) for port in range(128)])
    after = _value([('TCP', port) for port in range(128, 256)]
                   + [('TCP', 128)] * (minute_count - 255))
    before['relative_minutes'] = [{'minute': minute, 'count': 1} for minute in range(128)]
    after['relative_minutes'] = [{'minute': 0, 'count': 1}] + [
        {'minute': minute, 'count': 1} for minute in range(128, minute_count)]
    for name, value in [('before.json', before), ('after.json', after)]:
        (tmp_path / name).write_bytes(reports.json_bytes(value))
    status = compare.main(args)
    captured = capsys.readouterr()
    assert not captured.err
    assert len(captured.out.splitlines()) == 1
    result = json.loads(captured.out)
    if minute_count == 257:
        assert status == 1
        assert result == dict(compare._receipt('failed'), failure_code='COMPARISON_MINUTE_LIMIT')
        return
    assert status == 0
    assert result['changed_destination_ports_count'] == 256
    assert result['changed_relative_minutes_count'] == 256
    assert len(result['byte_bands']) == 3
    assert len(captured.out.encode('ascii')) <= compare.MAX_RECEIPT_BYTES
    assert result['truncated'] is False
    assert 'Byte bands count records by size, not byte volume or bandwidth.' in result['limitations']
    assert ("Relative-minute bins use each sample's own earliest record; wall-clock windows are not aligned."
            in result['limitations'])


def test_contradictory_reference_cannot_publish_reports_or_enter_dashboard(tmp_path, monkeypatch):
    batch = _batch()
    reference = _value()
    MALFORMED[0](reference)
    with monkeypatch.context() as guard:
        guard.setattr(reports, '_write', lambda *args: pytest.fail('report written'))
        with pytest.raises(OfflineError, match='^INVALID_BASELINE$'):
            reports.finish(-1, reports.manifest('synthetic', 'tshark', Limits()),
                           Limits(), batch=batch, reference=reference)
    output = tmp_path / 'run'
    with reports.output_directory(str(output)) as directory:
        reports.finish(directory, reports.manifest('synthetic', 'tshark', Limits()),
                       Limits(), batch=batch)
    assert offline_projection.load_offline_projection(output)['summary']['record_count'] == 6
    (output / 'baseline.json').write_bytes(reports.json_bytes(reference))
    with pytest.raises(OfflineError, match='^INVALID_OFFLINE_BASELINE$'):
        offline_projection.load_offline_projection(output)
