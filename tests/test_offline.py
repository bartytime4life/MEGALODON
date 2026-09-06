"""Synthetic metadata and controlled child processes only; never a live firewall."""

from __future__ import annotations

from decimal import Decimal
import json
import os
from pathlib import Path
import stat
import struct
import sys
import time
from types import SimpleNamespace

import pytest

from megalodon.models import PacketEvent
from megalodon.offline import analysis, common, reports, tshark, zeek
from megalodon.offline.__main__ import main, read_reference
from megalodon.offline.common import Batch, FlowRecord, Limits, OfflineError


def field_row(**changes):
    values = {'frame.time_epoch': '1788710400.123456789', 'ip.src': '192.0.2.10',
              'ip.dst': '198.51.100.20', 'ip.proto': '6', 'tcp.srcport': '40000',
              'tcp.dstport': '443', 'tcp.flags': '0x0012', 'frame.len': '60'}
    values.update(changes)
    return '\t'.join(values.get(key, '') for key in tshark.FIELDS)


def conn(**changes):
    value = {'ts': '1788710400.123456', 'uid': 'synthetic001', 'id.orig_h': '192.0.2.10',
             'id.orig_p': 40000, 'id.resp_h': '198.51.100.20', 'id.resp_p': 443,
             'proto': 'tcp', 'duration': '0.06685185432434082', 'orig_bytes': 0,
             'resp_bytes': 0, 'conn_state': 'SF', 'orig_pkts': 3, 'resp_pkts': 2,
             'orig_ip_bytes': 180, 'resp_ip_bytes': 120, 'ip_proto': 6}
    value.update(changes)
    return value


def batch(records, kind='packet'):
    return Batch(tshark.ADAPTER if kind == 'packet' else zeek.ADAPTERS['json'], kind,
                 tuple(records), len(records), 0, 100, '4.6.0', 'test_fixture')


def capture(tmp_path):
    path = tmp_path / 'capture.pcap'
    # Empty classic PCAP header. There are no packet or application payload bytes.
    path.write_bytes(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    return path


@pytest.fixture
def unprivileged(monkeypatch):
    monkeypatch.setattr(tshark, 'require_unprivileged_linux', lambda: None)
    monkeypatch.setattr(zeek, 'require_unprivileged_linux', lambda: None)
    monkeypatch.setattr('megalodon.offline.__main__.require_unprivileged_linux', lambda: None)


@pytest.fixture
def fake_tshark(monkeypatch, unprivileged):
    calls = []
    original = os.lstat
    def lstat(path, *args, **kwargs):
        if path == tshark.EXECUTABLE:
            return SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o755)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, 'lstat', lstat)
    monkeypatch.setattr(os, 'getxattr', lambda *a, **kw: b'')
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return b'TShark (Wireshark) 4.6.0 (test)\n' if '--version' in argv else (field_row() + '\n').encode()
    monkeypatch.setattr(tshark, '_bounded_process', run)
    return calls


@pytest.mark.parametrize('kwargs', [{'records': 0}, {'records': 10001}, {'records': True},
                                    {'timeout_seconds': 31}, {'input_bytes': -1},
                                    {'stdout_bytes': 2**30}, {'stderr_bytes': 0},
                                    {'report_bytes': 2**30}, {'line_bytes': 20000}])
def test_limits_fail_closed(kwargs):
    with pytest.raises(OfflineError, match='INVALID_LIMIT'):
        Limits(**kwargs)


@pytest.mark.parametrize('value', ['', None, True, '-1', 'NaN', 'Infinity',
                                  '4102444800', '1e99', '0.1;cmd'])
def test_bad_times(value):
    with pytest.raises(OfflineError):
        common.timestamp(value)


def test_precise_time_and_duration():
    assert common.timestamp('1788710400.123456789').microsecond == 123456
    assert common.seconds_us(Decimal('0.06685185432434082'), 604800) == 66851
    assert common.seconds_us(Decimal('1E-7'), 604800) == 0


def test_non_root_and_linux_required(monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(os, 'getuid', lambda: 0)
    with pytest.raises(OfflineError, match='NON_ROOT_REQUIRED'):
        common.require_unprivileged_linux()
    monkeypatch.setattr(sys, 'platform', 'darwin')
    with pytest.raises(OfflineError, match='LINUX_REQUIRED'):
        common.require_unprivileged_linux()


@pytest.mark.parametrize('relative', ['../input', '/absolute', 'a/../b', 'a//b', './x', 'https://host/input', 'a\n'])
def test_bad_paths(tmp_path, relative):
    with pytest.raises(OfflineError):
        with common.open_input(str(tmp_path), relative, Limits()):
            pytest.fail('unsafe path accepted')


def test_regular_files_links_size_and_symlink_ancestors(tmp_path):
    target = tmp_path / 'ok'
    target.write_text('metadata')
    link = tmp_path / 'link'
    link.symlink_to(target)
    with pytest.raises(OfflineError):
        with common.open_input(str(tmp_path), 'link', Limits()):
            pass
    (tmp_path / 'folder').mkdir()
    (tmp_path / 'alias').symlink_to(tmp_path / 'folder', target_is_directory=True)
    (tmp_path / 'folder' / 'x').write_text('x')
    with pytest.raises(OfflineError):
        with common.open_input(str(tmp_path), 'alias/x', Limits()):
            pass
    with pytest.raises(OfflineError):
        with common.open_input(str(tmp_path / 'alias'), 'x', Limits()):
            pass
    with pytest.raises(OfflineError, match='INPUT_SIZE_LIMIT'):
        with common.open_input(str(tmp_path), 'ok', Limits(input_bytes=1)):
            pass
    os.link(target, tmp_path / 'hard')
    with pytest.raises(OfflineError, match='SINGLE_LINK'):
        with common.open_input(str(tmp_path), 'ok', Limits()):
            pass
    os.mkfifo(tmp_path / 'fifo')
    with pytest.raises(OfflineError, match='REGULAR'):
        with common.open_input(str(tmp_path), 'fifo', Limits()):
            pass
    with pytest.raises(OfflineError, match='REGULAR'):
        with common.open_input(str(tmp_path), 'folder', Limits()):
            pass


def test_input_mutation_is_failure(tmp_path):
    (tmp_path / 'data').write_text('old')
    with pytest.raises(OfflineError, match='INPUT_CHANGED'):
        with common.open_input(str(tmp_path), 'data', Limits()):
            (tmp_path / 'data').write_text('changed')


def test_fixed_argv():
    args = tshark.fixed_argv(7, Limits(records=2))
    assert args[:8] == ('/usr/bin/tshark', '-n', '-l', '-r', '/proc/self/fd/7', '-c', '3', '-T')
    assert tuple(args[index + 1] for index, value in enumerate(args) if value == '-e') == tshark.FIELDS
    assert not {'-i', '-Y', '-f', '-x', '-V', '-w', '-X', '-z'} & set(args)
    assert 'occurrence=a' in args
    assert all('payload' not in field and 'dns.qry.name' not in field for field in tshark.FIELDS)


def test_packet_metadata_and_ipv6():
    event = tshark.parse_fields(field_row())
    assert isinstance(event, PacketEvent)
    assert event.tcp_flags == frozenset({'SYN', 'ACK'})
    assert event.dns_query_length is None
    event = tshark.parse_fields(field_row(**{'ip.src': '', 'ip.dst': '', 'ip.proto': '',
                                            'ipv6.src': '2001:db8::1', 'ipv6.dst': '2001:db8::2',
                                            'ipv6.nxt': '6'}))
    assert event.src_ip == '2001:db8::1'


@pytest.mark.parametrize('changes', [
    {'ip.src': '192.0.2.10,192.0.2.11'}, {'ip.src': 'SECRET;command'},
    {'ip.dst': '2001:db8::1'}, {'frame.time_epoch': ''}, {'tcp.srcport': '65536'},
    {'tcp.flags': '0x0100'}, {'tcp.flags': 'SYN'}, {'frame.len': '999999999'},
    {'udp.srcport': '4'}, {'ip.proto': '43'}, {'ipv6.src': '2001:db8::1'},
    {'tcp.dstport': '1.0'}, {'tcp.dstport': '=cmd'}, {'frame.time_epoch': 'NaN'},
])
def test_bad_packet_metadata(changes):
    with pytest.raises(OfflineError) as caught:
        tshark.parse_fields(field_row(**changes))
    assert 'SECRET' not in str(caught.value)


def test_non_ip_and_fragment_are_explicitly_skipped():
    row = '\t'.join('1788710400' if f == 'frame.time_epoch' else '60' if f == 'frame.len' else '' for f in tshark.FIELDS)
    assert tshark.parse_fields(row) is None
    assert tshark.parse_fields(field_row(**{'tcp.srcport': '', 'tcp.dstport': '', 'tcp.flags': ''})) is None


def test_complete_tshark_boundary(tmp_path, fake_tshark):
    capture(tmp_path)
    result = tshark.replay(str(tmp_path), 'capture.pcap')
    assert result.scanned == 1 and result.skipped == 0 and result.tool_version == '4.6.0'
    assert len(fake_tshark) == 2
    argv, kwargs = fake_tshark[-1]
    assert kwargs['pass_fds'] and argv[4].startswith('/proc/self/fd/')
    assert set(kwargs['env']) == {'PATH', 'LANG', 'LC_ALL', 'HOME', 'XDG_CONFIG_HOME',
                                  'XDG_CACHE_HOME', 'WIRESHARK_CONFIG_DIR'}
    assert not os.path.exists(kwargs['cwd'])


@pytest.mark.parametrize('raw,expected', [
    ((field_row() + '\n') * 2, 'RECORD_LIMIT'), (field_row(), 'TRUNCATED'),
    ('SECRET\n', 'AMBIGUOUS'), (field_row() + '\r\n', 'INVALID_FIELD'),
])
def test_tshark_replay_errors_discard_output(tmp_path, fake_tshark, monkeypatch, raw, expected):
    capture(tmp_path)
    monkeypatch.setattr(tshark, '_bounded_process', lambda argv, **kw:
                        b'TShark (Wireshark) 4.6.0 test\n' if '--version' in argv else raw.encode())
    with pytest.raises(OfflineError, match=expected):
        tshark.replay(str(tmp_path), 'capture.pcap', Limits(records=1))


def test_missing_tshark_and_bad_format(tmp_path, unprivileged, monkeypatch):
    monkeypatch.setattr(tshark, 'EXECUTABLE', str(tmp_path / 'missing'))
    capture(tmp_path)
    with pytest.raises(OfflineError, match='UNAVAILABLE'):
        tshark.replay(str(tmp_path), 'capture.pcap')
    with pytest.raises(OfflineError, match='UNSUPPORTED_CAPTURE'):
        tshark.replay(str(tmp_path), 'capture.pcap.gz')


def run_child(code, tmp_path, **kwargs):
    return tshark._bounded_process((sys.executable, '-c', code), env={'PATH': '/usr/bin:/bin'},
                                   cwd=str(tmp_path), limits=Limits(**kwargs))


def test_subprocess_drains_pipes_and_respects_exact_bounds(tmp_path):
    data = run_child("import os; os.write(2,b'x'*2048); os.write(1,b'a'*2048)", tmp_path,
                     stdout_bytes=2048, stderr_bytes=2048)
    assert data == b'a' * 2048


@pytest.mark.parametrize('code,kwargs,expected', [
    ("import os; os.write(1,b'x'*2049)", {'stdout_bytes': 2048}, 'STDOUT_LIMIT'),
    ("import os; os.write(2,b'SECRET'*1000)", {'stderr_bytes': 128}, 'STDERR_LIMIT'),
    ("import time; time.sleep(20)", {'timeout_seconds': 1}, 'TIMEOUT'),
    ("import sys; print('SECRET',file=sys.stderr); sys.exit(3)", {}, 'ANALYZER_FAILED'),
])
def test_process_failures_are_bounded_and_sanitized(tmp_path, code, kwargs, expected):
    start = time.monotonic()
    with pytest.raises(OfflineError, match=expected) as caught:
        run_child(code, tmp_path, **kwargs)
    assert time.monotonic() - start < 5
    assert 'SECRET' not in str(caught.value)


def test_descendant_pipe_holder_is_killed(tmp_path):
    code = ("import subprocess,sys,pathlib; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            "pathlib.Path('pid').write_text(str(p.pid))")
    with pytest.raises(OfflineError, match='TIMEOUT'):
        run_child(code, tmp_path, timeout_seconds=1)
    pid = int((tmp_path / 'pid').read_text())
    for _ in range(30):
        try:
            state = Path(f'/proc/{pid}/stat').read_text().split()[2]
        except FileNotFoundError:
            break
        if state == 'Z':  # Terminated, awaiting the environment's init reaper.
            break
        time.sleep(0.01)
    else:
        pytest.fail('descendant survived process-group cleanup')


def test_flow_mapping_is_separate_and_discards_extra_fields():
    value = zeek.parse_flow(conn(service='http', history='ShADadFf'))
    assert isinstance(value, FlowRecord) and not isinstance(value, PacketEvent)
    assert value.orig_packets == 3 and value.resp_packets == 2 and value.byte_count == 300
    assert value.duration_us == 66851
    assert not hasattr(value, 'uid') and not hasattr(value, 'service')


@pytest.mark.parametrize('changes', [
    {'proto': 'unknown_transport'}, {'id.orig_h': 'SECRET'}, {'orig_pkts': True},
    {'orig_ip_bytes': -1}, {'duration': 'NaN'}, {'id.resp_p': 65536},
    {'conn_state': 'CUSTOM'}, {'ip_proto': 17}, {'http_body': 'SECRET'},
    {'local_orig': 'T'}, {'tunnel_parents': [['nested']]}, {'id.resp_h': '2001:db8::1'},
    {'ts': None}, {'orig_pkts': None}, {'duration': '604800'}, {'history': '\nSECRET'},
])
def test_invalid_flow(changes):
    with pytest.raises(OfflineError) as caught:
        zeek.parse_flow(conn(**changes))
    assert 'SECRET' not in str(caught.value)


@pytest.mark.parametrize('text', ['{"ts":1,"ts":2}', '{"ts":NaN}', '[]', '{', '{"x":' + '['*1100 + '0' + ']'*1100 + '}'], ids=['duplicate', 'nan', 'array', 'syntax', 'depth'])
def test_bad_json(text):
    with pytest.raises(OfflineError):
        zeek.json_object(text)


def tsv(data=None):
    data = conn() if data is None else data
    fields = list(data)
    header = ['#separator \\x09', '#set_separator\t,', '#empty_field\t(empty)',
              '#unset_field\t-', '#path\tconn', '#open\t2026-09-06-12-00-00',
              '#fields\t' + '\t'.join(fields), '#types\t' + '\t'.join(zeek.TYPES[f] for f in fields)]
    row = '\t'.join('-' if data[f] is None else str(data[f]) for f in fields)
    return '\n'.join([*header, row, '#close\t2026-09-06-12-00-01']) + '\n'


def test_zeek_json_and_tsv_parity(tmp_path, unprivileged):
    (tmp_path / 'conn.jsonl').write_text(json.dumps(conn()) + '\n')
    (tmp_path / 'conn.log').write_text(tsv())
    a = zeek.replay(str(tmp_path), 'conn.jsonl', format='json', producer_version='8.2.2')
    b = zeek.replay(str(tmp_path), 'conn.log', format='tsv', producer_version='8.2.2')
    assert a.records == b.records and a.kind == b.kind == 'flow'
    assert a.adapter != b.adapter
    assert a.version_basis == 'operator_declared_unverified'


@pytest.mark.parametrize('alter', [
    lambda text: text.replace('#separator \\x09', '#separator ,'),
    lambda text: text.replace('#path\tconn', '#path\thttp'),
    lambda text: text.replace('#types\ttime', '#types\tstring'),
    lambda text: text[:text.index('#close')],
    lambda text: text + 'data\n',
    lambda text: text.replace('#open\t2026', '#open\t\x00SECRET2026'),
    lambda text: text.replace('#fields\tts\tuid', '#fields\tts\tts'),
])
def test_zeek_tsv_fail_closed(tmp_path, unprivileged, alter):
    (tmp_path / 'conn.log').write_text(alter(tsv()))
    with pytest.raises(OfflineError):
        zeek.replay(str(tmp_path), 'conn.log', format='tsv', producer_version='8.2.2')


def test_line_and_record_limits(tmp_path, unprivileged):
    (tmp_path / 'conn.jsonl').write_text((json.dumps(conn()) + '\n') * 2)
    with pytest.raises(OfflineError, match='RECORD_LIMIT'):
        zeek.replay(str(tmp_path), 'conn.jsonl', format='json', producer_version='8.2.2', limits=Limits(records=1))
    with pytest.raises(OfflineError, match='INPUT_SIZE_LIMIT'):
        zeek.replay(str(tmp_path), 'conn.jsonl', format='json', producer_version='8.2.2', limits=Limits(line_bytes=10))


def packet_at(seconds, port=443):
    return tshark.parse_fields(field_row(**{'frame.time_epoch': str(1788710400 + seconds), 'tcp.dstport': str(port)}))


def test_deterministic_baselines_and_candidates():
    records = [packet_at(seconds) for seconds in (0, 10, 20, 30, 40)]
    a, b = batch(records), batch(list(reversed(records)))
    assert analysis.baseline(a) == analysis.baseline(b)
    assert analysis.candidates(a) == analysis.candidates(b)
    assert analysis.candidates(a)[0]['rule'] == 'REGULAR_INTERVAL'
    benign = batch([packet_at(s) for s in (0, 3, 14, 20, 49)])
    assert analysis.candidates(benign) == []
    reference = analysis.baseline(a)
    changed = batch([packet_at(0, port=8443)])
    assert analysis.candidates(changed, reference)[0]['rule'] == 'NEW_DESTINATION_PORT'
    burst = batch([packet_at(0, port=53)] * 20)
    assert [c['rule'] for c in analysis.candidates(burst)] == ['PORT_53_BURST']


def test_baseline_source_mismatch_and_bad_counts():
    a = batch([packet_at(i) for i in range(5)])
    reference = analysis.baseline(a)
    reference['record_kind'] = 'flow'
    with pytest.raises(OfflineError, match='INCOMPATIBLE_BASELINE'):
        analysis.candidates(a, reference)
    reference = analysis.baseline(a)
    reference['destination_ports'][0]['count'] = 0
    with pytest.raises(OfflineError, match='INVALID_BASELINE'):
        analysis.candidates(a, reference)
    reference = analysis.baseline(a)
    reference['raw_payload'] = 'SECRET'
    with pytest.raises(OfflineError, match='INCOMPATIBLE_BASELINE'):
        analysis.candidates(a, reference)


def test_candidate_limit_is_not_silent_truncation():
    base = analysis.baseline(batch([packet_at(i) for i in range(5)]))
    target = batch([packet_at(0, port=i) for i in range(1000, 1257)])
    with pytest.raises(OfflineError, match='CANDIDATE_LIMIT'):
        analysis.candidates(target, base)


def test_reports_are_private_redacted_and_no_overwrite(tmp_path):
    output = tmp_path / 'run'
    a = batch([packet_at(i) for i in range(5)])
    receipt = reports.manifest('case1', 'tshark', Limits())
    with reports.output_directory(str(output)) as fd:
        reports.finish(fd, receipt, Limits(), batch=a)
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for path in output.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        text = path.read_text()
        assert '192.0.2.10' not in text and '198.51.100.20' not in text
        assert '1788710400' not in text and str(tmp_path) not in text
    assert json.loads((output / 'manifest.json').read_text())['status'] == 'complete'
    assert (output / 'records.csv').read_text().startswith('record,record_kind,offset_us')
    with pytest.raises(OfflineError, match='OUTPUT_IO_ERROR'):
        with reports.output_directory(str(output)):
            pass


def test_report_overflow_does_not_publish_complete(tmp_path):
    limits = Limits(report_bytes=1500)
    output = tmp_path / 'run'
    receipt = reports.manifest('case1', 'tshark', limits)
    with reports.output_directory(str(output)) as fd:
        with pytest.raises(OfflineError, match='REPORT_SIZE_LIMIT'):
            reports.finish(fd, receipt, limits, batch=batch([packet_at(i) for i in range(20)]))
        reports.finish(fd, receipt, limits, failure='REPORT_SIZE_LIMIT')
    assert [p.name for p in output.iterdir()] == ['manifest.json']
    assert json.loads((output / 'manifest.json').read_text())['status'] == 'failed'


def test_write_failure_removes_partial_report_files(tmp_path, monkeypatch):
    original = reports._write
    def fail(fd, name, data):
        if name == 'baseline.json':
            raise OSError('SECRET')
        original(fd, name, data)
    monkeypatch.setattr(reports, '_write', fail)
    output = tmp_path / 'run'
    with reports.output_directory(str(output)) as fd:
        with pytest.raises(OfflineError, match='REPORT_IO_ERROR'):
            reports.finish(fd, reports.manifest('case1', 'tshark', Limits()), Limits(), batch=batch([packet_at(0)]))
    assert list(output.iterdir()) == []


def cli_args(tmp_path, source='zeek-json'):
    return ['--source', source, '--input-root', str(tmp_path), '--input', 'conn.jsonl',
            '--output', str(tmp_path / 'run'), '--case', 'case1', '--zeek-version', '8.2.2']


def test_cli_complete_and_failed_manifests(tmp_path, unprivileged, capsys):
    (tmp_path / 'conn.jsonl').write_text(json.dumps(conn()) + '\n')
    assert main(cli_args(tmp_path)) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'complete'
    bad = tmp_path / 'bad'
    bad.mkdir()
    (bad / 'conn.jsonl').write_text('{"http_body":"SECRET"}\n')
    assert main(cli_args(bad)) == 1
    text = capsys.readouterr().out
    assert 'SECRET' not in text and json.loads(text)['manifest_written'] is True
    manifest = json.loads((bad / 'run' / 'manifest.json').read_text())
    assert manifest['status'] == 'failed' and manifest['accepted_records'] == 0
    assert [p.name for p in (bad / 'run').iterdir()] == ['manifest.json']


def test_reference_read_and_validation(tmp_path):
    a = batch([packet_at(i) for i in range(5)])
    (tmp_path / 'baseline.json').write_bytes(reports.json_bytes(analysis.baseline(a)))
    reference = read_reference(str(tmp_path), 'baseline.json', Limits())
    assert analysis.validate_reference(reference, a) == {('TCP', 443)}


@pytest.mark.parametrize('extra', [['--endpoint', 'https://SECRET'], ['--apply'], ['--source', 'shell']])
def test_no_egress_or_apply_arguments(tmp_path, extra, capsys):
    with pytest.raises(SystemExit) as caught:
        main([*cli_args(tmp_path), *extra])
    assert caught.value.code == 2
    assert capsys.readouterr().err == 'INVALID_ARGUMENTS\n'


def test_offline_package_has_no_live_imports():
    import ast
    directory = Path(tshark.__file__).parent
    forbidden = {'requests', 'http', 'urllib', 'socket', 'firewall', 'service', 'storage', 'dashboard'}
    for path in directory.glob('*.py'):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not forbidden & {alias.name.split('.')[0] for alias in node.names}
            if isinstance(node, ast.ImportFrom):
                assert not forbidden & set((node.module or '').split('.'))
            if isinstance(node, ast.keyword) and node.arg == 'shell':
                assert isinstance(node.value, ast.Constant) and node.value.value is False


@pytest.mark.skipif(os.environ.get('MEGALODON_TEST_TSHARK') != '1' or os.geteuid() == 0 or
                    not Path('/usr/bin/tshark').is_file(),
                    reason='Explicit MEGALODON_TEST_TSHARK=1 lane requires installed TShark and non-root Linux')
def test_system_tshark_headers_only(tmp_path):
    # Ethernet + IPv4 + TCP SYN headers, zero application payload.
    ethernet = bytes.fromhex('0000000000020000000000010800')
    ipv4 = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0, 64, 6, 0,
                       bytes([192, 0, 2, 10]), bytes([198, 51, 100, 20]))
    tcp = struct.pack('!HHIIBBHHH', 40000, 443, 0, 0, 0x50, 2, 8192, 0, 0)
    packet = ethernet + ipv4 + tcp
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    data += struct.pack('<IIII', 1788710400, 0, len(packet), len(packet)) + packet
    (tmp_path / 'headers.pcap').write_bytes(data)
    result = tshark.replay(str(tmp_path), 'headers.pcap')
    assert len(result.records) == 1
    assert result.records[0].dst_port == 443
    assert result.records[0].tcp_flags == frozenset({'SYN'})


@pytest.mark.parametrize('capabilities', [True, False])
def test_process_capability_guard(monkeypatch, capabilities):
    import io
    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(os, 'getuid', lambda: 1000)
    monkeypatch.setattr(os, 'geteuid', lambda: 1000)
    status = 'CapInh: 0\nCapPrm: 0\nCapEff: ' + ('1' if capabilities else '0') + '\nCapAmb: 0\n'
    monkeypatch.setattr('builtins.open', lambda *a, **kw: io.StringIO(status))
    if capabilities:
        with pytest.raises(OfflineError, match='CAPABILITY_FREE'):
            common.require_unprivileged_linux()
    else:
        common.require_unprivileged_linux()


def test_analyzer_file_capabilities_rejected(tmp_path, fake_tshark, monkeypatch):
    capture(tmp_path)
    monkeypatch.setattr(os, 'getxattr', lambda *a, **kw: b'nonempty-capability-attribute')
    with pytest.raises(OfflineError, match='UNTRUSTED_ANALYZER'):
        tshark.replay(str(tmp_path), 'capture.pcap')
    assert fake_tshark == []
