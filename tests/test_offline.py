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


def test_process_cleanup_failure_does_not_replace_the_primary_refusal(tmp_path, monkeypatch):
    class Process:
        pid = 123
        stdout = None
        stderr = None

        def wait(self, timeout):
            raise subprocess.TimeoutExpired('synthetic', timeout)

    class BrokenSelector:
        def __enter__(self):
            raise OSError('synthetic selector failure')

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(tshark.subprocess, 'Popen', lambda *_args, **_kwargs: Process())
    monkeypatch.setattr(tshark.selectors, 'DefaultSelector', BrokenSelector)
    monkeypatch.setattr(tshark.os, 'killpg', lambda *_args: None)

    with pytest.raises(OfflineError, match='ANALYZER_IO_ERROR') as caught:
        tshark._bounded_process(('synthetic',), env={}, cwd=str(tmp_path), limits=Limits())

    assert caught.value.__notes__ == [
        'offline analyzer cleanup failed; shutdown is unverified'
    ]


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
