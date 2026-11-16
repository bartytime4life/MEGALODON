"""No privileged helper, live capture, updater, download, or service operation.

Helper definitions run only against temporary files with a fake native adapter.
The optional installed-engine smoke test runs -T/--dump-config on synthetic
configuration and rules; it cannot start a capture or read installed config.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from megalodon import execution_boundary
from megalodon.suricata_rules import ROOT_PROGRAM, SCHEMA, SuricataRules, validate_scope


RULE = b'alert tcp any any -> any any (msg:"Synthetic rule"; sid:4000001; rev:1;)\n'
CUSTOM = b'alert tcp any any -> any any (msg:"Preserved rule"; sid:4000002; rev:1;)\n'
DUMP = b'''outputs = (null)
outputs.0 = eve-log
outputs.0.eve-log = (null)
outputs.0.eve-log.enabled = yes
outputs.0.eve-log.filetype = regular
outputs.0.eve-log.filename = eve.json
outputs.0.eve-log.threaded = false
outputs.0.eve-log.types = (null)
outputs.0.eve-log.types.0 = alert
outputs.0.eve-log.types.0.alert = (null)
outputs.0.eve-log.types.0.alert.payload = no
outputs.0.eve-log.types.0.alert.payload-printable = no
outputs.0.eve-log.types.0.alert.packet = no
outputs.0.eve-log.types.0.alert.metadata = no
outputs.0.eve-log.types.0.alert.tagged-packets = no
outputs.0.eve-log.types.1 = flow
outputs.0.eve-log.types.2 = stats
outputs.0.eve-log.types.2.stats = (null)
outputs.0.eve-log.types.2.stats.totals = yes
outputs.0.eve-log.types.2.stats.threads = no
af-packet = (null)
af-packet.0 = interface
af-packet.0.interface = test0
af-packet.0.threads = 1
af-packet.0.cluster-id = 99
af-packet.0.cluster-type = cluster_flow
af-packet.0.defrag = yes
unix-command = (null)
unix-command.enabled = no
'''


class FakeNative:
    def __init__(self, namespace):
        self.ns = namespace
        self.calls = []
        self.candidate = RULE
        self.dump = DUMP
        self.test_code = 0
        self.update_code = 0
        self.running = False
        self.restart_codes = []
        self.timeout = False

    def __call__(self, argv, timeout=30, cwd=None, maximum=None):
        argv = list(map(str, argv))
        self.calls.append((argv, timeout))
        if self.timeout:
            raise self.ns['Fault']('TIMEOUT')
        if argv[0] == str(self.ns['UPDATER']):
            output = Path(argv[argv.index('-o') + 1])
            (output / 'suricata.rules').write_bytes(self.candidate)
            return b'', self.update_code
        if argv[0] == str(self.ns['ENGINE']):
            assert '-T' in argv or '--dump-config' in argv, 'test attempted live capture'
            return (self.dump, 0) if '--dump-config' in argv else (b'', self.test_code)
        assert argv[0] == str(self.ns['SYSTEMCTL'])
        if argv[1] == 'show':
            paths = sorted(self.ns['DROP_DIR'].glob('*.conf'))
            return (f"FragmentPath={self.ns['UNIT']}\nDropInPaths={' '.join(map(str, paths))}\nNeedDaemonReload=no\n".encode(), 0)
        if argv[1] == 'is-active':
            return b'', 0 if self.running else 3
        if argv[1] == 'daemon-reload':
            return b'', 0
        if argv[1] == 'restart':
            code = self.restart_codes.pop(0) if self.restart_codes else 0
            self.running = code == 0
            return b'', code
        if argv[1] == 'stop':
            self.running = False
            return b'', 0
        raise AssertionError(argv)


@pytest.fixture
def helper(tmp_path, monkeypatch):
    ns = {'__name__': 'isolated_helper_definitions'}
    exec(compile(ROOT_PROGRAM, '<rules-helper-definitions>', 'exec'), ns)
    mapping = {
        'ROOT': 'var/lib/megalodon-suricata',
        'BASE': 'etc/suricata/suricata.yaml',
        'DROP_DIR': 'etc/systemd/system/suricata.service.d',
        'ENGINE': 'usr/bin/suricata', 'UPDATER': 'usr/bin/suricata-update',
        'SYSTEMCTL': 'usr/bin/systemctl', 'LOG': 'var/log/suricata',
        'UNIT': 'usr/lib/systemd/system/suricata.service',
        'LOCAL_UNIT': 'etc/systemd/system/suricata.service',
    }
    for key, relative in mapping.items():
        ns[key] = tmp_path / relative
    ns['GENS'] = ns['ROOT'] / 'generations'
    ns['DROP'] = ns['DROP_DIR'] / 'zzzz-megalodon-rules.conf'
    ns['ANCHOR'] = tmp_path
    ns['TRUSTED_UID'] = os.getuid()
    for key in ('ROOT', 'GENS', 'DROP_DIR', 'LOG'):
        ns[key].mkdir(parents=True, exist_ok=True, mode=0o750)
    for key in ('ENGINE', 'UPDATER', 'SYSTEMCTL', 'BASE', 'UNIT'):
        ns[key].parent.mkdir(parents=True, exist_ok=True)
        ns[key].write_bytes(b'fixture executable' if key != 'BASE' else b'')
    ns['UNIT'].write_text('[Service]\nExecStart='+str(ns['ENGINE'])+' --af-packet -c '+str(ns['BASE'])+' --pidfile /run/suricata.pid --user suricata --group suricata\n')
    custom = ns['BASE'].parent / 'custom.rules'
    custom.write_bytes(CUSTOM)
    config = {'vars': {'address-groups': {'HOME_NET': '[198.51.100.0/24]', 'EXTERNAL_NET': '!$HOME_NET'},
                       'port-groups': {'HTTP_PORTS': '80'}},
              'rule-files': ['custom.rules'], 'default-rule-path': str(custom.parent)}
    ns['BASE'].write_text(json.dumps(config))
    monkeypatch.setattr(ns['socket'], 'if_nameindex', lambda: [(1, 'test0')])
    monkeypatch.setattr(ns['grp'], 'getgrnam', lambda _: SimpleNamespace(gr_gid=os.getgid()))
    native = FakeNative(ns)
    ns['run'] = native
    return SimpleNamespace(ns=ns, native=native, custom=custom, config=config, path=tmp_path,
                           stage=lambda: ns['stage']('test0', '192.0.2.0/24'))


def test_stage_is_additive_and_isolated_without_activation(helper):
    ns, native = helper.ns, helper.native
    base, custom = ns['BASE'].read_bytes(), helper.custom.read_bytes()
    result = helper.stage()
    assert result['state'] == 'staged'
    assert result['native_test_passed'] and result['runtime_state'] == 'not_checked'
    assert not ns['DROP'].exists() and not (ns['ROOT'] / 'state.json').exists()
    assert ns['BASE'].read_bytes() == base and helper.custom.read_bytes() == custom
    generation = ns['GENS'] / result['generation']
    config = json.loads((generation / 'update.yaml').read_bytes())
    assert config['sources'] == [ns['SOURCE']] and config['local'] == []
    assert config['dist-rule-directory'] == str(generation / 'empty')
    for field in ('enable-conf', 'disable-conf', 'drop-conf', 'modify-conf'):
        assert config[field] == str(generation / 'empty.conf')
    update = next(argv for argv, _ in native.calls if argv[0] == str(ns['UPDATER']))
    assert update[-3:] == ['--no-reload', '--no-test', '--fail']
    assert update[update.index('-D') + 1] == str(generation / 'data')
    tests = [argv for argv, _ in native.calls if '-T' in argv]
    assert len(tests) == 1 and '-s' in tests[0] and '-S' not in tests[0]
    assert '--init-errors-fatal' in tests[0]
    overlay = ns['yaml_document']((generation / 'overlay.yaml').read_bytes())
    assert overlay['vars']['address-groups']['HOME_NET'] == '[192.0.2.0/24]'
    assert overlay['vars']['address-groups']['EXTERNAL_NET'] == '!$HOME_NET'
    assert overlay['vars']['port-groups'] == {'HTTP_PORTS': '80'}


def test_activate_check_and_explicit_rollback_preserve_original(helper):
    ns = helper.ns
    before = ns['BASE'].read_bytes(), helper.custom.read_bytes(), ns['UNIT'].read_bytes()
    staged = helper.stage()
    result = ns['activate'](staged['generation'])
    assert result['state'] == 'active' and result['rollback'] == 'available'
    assert ns['check']()['generation'] == staged['generation']
    assert ns['DROP'].read_bytes() == ns['dropin'](staged['generation'], 'test0')
    result = ns['rollback']()
    assert result['state'] == 'rolled_back' and result['runtime_state'] == 'inactive_at_check'
    assert not ns['DROP'].exists() and not (ns['ROOT'] / 'pending.json').exists()
    assert ns['state']() == {'active': None, 'rollback': None}
    assert before == (ns['BASE'].read_bytes(), helper.custom.read_bytes(), ns['UNIT'].read_bytes())


def test_second_generation_rolls_back_to_previous_managed_generation(helper):
    ns = helper.ns
    first = helper.stage()['generation']
    ns['activate'](first)
    helper.native.candidate = RULE.replace(b'4000001', b'4000003')
    second = helper.stage()['generation']
    ns['activate'](second)
    result = ns['rollback']()
    assert result['generation'] == first and result['runtime_state'] == 'active_at_check'
    assert ns['state']()['active'] == first
    assert ns['check']()['generation'] == first


@pytest.mark.parametrize('failure,code', [('update', 'UPDATE_FAILED'), ('test', 'TEST_FAILED'), ('timeout', 'TIMEOUT')])
def test_staging_failure_never_touches_active_service(helper, failure, code):
    if failure == 'update':
        helper.native.update_code = 1
    elif failure == 'test':
        helper.native.test_code = 1
    else:
        helper.native.timeout = True
    with pytest.raises(helper.ns['Fault'], match=code):
        helper.stage()
    assert not helper.ns['DROP'].exists()
    assert not any(argv[1] in {'restart', 'stop'} for argv, _ in helper.native.calls)


@pytest.mark.parametrize('target', ['engine', 'base', 'custom', 'rules', 'overlay', 'manifest', 'service'])
def test_activation_rejects_generation_or_dependency_tampering(helper, target):
    ns = helper.ns
    generation = helper.stage()['generation']
    directory = ns['GENS'] / generation
    paths = {'engine': ns['ENGINE'], 'base': ns['BASE'], 'custom': helper.custom,
             'rules': directory / 'suricata.rules', 'overlay': directory / 'overlay.yaml',
             'manifest': directory / 'manifest.json', 'service': ns['UNIT']}
    if target == 'manifest':
        value = json.loads(paths[target].read_bytes()); value['generation'] = 'b' * 32
        paths[target].write_text(json.dumps(value))
    else:
        paths[target].write_bytes(paths[target].read_bytes() + b'\n# changed\n')
    with pytest.raises(ns['Fault']):
        ns['activate'](generation)
    assert not ns['DROP'].exists()


def test_check_rejects_preserved_service_drift(helper):
    ns = helper.ns
    ns['activate'](helper.stage()['generation'])
    ns['UNIT'].write_bytes(ns['UNIT'].read_bytes() + b'# changed\n')
    with pytest.raises(ns['Fault'], match='STALE_GENERATION'):
        ns['check']()


def test_mutation_during_native_retest_prevents_activation(helper):
    ns=helper.ns
    generation=helper.stage()['generation']
    original=ns['run']
    def mutate(argv,*args,**kwargs):
        result=original(argv,*args,**kwargs)
        if '-T' in argv:
            (ns['GENS']/generation/'suricata.rules').write_bytes(RULE.replace(b'4000001',b'4000099'))
        return result
    ns['run']=mutate
    with pytest.raises(ns['Fault'],match='STALE_GENERATION'):
        ns['activate'](generation)
    assert not ns['DROP'].exists()


def test_restart_failure_restores_original_service(helper):
    ns = helper.ns
    helper.native.running = True
    generation = helper.stage()['generation']
    helper.native.restart_codes = [1, 0]
    result = ns['activate'](generation)
    assert result['error'] == 'RESTART_FAILED' and result['rollback'] == 'restored'
    assert helper.native.running and not ns['DROP'].exists()
    assert not (ns['ROOT'] / 'pending.json').exists()


def test_failed_rollback_leaves_durable_recovery_then_explicit_rollback(helper):
    ns = helper.ns
    helper.native.running = True
    generation = helper.stage()['generation']
    helper.native.restart_codes = [1, 1]
    result = ns['activate'](generation)
    assert result['error'] == 'ROLLBACK_FAILED' and result['rollback'] == 'failed'
    assert (ns['ROOT'] / 'pending.json').exists()
    with pytest.raises(ns['Fault'], match='PENDING_RECOVERY'):
        ns['check']()
    assert ns['rollback']()['rollback'] == 'restored'
    assert not (ns['ROOT'] / 'pending.json').exists()


def test_pending_recovery_never_deletes_operator_override(helper):
    ns = helper.ns
    helper.native.running = True
    generation = helper.stage()['generation']
    helper.native.restart_codes = [1, 1]
    ns['activate'](generation)
    ns['DROP'].write_bytes(b'[Service]\n# operator edit\n')
    result = ns['rollback']()
    assert result['error'] == 'ROLLBACK_FAILED'
    assert b'operator edit' in ns['DROP'].read_bytes()
    assert (ns['ROOT'] / 'pending.json').exists()


def test_rollback_can_remove_broken_current_rules_without_overwriting_custom_files(helper):
    ns = helper.ns
    generation = helper.stage()['generation']
    ns['activate'](generation)
    (ns['GENS'] / generation / 'suricata.rules').write_bytes(b'broken candidate')
    assert ns['rollback']()['rollback'] == 'restored'
    assert helper.custom.read_bytes() == CUSTOM


@pytest.mark.parametrize('kind', ['file_link', 'directory_link', 'hardlink', 'writable_parent', 'traversal', 'fifo'])
def test_untrusted_paths_fail_closed(helper, kind):
    ns = helper.ns
    path = helper.path / 'safe-file'
    path.write_bytes(b'fixture')
    if kind == 'file_link':
        path.unlink(); path.symlink_to(helper.custom)
    elif kind == 'directory_link':
        (helper.path / 'linked').symlink_to(helper.custom.parent, target_is_directory=True)
        path = helper.path / 'linked' / 'custom.rules'
    elif kind == 'hardlink':
        os.link(path, helper.path / 'second-name')
    elif kind == 'writable_parent':
        directory = helper.path / 'writable'; directory.mkdir(mode=0o777); directory.chmod(0o777)
        path = directory / 'file'; path.write_bytes(b'fixture')
    elif kind == 'traversal':
        path = helper.path / 'not-real' / '..' / 'safe-file'
    else:
        path.unlink(); os.mkfifo(path)
    with pytest.raises(ns['Fault'], match='UNSAFE_PATH'):
        ns['read'](path)


@pytest.mark.parametrize('rule,code', [
    (CUSTOM, 'RULE_CONFLICT'), (RULE + RULE, 'RULE_CONFLICT'),
    (RULE.replace(b'alert ', b'drop '), 'RULE_UNSUPPORTED'),
    (RULE.replace(b'rev:1;', b'lua:script.lua;'), 'RULE_UNSUPPORTED'),
    (RULE.replace(b'rev:1;', b'luaxform:script.lua;'), 'RULE_UNSUPPORTED'),
    (RULE.replace(b'rev:1;', b'filestore;'), 'RULE_UNSUPPORTED'),
    (RULE.replace(b'rev:1;', b'dataset:isset,data;'), 'RULE_UNSUPPORTED'),
    (RULE.replace(b'rev:1;', b'filesha256:file.txt;'), 'RULE_UNSUPPORTED'),
])
def test_conflicting_or_effectful_rules_are_never_staged(helper, rule, code):
    helper.native.candidate = rule
    with pytest.raises(helper.ns['Fault'], match=code):
        helper.stage()
    assert not helper.ns['DROP'].exists()


@pytest.mark.parametrize('config', [b'include: /other.yaml\n', b'a: 1\na: 2\n', b'a: &anchor [a]\nb: *anchor\n', b'lua: {scripts: [other.lua]}\n'])
def test_unresolved_config_is_rejected_before_download(helper, config):
    helper.ns['BASE'].write_bytes(config)
    with pytest.raises(helper.ns['Fault'], match='CONFIG_UNSUPPORTED'):
        helper.stage()
    assert not helper.native.calls


@pytest.mark.parametrize('directive', ['EnvironmentFile=/unbound/environment',
    'ExecStartPre=/unbound/script', 'Environment=LD_PRELOAD=/unbound/library',
    'RootDirectory=/unbound/root', 'BindPaths=/unbound/path', 'ExecStartPost=/unbound/script'])
def test_service_external_dependencies_are_rejected_before_download(helper, directive):
    path=helper.ns['UNIT']
    path.write_text(path.read_text()+directive+'\n')
    with pytest.raises(helper.ns['Fault'], match='SERVICE_UNSUPPORTED'):
        helper.stage()
    assert not any(argv[0]==str(helper.ns['UPDATER']) for argv,_ in helper.native.calls)


@pytest.mark.parametrize('extra', [b'outputs.1 = pcap-log\n', b'outputs.0.eve-log.types.0.alert.packet = yes\n', b'af-packet.1.interface = other\n'])
def test_merged_capture_or_payload_outputs_fail_closed(helper, extra):
    helper.native.dump += extra
    with pytest.raises(helper.ns['Fault'], match='CONFIG_UNSUPPORTED'):
        helper.stage()
    assert not helper.ns['DROP'].exists()


def encoded_receipt(**changes):
    value = dict(schema=SCHEMA, action='check', state='unconfigured', checked_at='2026-11-16T12:00:00Z',
                 generation=None, interface=None, home_net=None, rule_count=0,
                 native_test_passed=False, runtime_state='not_checked', rollback='none', error=None)
    value.update(changes)
    return json.dumps(value).encode()


def test_manager_get_is_cached_and_actions_have_closed_fixed_arguments():
    calls = []
    def run(argv, maximum, timeout):
        calls.append((argv, maximum, timeout))
        return encoded_receipt(), 0
    manager = SuricataRules(run=run)
    assert manager.snapshot()['checked_at'] is None and not calls
    assert manager.check()['checked_at'] == '2026-11-16T12:00:00Z'
    assert calls[0][0] == ['/usr/bin/pkexec', '/usr/bin/python3', '-I', '-c', ROOT_PROGRAM, 'check']
    assert calls[0][1:] == (8192, 420)
    copy = manager.snapshot(); copy['state'] = 'active'
    assert manager.snapshot()['state'] == 'unconfigured' and len(calls) == 1


@pytest.mark.parametrize('interface,home_net', [('test0;id', '192.0.2.0/24'), ('x' * 16, '192.0.2.0/24'),
    ('test0', '192.0.2.4/24'), ('test0', '192.0.2.0/24,198.51.100.0/24'), ('test0', 'any'), ('test0', ['192.0.2.0/24'])])
def test_scope_refuses_injection_and_ambiguous_network(interface, home_net):
    with pytest.raises(ValueError):
        validate_scope(interface, home_net)


@pytest.mark.parametrize('output,code', [(b'not json', 0), (b'{}', 0),
    (encoded_receipt(extra='unexpected'), 0), (encoded_receipt(), 1),
    (encoded_receipt(state='active'), 0), (b'x' * 8193, 0)])
def test_malformed_or_inconsistent_receipt_is_never_runtime_evidence(output, code):
    manager = SuricataRules(run=lambda *_: (output, code))
    with pytest.raises(ValueError, match='valid receipt'):
        manager.check()
    status = manager.snapshot()
    assert status['state'] == 'needs_review' and status['runtime_state'] == 'unknown'
    assert not status['native_test_passed']


def test_manager_timeout_and_pending_recovery_are_actionable_without_native_effects():
    def timeout(*_):
        raise subprocess.TimeoutExpired('fixture', 1)
    manager = SuricataRules(run=timeout)
    with pytest.raises(ValueError):
        manager.check()
    assert manager.snapshot()['runtime_state'] == 'unknown'
    manager.run = lambda *_: (encoded_receipt(state='needs_review', error='PENDING_RECOVERY', rollback='available'), 1)
    with pytest.raises(ValueError, match='explicit rollback'):
        manager.check()
    assert manager.snapshot()['rollback'] == 'available'


def test_stage0_denies_constructor_and_malformed_actions_before_adapter(monkeypatch):
    calls = []
    manager = SuricataRules(run=lambda *args: calls.append(args))
    def deny():
        raise execution_boundary.Stage0Denied()
    monkeypatch.setattr(execution_boundary, 'require_effects_allowed', deny)
    for call in (lambda: SuricataRules(), lambda: validate_scope(None, None),
                 lambda: manager.stage(None, None), lambda: manager.activate(None),
                 manager.check, manager.rollback):
        with pytest.raises(execution_boundary.Stage0Denied):
            call()
    assert not calls
    assert manager.snapshot()['checked_at'] is None


def test_installed_engine_inert_overlay_smoke_preserves_variables_and_only_metadata(tmp_path):
    engine = Path('/usr/bin/suricata')
    if not engine.is_file():
        pytest.skip('Optional installed engine is unavailable; no engine qualification claimed.')
    ns = {'__name__': 'inert_smoke_definitions'}
    exec(compile(ROOT_PROGRAM, '<rules-helper-definitions>', 'exec'), ns)
    (tmp_path / 'classification.config').write_text('config classification: misc-activity,Misc activity,3\n')
    (tmp_path / 'reference.config').write_text('')
    config = {'vars': {'address-groups': {'HOME_NET': '[198.51.100.0/24]', 'EXTERNAL_NET': '!$HOME_NET'},
                       'port-groups': {'HTTP_PORTS': '80'}}, 'rule-files': [], 'outputs': [], 'af-packet': [],
              'classification-file': str(tmp_path / 'classification.config'),
              'reference-config-file': str(tmp_path / 'reference.config')}
    (tmp_path / 'base.yaml').write_text('%YAML 1.1\n---\n' + json.dumps(config))
    (tmp_path / 'overlay.yaml').write_bytes(ns['overlay']('lo', '192.0.2.0/24', config['vars']))
    (tmp_path / 'fixture.rules').write_bytes(RULE.replace(b'any any -> any any', b'$EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS'))
    args = [str(engine), '-c', str(tmp_path / 'base.yaml'), '--include', str(tmp_path / 'overlay.yaml'),
            '-s', str(tmp_path / 'fixture.rules'), '--af-packet=lo', '--runmode', 'single',
            '--init-errors-fatal', '-l', str(tmp_path)]
    for flag in ('--dump-config', '-T'):
        result = subprocess.run(args + [flag], capture_output=True, timeout=30,
                                env={**os.environ, 'SC_LOG_LEVEL': 'Error'})
        assert result.returncode == 0, (result.stdout + result.stderr).decode(errors='replace')
        if flag == '--dump-config':
            ns['run'] = lambda *_: (result.stdout + result.stderr, result.returncode)
            assert ns['effective']('a' * 32, 'lo')
            assert b'vars.port-groups.HTTP_PORTS = 80' in result.stdout
            assert b'vars.address-groups.EXTERNAL_NET = !$HOME_NET' in result.stdout
            assert b'vars.address-groups.HOME_NET = [192.0.2.0/24]' in result.stdout
