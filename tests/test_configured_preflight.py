"""Selected configuration checks cannot start work or disclose private inputs."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

from megalodon import local_setup
from megalodon.config_check import MAX_BYTES
from megalodon.dashboard import UnconfiguredDashboardReader
from megalodon.storage import Store


@pytest.fixture
def configuration(tmp_path, monkeypatch):
    monkeypatch.setattr(local_setup.sys,'platform','linux')
    path=tmp_path/'private settings.toml'
    path.write_text('[app]\ndb_path = "selected core.sqlite3"\n')
    return path


@pytest.fixture
def reader(monkeypatch):
    calls=[]
    @contextmanager
    def missing(path, *, allow_missing):
        calls.append((path,allow_missing))
        yield UnconfiguredDashboardReader(path)
    monkeypatch.setattr(local_setup,'_dashboard_reader',missing)
    return calls


def receipt(capsys):
    captured=capsys.readouterr()
    assert captured.err==''
    result=json.loads(captured.out)
    assert len(captured.out.encode())<4096
    assert result['runtime_verified'] is False
    return result


def test_selected_config_checks_selected_core_path_and_returns_no_paths(configuration,reader,capsys):
    before=configuration.read_bytes()
    assert local_setup.main(['--config',str(configuration),'--json'])==0
    result=receipt(capsys)
    assert reader==[(Path('selected core.sqlite3'),True)]
    assert result['configuration']==dict(selection='explicit',status='valid')
    assert result['data']==dict(scope='configured_core_audit_store',status='not_configured')
    assert result['status']=='passed' and result['code']=='data_not_configured'
    text=json.dumps(result)
    assert str(configuration) not in text and 'selected core.sqlite3' not in text
    assert configuration.read_bytes()==before


def test_defaults_are_explicitly_distinguished_from_a_selected_file(reader,capsys,monkeypatch):
    monkeypatch.setattr(local_setup.sys,'platform','linux')
    assert local_setup.main(['--json'])==0
    result=receipt(capsys)
    assert result['configuration']==dict(selection='defaults',status='valid')
    assert reader==[(Path('data/megalodon.db'),True)]


@pytest.mark.parametrize('content,code', [
    (b'','input_empty_or_too_large'), (b'\xff','input_not_utf8'),
    (b'[app\nPRIVATE','invalid_toml'), (b'[wrong]\nsecret="PRIVATE"','unknown_table'),
    (b'[app]\ndb_pth="PRIVATE"','unknown_setting'),
    (b'[dashboard]\nport=true','invalid_setting_value'),
    (b'[dashboard]\nhost="example.invalid"','unsupported_dashboard_binding'),
    (b'[dashboard]\nhost="0.0.0.0"','unsupported_dashboard_binding'),
    (b'[capture]\nsource="scapy"','capture_interface_required'),
    (b'[ai]\nendpoint="https://PRIVATE.invalid"','invalid_setting_value'),
    (b'[app]\nname="first"\nname="PRIVATE"','invalid_toml'),
])
def test_invalid_configuration_is_refused_before_database_work(configuration,reader,capsys,content,code):
    configuration.write_bytes(content)
    assert local_setup.main(['--config',str(configuration),'--json'])==2
    result=receipt(capsys)
    assert result['status']=='refused' and result['code']==code
    assert result['configuration']['status']=='refused'
    assert result['data']['status']=='not_checked' and not reader
    assert 'PRIVATE' not in json.dumps(result)


@pytest.mark.parametrize('kind', ['missing','directory','symlink','fifo','too_large'])
def test_nonregular_missing_or_oversized_config_cannot_block_or_reach_database(configuration,reader,capsys,kind,tmp_path):
    if kind=='missing':configuration.unlink()
    elif kind=='directory':configuration.unlink();configuration.mkdir()
    elif kind=='symlink':
        target=tmp_path/'target';configuration.rename(target);configuration.symlink_to(target)
    elif kind=='fifo':configuration.unlink();os.mkfifo(configuration)
    else:configuration.write_bytes(b'#'+b'x'*MAX_BYTES)
    assert local_setup.main(['--config',str(configuration),'--json'])==2
    result=receipt(capsys)
    assert result['code']=='configuration_unavailable' and not reader
    assert str(configuration) not in json.dumps(result)


def test_exact_file_byte_limit(configuration,reader,capsys):
    configuration.write_bytes(b'#'+b'x'*(MAX_BYTES-1))
    assert local_setup.main(['--config',str(configuration),'--json'])==0
    assert receipt(capsys)['configuration']['status']=='valid'


@pytest.mark.parametrize('path',['','x'*4097,'private\nsettings','private\x00settings'])
def test_invalid_path_is_refused_without_echo_or_file_access(path,reader,capsys,monkeypatch):
    monkeypatch.setattr(local_setup.sys,'platform','linux')
    def forbidden(*args,**kwargs):raise AssertionError('invalid path opened')
    monkeypatch.setattr(local_setup.os,'open',forbidden)
    assert local_setup.main(['--config',path,'--json'])==2
    result=receipt(capsys)
    assert result['code']=='configuration_unavailable' and not reader


def test_config_change_during_read_is_refused_and_descriptor_closed(configuration,reader,capsys,monkeypatch):
    original=local_setup.os.read
    seen=[]
    def changing(descriptor,count):
        seen.append(descriptor)
        result=original(descriptor,count)
        if len(seen)==1:configuration.write_bytes(b'# changed size\n')
        return result
    monkeypatch.setattr(local_setup.os,'read',changing)
    assert local_setup.main(['--config',str(configuration),'--json'])==2
    assert receipt(capsys)['code']=='configuration_unavailable' and not reader
    with pytest.raises(OSError):os.fstat(seen[0])


def test_replaced_path_cannot_present_an_old_descriptor_as_the_selected_file(configuration,reader,capsys,monkeypatch):
    original=local_setup.os.read
    changed=[]
    def replacing(descriptor,count):
        result=original(descriptor,count)
        if not changed:
            changed.append(True)
            configuration.rename(configuration.with_suffix('.old'))
            configuration.write_bytes(b'# replaced path\n')
        return result
    monkeypatch.setattr(local_setup.os,'read',replacing)
    assert local_setup.main(['--config',str(configuration),'--json'])==2
    assert receipt(capsys)['code']=='configuration_unavailable' and not reader


@pytest.mark.parametrize('error',[ValueError('PRIVATE database'),OSError('PRIVATE path'),sqlite3.DatabaseError('PRIVATE contents')])
def test_database_errors_are_closed_diagnostics(configuration,capsys,monkeypatch,error):
    @contextmanager
    def refusing(*args,**kwargs):
        raise error
        yield
    monkeypatch.setattr(local_setup,'_dashboard_reader',refusing)
    assert local_setup.main(['--config',str(configuration),'--json'])==2
    result=receipt(capsys)
    assert result['code']=='database_unavailable'
    assert result['configuration']['status']=='valid' and result['data']['status']=='refused'
    assert 'PRIVATE' not in json.dumps(result)


@pytest.mark.parametrize('arguments', [['--config'],['--conf','SECRET'],['--port','8797'],
    ['--config','first','--config','SECRET'],['--json','--json'],['SECRET'],['--help']])
def test_cli_usage_is_admitted_before_configuration_or_data_work(arguments,monkeypatch,capsys):
    def forbidden(*args,**kwargs):raise AssertionError('preflight ran before argument admission')
    monkeypatch.setattr(local_setup,'preflight',forbidden)
    with pytest.raises(SystemExit) as caught:local_setup.main(arguments)
    assert caught.value.code==(0 if arguments==['--help'] else 2)
    captured=capsys.readouterr()
    assert 'SECRET' not in captured.out+captured.err


def test_unsupported_platform_refuses_before_reading_selected_path(configuration,reader,capsys,monkeypatch):
    monkeypatch.setattr(local_setup.sys,'platform','win32')
    def forbidden(*args):raise AssertionError('file read on unsupported platform')
    monkeypatch.setattr(local_setup,'_read_config',forbidden)
    assert local_setup.main(['--config',str(configuration),'--json'])==2
    result=receipt(capsys)
    assert result['code']=='unsupported_platform' and not reader


def test_no_external_work_when_enabled_options_are_present(configuration,reader,capsys):
    configuration.write_text('[ai]\nenabled=true\n[capture]\nsource="scapy"\ninterface="PRIVATE"\n')
    def forbidden(*args,**kwargs):raise AssertionError('external work attempted')
    with patch('socket.socket',forbidden),patch('socket.getaddrinfo',forbidden), \
         patch('subprocess.Popen',forbidden),patch('sqlite3.connect',forbidden):
        assert local_setup.main(['--config',str(configuration),'--json'])==0
    result=receipt(capsys)
    assert 'PRIVATE' not in json.dumps(result) and len(reader)==1


def test_text_command_preserves_selected_path_literally(configuration,reader,capsys,tmp_path):
    path=tmp_path/"settings ' $(touch NEVER_EXECUTE).toml"
    configuration.rename(path)
    assert local_setup.main(['--config',str(path)])==0
    text=capsys.readouterr().out
    command=text.split('Ready for manual HUD launch from this directory: ',1)[1].splitlines()[0]
    import shlex
    assert shlex.split(command)[-2:]==['--config',str(path.absolute())]
    assert not (tmp_path/'NEVER_EXECUTE').exists()


def test_real_selected_store_is_read_without_falling_back_to_default(tmp_path,monkeypatch,capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(local_setup.sys,'platform','linux')
    database=tmp_path/'selected'/'core.sqlite3'
    with Store(database):pass
    before=database.read_bytes()
    config=tmp_path/'settings.toml'
    config.write_text('[app]\ndb_path="selected/core.sqlite3"\n')
    unused=tmp_path/'data';unused.mkdir(mode=0o700)
    (unused/'megalodon.db').write_bytes(b'default store must not be opened')
    assert local_setup.main(['--config',str(config),'--json'])==0
    assert receipt(capsys)['data']['status']=='readable'
    assert database.read_bytes()==before
    assert (unused/'megalodon.db').read_bytes()==b'default store must not be opened'
