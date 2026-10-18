"""Upgrade handoff must not leave an old service or lose rollback state."""
import json
from pathlib import Path
import pytest
from megalodon import local_install, install_lifecycle
from test_local_install import layout, source, release_factory


def test_supported_extra_survives_replacement(layout):
    target=layout.releases/'old/venv/lib/python3.12/site-packages/scapy-2.6.1.dist-info'
    target.mkdir(parents=True)
    layout.current.symlink_to(layout.releases/'old')
    assert install_lifecycle.selected_extras(layout)==['geo','knowledge','capture']


@pytest.mark.parametrize('failed',[False,True])
def test_service_handoff_and_rollback(layout,source,monkeypatch,failed):
    ids=iter(['1-20261001T120000Z-aaaabbbb','1-20261001T120001Z-aaaabbbc'])
    factory=release_factory(layout,ids)
    def create(paths,src):
        identifier,value=factory(paths,src)
        (paths.releases/identifier/'release.json').write_text(json.dumps({'package_sha256':'a'*64}))
        return identifier,value
    monkeypatch.setattr(local_install,'_create_release',create)
    monkeypatch.setattr(install_lifecycle,'retire_releases',lambda p,m:m)
    first=local_install.install(source,layout)
    original=layout.manifest.read_bytes()
    calls=[]
    monkeypatch.setattr(install_lifecycle,'service_running',lambda p:True)
    monkeypatch.setattr(install_lifecycle,'service_action',calls.append)
    def verify(p,digest):
        assert digest=='a'*64
        if failed:raise local_install.InstallError('synthetic readiness failure')
    monkeypatch.setattr(install_lifecycle,'verify_running',verify)
    if failed:
        with pytest.raises(local_install.InstallError):local_install.install(source,layout)
        assert layout.manifest.read_bytes()==original
        assert layout.current.resolve().name==first['active_release']
        assert calls==['stop','start','stop','start']
    else:
        result=local_install.install(source,layout)
        assert result['previous_release']==first['active_release']
        assert layout.current.resolve().name==result['active_release']
        assert calls==['stop','start']


@pytest.mark.parametrize('listener',[None,501])
def test_readiness_requires_managed_listener_even_with_matching_digest(layout,monkeypatch,listener):
    from types import SimpleNamespace
    import megalodon.config as config
    monkeypatch.setattr(config,'load_settings',lambda path:SimpleNamespace(dashboard=SimpleNamespace(host='127.0.0.1',port=8787)))
    monotonic=iter([0,0,1]);monkeypatch.setattr(install_lifecycle.time,'monotonic',lambda:next(monotonic))
    monkeypatch.setattr(install_lifecycle.time,'sleep',lambda seconds:None)
    monkeypatch.setattr(install_lifecycle,'_listener_pid',lambda port,host:listener)
    class Reply:
        status=200
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def read(self,limit):return json.dumps({'status':'ready','package_sha256':'a'*64}).encode()
    monkeypatch.setattr(install_lifecycle.urllib.request,'build_opener',lambda *args:SimpleNamespace(open=lambda *a,**kw:Reply()))
    if listener is None:
        with pytest.raises(local_install.InstallError):install_lifecycle.verify_running(layout,'a'*64,timeout=.5)
    else:install_lifecycle.verify_running(layout,'a'*64,timeout=.5)


def test_listener_requires_exact_address_and_service_socket(tmp_path,monkeypatch):
    from types import SimpleNamespace
    import os
    root=tmp_path/'proc';process=root/'501';(process/'fd').mkdir(parents=True);(process/'net').mkdir()
    (process/'fd/4').symlink_to('socket:[200]')
    (process/'net/tcp').write_text('header\n 0: 0100007F:2253 00000000:0000 0A 0 0 0 0 0 200\n')
    realpath=install_lifecycle.Path
    monkeypatch.setattr(install_lifecycle,'Path',lambda p:root if str(p)=='/proc' else realpath(p))
    monkeypatch.setattr(install_lifecycle.subprocess,'run',lambda *a,**kw:SimpleNamespace(stdout='501\n',returncode=0))
    monkeypatch.setattr(install_lifecycle,'_BYTE_ORDER','little')  # the row above is little-endian
    assert install_lifecycle._listener_pid(8787,'127.0.0.1')==501
    assert install_lifecycle._listener_pid(8787,'127.0.0.2') is None
    (process/'fd/4').unlink()
    assert install_lifecycle._listener_pid(8787,'127.0.0.1') is None


@pytest.mark.parametrize('order,address',[('little','0100007F'),('big','7F000001')])
def test_listener_address_decodes_in_host_byte_order(tmp_path,monkeypatch,order,address):
    from types import SimpleNamespace
    root=tmp_path/'proc';process=root/'501';(process/'fd').mkdir(parents=True);(process/'net').mkdir()
    (process/'fd/4').symlink_to('socket:[200]')
    (process/'net/tcp').write_text(f'header\n 0: {address}:2253 00000000:0000 0A 0 0 0 0 0 200\n')
    realpath=install_lifecycle.Path
    monkeypatch.setattr(install_lifecycle,'Path',lambda p:root if str(p)=='/proc' else realpath(p))
    monkeypatch.setattr(install_lifecycle.subprocess,'run',lambda *a,**kw:SimpleNamespace(stdout='501\n',returncode=0))
    monkeypatch.setattr(install_lifecycle,'_BYTE_ORDER',order)
    assert install_lifecycle._listener_pid(8787,'127.0.0.1')==501
    monkeypatch.setattr(install_lifecycle,'_BYTE_ORDER','big' if order=='little' else 'little')
    assert install_lifecycle._listener_pid(8787,'127.0.0.1') is None
    # A 16-byte tcp6-shaped address is never an IPv4 loopback listener.
    (process/'net/tcp').write_text('header\n 0: 0000000000000000FFFF00000100007F:2253 00000000:0000 0A 0 0 0 0 0 200\n')
    assert install_lifecycle._listener_pid(8787,'127.0.0.1') is None


def test_retirement_preserves_release_directory_held_by_a_process(layout,monkeypatch):
    from types import SimpleNamespace
    import os
    local_install._prepare_directories(layout)
    ids=[f'1-20261001T12000{i}Z-aaaabbb{i}' for i in range(6)]
    for identifier in ids:(layout.releases/identifier).mkdir(parents=True,mode=0o700)
    proc=layout.app/'fake-proc';process=proc/'123';(process/'fd').mkdir(parents=True)
    (process/'cmdline').write_bytes(str(layout.current/'venv/bin/python').encode())
    (process/'maps').write_bytes(b'')
    (process/'fd/7').symlink_to(layout.releases/ids[0]/'venv/lib/python3.12/site-packages/megalodon')
    realpath=install_lifecycle.Path
    monkeypatch.setattr(install_lifecycle,'Path',lambda p:proc if str(p)=='/proc' else realpath(p))
    monkeypatch.setattr(local_install,'_atomic_write',lambda *args:None)
    manifest=dict(active_release=ids[-1],previous_release=ids[-2],releases=[{'id':v} for v in ids])
    value=install_lifecycle.retire_releases(layout,manifest)
    assert ids[0] in [r['id'] for r in value['releases']]
    assert ids[1] not in [r['id'] for r in value['releases']]
    assert (layout.releases/ids[0]).exists() and not (layout.releases/ids[1]).exists()


def test_retirement_keeps_the_release_the_selector_points_at(layout,monkeypatch):
    local_install._prepare_directories(layout)
    ids=[f'1-20261001T1200{i:02d}Z-aaaabbbb' for i in range(8)]
    for identifier in ids:(layout.releases/identifier).mkdir(parents=True,mode=0o700)
    layout.current.symlink_to(layout.releases/ids[0])  # owner rollback to an old tree
    proc=layout.app/'fake-proc';proc.mkdir()
    realpath=install_lifecycle.Path
    monkeypatch.setattr(install_lifecycle,'Path',lambda p:proc if str(p)=='/proc' else realpath(p))
    monkeypatch.setattr(local_install,'_atomic_write',lambda *args:None)
    manifest=dict(active_release=ids[-1],previous_release=ids[-2],releases=[{'id':v} for v in ids])
    value=install_lifecycle.retire_releases(layout,manifest)
    assert (layout.releases/ids[0]).exists() and ids[0] in [r['id'] for r in value['releases']]
    assert not (layout.releases/ids[1]).exists()


@pytest.mark.parametrize('managed,state,expected',[
    (False,None,False),
    (False,{'DropInPaths':'','FragmentPath':'','LoadState':'not-found','ActiveState':'inactive'},False),
    (False,{'DropInPaths':'','FragmentPath':'/other/config/systemd/user/megalodon-hud.service','LoadState':'loaded','ActiveState':'active'},'refuse'),
    (False,{'DropInPaths':'','FragmentPath':'','LoadState':'not-found','ActiveState':'active'},'refuse'),
    (True,{'DropInPaths':'','FragmentPath':'/other/config/systemd/user/megalodon-hud.service','LoadState':'loaded','ActiveState':'inactive'},'refuse'),
    (True,{'DropInPaths':'','FragmentPath':'UNIT','LoadState':'loaded','ActiveState':'active'},True),
    (True,{'DropInPaths':'','FragmentPath':'UNIT','LoadState':'loaded','ActiveState':'inactive'},False),
    (True,None,False),
])
def test_service_running_asks_systemd_which_unit_file_it_loaded(layout,monkeypatch,managed,state,expected):
    from megalodon import hud_autostart
    unit=hud_autostart.unit_path(layout)
    if managed:
        unit.parent.mkdir(parents=True);unit.write_bytes(hud_autostart.unit_contents(layout))
    if state is not None and state['FragmentPath']=='UNIT':state=dict(state,FragmentPath=str(unit))
    monkeypatch.setattr(hud_autostart,'_service_state',lambda:state,raising=False)
    if expected=='refuse':
        with pytest.raises(local_install.InstallError,match='another unit file'):install_lifecycle.service_running(layout)
    else:assert install_lifecycle.service_running(layout) is expected


def test_service_running_refuses_drop_in_override(layout,monkeypatch):
    from megalodon import hud_autostart
    unit=hud_autostart.unit_path(layout)
    (unit.parent/'megalodon-hud.service.d').mkdir(parents=True);unit.write_bytes(hud_autostart.unit_contents(layout))
    monkeypatch.setattr(hud_autostart,'_service_state',lambda:pytest.fail('checked files first'),raising=False)
    with pytest.raises(local_install.InstallError,match='modified HUD service'):install_lifecycle.service_running(layout)


def test_service_running_refuses_drop_ins_systemd_loads_from_other_paths(layout,monkeypatch):
    from megalodon import hud_autostart
    unit=hud_autostart.unit_path(layout)
    unit.parent.mkdir(parents=True);unit.write_bytes(hud_autostart.unit_contents(layout))
    state={'FragmentPath':str(unit),'LoadState':'loaded','ActiveState':'active',
           'DropInPaths':'/run/systemd/user/megalodon-hud.service.d/override.conf'}
    monkeypatch.setattr(hud_autostart,'_service_state',lambda:state,raising=False)
    with pytest.raises(local_install.InstallError,match='modified HUD service'):install_lifecycle.service_running(layout)


def test_retirement_keeps_the_selected_release_when_data_home_has_dot_dot(tmp_path,monkeypatch):
    home=tmp_path/'home';(home/'detour').mkdir(parents=True,mode=0o700);home.chmod(0o700)
    paths=local_install.install_paths({'HOME':str(home),'XDG_DATA_HOME':str(home/'detour'/'..'/'share'),
                                       'XDG_CONFIG_HOME':str(home/'config')})
    assert '..' in paths.releases.parts
    local_install._prepare_directories(paths)
    ids=[f'1-20261001T1200{i:02d}Z-aaaabbbb' for i in range(8)]
    for identifier in ids:(paths.releases/identifier).mkdir(parents=True,mode=0o700)
    paths.current.symlink_to(paths.releases/ids[0])  # owner rollback, as _activate writes it
    proc=tmp_path/'fake-proc';proc.mkdir()
    realpath=install_lifecycle.Path
    monkeypatch.setattr(install_lifecycle,'Path',lambda p:proc if str(p)=='/proc' else realpath(p))
    monkeypatch.setattr(local_install,'_atomic_write',lambda *args:None)
    manifest=dict(active_release=ids[-1],previous_release=ids[-2],releases=[{'id':v} for v in ids])
    value=install_lifecycle.retire_releases(paths,manifest)
    assert (paths.releases/ids[0]).exists() and ids[0] in [r['id'] for r in value['releases']]
    assert not (paths.releases/ids[1]).exists()


def test_retirement_sees_normalized_proc_paths_when_data_home_has_dot_dot(tmp_path,monkeypatch):
    import os
    home=tmp_path/'home';(home/'detour').mkdir(parents=True,mode=0o700);home.chmod(0o700)
    paths=local_install.install_paths({'HOME':str(home),'XDG_DATA_HOME':str(home/'detour'/'..'/'share'),
                                       'XDG_CONFIG_HOME':str(home/'config')})
    local_install._prepare_directories(paths)
    ids=[f'1-20261001T12000{i}Z-aaaabbb{i}' for i in range(6)]
    for identifier in ids:(paths.releases/identifier).mkdir(parents=True,mode=0o700)
    # The kernel reports the descriptor target without `..`.
    held=os.path.normpath(paths.releases/ids[0])
    proc=tmp_path/'fake-proc';process=proc/'123';(process/'fd').mkdir(parents=True)
    (process/'cmdline').write_bytes(b'python\0-I\0-m\0megalodon\0hud')
    (process/'maps').write_bytes(b'')
    (process/'fd/7').symlink_to(held+'/venv/lib/python3.12/site-packages/megalodon')
    realpath=install_lifecycle.Path
    monkeypatch.setattr(install_lifecycle,'Path',lambda p:proc if str(p)=='/proc' else realpath(p))
    monkeypatch.setattr(local_install,'_atomic_write',lambda *args:None)
    manifest=dict(active_release=ids[-1],previous_release=ids[-2],releases=[{'id':v} for v in ids])
    value=install_lifecycle.retire_releases(paths,manifest)
    assert (paths.releases/ids[0]).exists() and ids[0] in [r['id'] for r in value['releases']]
    assert not (paths.releases/ids[1]).exists()
