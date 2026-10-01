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
    assert install_lifecycle.selected_extras(layout)==['geo','capture']


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
    assert install_lifecycle._listener_pid(8787,'127.0.0.1')==501
    assert install_lifecycle._listener_pid(8787,'127.0.0.2') is None
    (process/'fd/4').unlink()
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
