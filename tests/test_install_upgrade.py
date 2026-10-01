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
