from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from megalodon import install_lifecycle, local_install, release_inspection as ri
from test_local_install import layout


@pytest.mark.parametrize(('location','expected'), [('none',False),('cwd',True),('exe',True),
    ('fd',True),('map',True),('argv',True),('alias',True),('marked_alias',False),('wrong_marker',True)])
def test_real_metadata_matchers_on_private_fixture(tmp_path,monkeypatch,location,expected):
    base=tmp_path/'proc [case]*'/'42'
    (base/'fd').mkdir(parents=True)
    paths=SimpleNamespace(current=tmp_path/'current')
    release=tmp_path/'lib[abc]*?'/'old'
    (base/'cwd').symlink_to(release if location=='cwd' else '/')
    (base/'exe').symlink_to(release/'program' if location=='exe' else '/usr/bin/python3')
    (base/'maps').write_bytes(str(release/'lib.so').encode() if location=='map' else b'')
    command={'argv':release/'bin/p','alias':paths.current/'bin/p','marked_alias':paths.current/'bin/p','wrong_marker':paths.current/'bin/p'}.get(location, '/bin/sh')
    (base/'cmdline').write_bytes(str(command).encode()+b'\x00-I\x00')
    target={'fd':release/'owned','marked_alias':release.parent/'new'/'megalodon','wrong_marker':tmp_path/'else'/'megalodon'}.get(location,'/dev/null')
    (base/'fd'/'3').symlink_to(target)
    monkeypatch.setattr(ri,'_inspect',lambda argv: subprocess.run(argv,capture_output=True))
    assert ri._references_at(base,paths,release) is expected


@pytest.mark.parametrize('code,stdout,stderr', [(1,b'',b''),(1,b'0\n',b'denied'),(2,b'0\n',b''),(0,b'0\n',b''),(0,b'',b'')])
def test_denied_or_inconclusive_is_never_absence(monkeypatch,code,stdout,stderr):
    monkeypatch.setattr(ri,'_inspect',lambda argv:subprocess.CompletedProcess(argv,code,stdout,stderr))
    with pytest.raises(local_install.InstallError):
        ri._contains(Path('/fixture/maps'),'dummy')


def test_recovery_only_retires_one_confirmed_unused_copy(layout,monkeypatch):
    local_install._prepare_directories(layout)
    ids=[f'1-20261001T1200{i:02d}Z-aaaabbbb' for i in range(40)]
    for name in ids:(layout.releases/name).mkdir(mode=0o700)
    proc=layout.app/'fake-proc';process=proc/'123';(process/'fd').mkdir(parents=True)
    (process/'cmdline').write_bytes(b'normal')
    real_iterdir=Path.iterdir
    def iterdir(path):
        if path==Path('/proc'):return iter([process])
        if path==process/'fd':raise PermissionError()
        return real_iterdir(path)
    monkeypatch.setattr(Path,'iterdir',iterdir)
    manifest=dict(active_release=ids[-1], previous_release=ids[-2],releases=[dict(id=i) for i in ids])
    layout.current.symlink_to(layout.releases/ids[2])
    calls=[]
    def protected(pid,paths,release):
        calls.append(release.name)
        return release.name==ids[0]
    monkeypatch.setattr(ri,'protected_process_holds',protected)
    assert len(install_lifecycle.retire_releases(layout,manifest)['releases'])==40
    assert calls==[]
    assert len(install_lifecycle.retire_releases(layout,manifest,inspect_protected=True)['releases'])==39
    assert calls==ids[:2] and not (layout.releases/ids[1]).exists()
    assert all((layout.releases/i).is_dir() for i in ids if i!=ids[1])
