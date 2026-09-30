from datetime import datetime, timezone
import gzip
import io
import json
from types import SimpleNamespace

import pytest

from megalodon import live_geography as module


class Response(io.BytesIO):
    status=200
    def getheader(self,name,default=None):
        return str(len(self.getvalue())) if name=='Content-Length' else default


def connections(monkeypatch, database=b'mock MMDB', public=b'{"ip":"8.8.8.8"}'):
    calls=[]
    class Connection:
        def __init__(self,host,timeout): self.host=host
        def request(self,method,path,headers): calls.append((self.host,method,path))
        def getresponse(self):
            return Response(gzip.compress(database) if self.host=='download.db-ip.com' else public)
        def close(self): pass
    monkeypatch.setattr(module,'HTTPSConnection',Connection)
    return calls


def test_monthly_download_then_private_peer_lookups_and_bounded_egress_discovery(tmp_path,monkeypatch):
    calls=connections(monkeypatch)
    stamp=datetime.now(timezone.utc).replace(day=1,hour=0,minute=0,second=0,microsecond=0)
    class Reader:
        def metadata(self): return SimpleNamespace(database_type='DBIP-City-Lite',build_epoch=stamp.timestamp())
        def close(self): pass
        def detail(self,ip): return {'latitude':38.9,'longitude':-94.7,'label':'Approximate test region','source':'DB-IP City Lite','country':'US','approximate':True,'accuracy_radius_km':None}
    monkeypatch.setattr(module.OfflineLocations,'open',lambda path:Reader())
    geo=module.Geography(tmp_path)
    assert geo.snapshot()['status']=='missing' and calls==[]
    geo.refresh()
    assert geo.snapshot()['status']=='ready' and geo.snapshot()['anchor']
    assert len(calls)==2
    assert calls[0][0]=='download.db-ip.com' and calls[1][0]=='api64.ipify.org'
    assert geo.path.stat().st_mode & 0o777==0o600
    assert json.loads(geo.receipt.read_text())['license']=='CC BY 4.0'
    for ip in ('1.1.1.1','8.8.4.4','9.9.9.9'):
        assert geo.lookup(ip)
    assert len(calls)==2  # no peer address appears in a network request
    geo.refresh()
    assert len(calls)==3 and calls[-1][0]=='api64.ipify.org'
    geo.close()


def test_geography_bomb_or_bad_release_does_not_replace_saved_database(tmp_path,monkeypatch):
    connections(monkeypatch,database=b'x'*1000)
    monkeypatch.setattr(module,'MAX_DATABASE_BYTES',64)
    geo=module.Geography(tmp_path)
    module._owned_directory(geo.root,private=True)
    geo.path.write_bytes(b'previous')
    with pytest.raises(ValueError):
        geo._download(datetime.now(timezone.utc).strftime('%Y-%m'))
    assert geo.path.read_bytes()==b'previous'
    assert not list(geo.root.glob('.dbip-*'))


def test_failed_public_lookup_clears_old_anchor_without_fabricating_location(tmp_path,monkeypatch):
    connections(monkeypatch,public=b'{"ip":"192.168.1.10"}')
    geo=module.Geography(tmp_path)
    geo._source_month=datetime.now(timezone.utc).strftime('%Y-%m')
    geo._reader=SimpleNamespace()
    geo._state['anchor']={'latitude':1,'longitude':2}
    geo.refresh()
    assert geo.snapshot()['anchor'] is None
    assert geo.snapshot()['status']=='ready'
