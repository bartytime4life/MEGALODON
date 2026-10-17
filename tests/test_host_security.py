"""Host security must preserve provenance, baseline identity and action separation."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import pytest
from megalodon.host_security import HostSecurity, SOURCES, parse_feed, stamp, CACHE_SCHEMA

NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def source_body(source, now=NOW):
    if source == 'ipsum':
        return ('# IPsum Threat Intelligence Feed\n# Last update: '+now.strftime('%a, %d %b %Y %H:%M:%S +0000')+'\n8.8.8.8\t4\n1.1.1.1\t2\n').encode()
    cidr = '8.8.8.0/24' if source == 'drop-v4' else '2606:4700::/32'
    return (json.dumps(dict(cidr=cidr,sblid='SBL123'))+'\n'+json.dumps(dict(type='metadata',timestamp=int(now.timestamp()),records=1))+'\n').encode()


@pytest.fixture
def manager(tmp_path):
    home = tmp_path/'home'; home.mkdir(mode=0o700)
    return HostSecurity(home, now=lambda:NOW, downloader=source_body)


def test_match_is_local_dated_context_never_a_command(manager):
    manager.execute('refresh')
    manager.downloader=lambda *a: pytest.fail('matching contacted a publisher')
    rows=manager.matches(['8.8.8.8','1.1.1.1','2606:4700:4700::1111','127.0.0.1'])
    assert {(r['ip'],r['source']) for r in rows} == {('8.8.8.8','drop-v4'),('8.8.8.8','ipsum'),('2606:4700:4700::1111','drop-v6')}
    assert all(r['action_status']=='not_attempted' and r['status']=='context_match' for r in rows)
    assert all(r['sha256']==hashlib.sha256(source_body(r['source'])).hexdigest() for r in rows)
    assert manager.snapshot()['action_authority']=='none'
    assert not manager.matches(['1.1.1.1'])  # Occurrence count 2 is below the fixed threshold.
    manager.now=lambda:NOW+timedelta(days=3)
    assert manager.snapshot()['feed_state']=='stale'
    assert manager.matches(['8.8.8.8'])==[]


@pytest.mark.parametrize('age', [timedelta(days=3),-timedelta(hours=1)])
def test_reject_publisher_staleness_and_future_time(age):
    for source in SOURCES:
        with pytest.raises(ValueError):parse_feed(source,source_body(source,NOW-age),NOW)


def test_failed_refresh_preserves_valid_cache_and_consumes_daily_slot(manager):
    manager.execute('refresh'); old=(manager.root/'feeds.json').read_bytes()
    manager.now=lambda:NOW+timedelta(hours=25)
    manager.downloader=lambda source:source_body(source,manager.now()) if source!='ipsum' else b'invalid'
    with pytest.raises(ValueError):manager.execute('refresh')
    assert (manager.root/'feeds.json').read_bytes()==old
    with pytest.raises(ValueError,match='once per day'):manager.execute('refresh')
    assert manager.matches(['8.8.8.8'])


def test_cache_replacement_retains_previous_and_receipts(manager):
    manager.execute('refresh');old=(manager.root/'feeds.json').read_bytes()
    manager.now=lambda:NOW+timedelta(days=1)
    manager.downloader=lambda source:source_body(source,manager.now())
    manager.execute('refresh')
    assert (manager.root/'feeds.previous.json').read_bytes()==old
    assert all(f['terms'] and f['bytes']>0 for f in manager.snapshot()['feeds'])


@pytest.mark.parametrize('bad', [b'',b'{"cidr":"0.0.0.0/0","sblid":"SBL1"}\n',
                                b'{"cidr":"8.8.8.0/24","cidr":"1.1.1.0/24","sblid":"SBL1"}\n'])
def test_reject_missing_metadata_duplicates_and_broad_nonpublic_ranges(bad):
    with pytest.raises((ValueError,KeyError)):parse_feed('drop-v4',bad,NOW)


def test_reject_symlink_and_broadly_readable_cache(manager,tmp_path):
    manager.execute('refresh');path=manager.root/'feeds.json'
    path.chmod(0o644)
    assert manager.snapshot()['feed_state']=='unavailable'
    with pytest.raises(ValueError):manager.matches(['8.8.8.8'])
    path.chmod(0o600);path.unlink();outside=tmp_path/'outside';outside.write_text('{}');path.symlink_to(outside)
    with pytest.raises(ValueError):manager.matches(['8.8.8.8'])


def test_refuse_arbitrary_actions_and_unbounded_addresses(manager):
    for action in ['block','shell','audit;id','update-baseline']:
        with pytest.raises(ValueError):manager.execute(action)
    with pytest.raises(ValueError):manager.matches(['8.8.8.8']*257)
    assert not manager.root.exists()


def test_aide_baseline_refusal_precedes_any_program(manager):
    with manager.locked():
        (manager.root/'baseline.json').write_text('{}')
    manager.runner=lambda *a:pytest.fail('baseline executed a tool')
    with pytest.raises(ValueError,match='already exists'):manager.execute('baseline')


def test_baseline_and_changed_check_preserve_initial_database(manager,monkeypatch):
    from megalodon import host_security as module
    real_is_file=Path.is_file;real_stat=Path.stat
    def file_exists(p):return True if str(p)=='/usr/sbin/aide' else real_is_file(p)
    from types import SimpleNamespace
    def metadata(p,*args,**kwargs):
        return SimpleNamespace(st_uid=0,st_mode=0o100755) if str(p)=='/usr/sbin/aide' else real_stat(p,*args,**kwargs)
    monkeypatch.setattr(Path,'is_file',file_exists);monkeypatch.setattr(Path,'stat',metadata)
    calls=[]
    def run(argv,work):
        calls.append(argv)
        if '--init' in argv:(work/'new.db.gz').write_bytes(b'observed baseline')
        return b'AIDE result',0 if '--init' in argv else 4
    manager.runner=run
    manager.execute('baseline')
    before=(manager.root/'aide.db.gz').read_bytes()
    manager.execute('check')
    assert (manager.root/'aide.db.gz').read_bytes()==before
    assert manager.snapshot()['integrity']['metrics']['changed_detected']==1
    assert all('--update' not in argv for argv in calls)
    assert json.loads((manager.root/'baseline.json').read_text())['trust']=='observed_not_known_clean'
    (manager.root/'aide.db.gz').write_bytes(b'changed baseline')
    with pytest.raises(ValueError,match='integrity'):manager.execute('check')
    assert len(calls)==2


def test_support_actions_are_closed_and_use_existing_job_lane():
    from megalodon.support_config import validate_action
    for action in ['security_audit','security_baseline','security_check','security_refresh']:
        assert validate_action({'action':action})=={'action':action}
        with pytest.raises(ValueError):validate_action({'action':action,'url':'https://example.com'})


def test_drop_preserves_multiple_sbl_references_for_one_range():
    rows=[dict(cidr='8.8.8.0/24',sblid='SBL1'),dict(cidr='8.8.8.0/24',sblid='SBL2'),
          dict(type='metadata',timestamp=int(NOW.timestamp()),records=2)]
    raw=('\n'.join(json.dumps(row) for row in rows)+'\n').encode()
    value=parse_feed('drop-v4',raw,NOW)
    assert value['entries']==[['8.8.8.0/24','SBL1, SBL2']]


@pytest.mark.parametrize('declared', ['5','999999999','2, 2'])
def test_download_rejects_truncation_or_ambiguous_size(monkeypatch,declared):
    from megalodon import host_security as module
    class Response:
        status=200
        def getheader(self,key,default=None):return declared if key=='Content-Length' else default
        def read1(self,size):
            value=getattr(self,'body',b'xy');self.body=b'';return value
    class Connection:
        def __init__(self,host,timeout):assert host=='www.spamhaus.org' and timeout==10
        def request(self,method,target,headers):assert method=='GET' and target=='/drop/drop_v4.json'
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(module.http.client,'HTTPSConnection',Connection)
    with pytest.raises(ValueError):module.fetch('drop-v4')
