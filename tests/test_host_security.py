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


UNSAFE_RANGES = ('0.0.0.0/0', '224.0.0.0/4', '240.0.0.0/4',
    '8.0.0.0/5', '100.0.0.0/8', '192.0.0.0/16', '192.31.196.0/24',
    '192.52.193.0/24', '192.175.48.0/24', '::/0', 'ff00::/8',
    'fc00::/7', 'fe80::/10', '2000::/3', '2001::/16', '2002::/16',
    '2001:db8::/32', '3ffe::/16', '3fff::/20')


@pytest.mark.parametrize('cidr', UNSAFE_RANGES)
def test_complete_drop_feed_rejects_nonunicast_or_mixed_scope_ranges(cidr):
    source = 'drop-v6' if ':' in cidr else 'drop-v4'
    body = (json.dumps(dict(cidr=cidr, sblid='SBL1'))+'\n'
            +json.dumps(dict(type='metadata', timestamp=int(NOW.timestamp()), records=1))+'\n').encode()
    with pytest.raises(ValueError, match='Nonpublic'):
        parse_feed(source, body, NOW)


@pytest.mark.parametrize('cidr', UNSAFE_RANGES)
def test_preexisting_unsafe_cache_is_refused_before_matching(cidr, monkeypatch):
    manager = HostSecurity(now=lambda: NOW)
    feeds = [parse_feed(source, source_body(source), NOW) for source in SOURCES]
    source = 'drop-v6' if ':' in cidr else 'drop-v4'
    next(row for row in feeds if row['source'] == source)['entries'] = [[cidr, 'SBL1']]
    cache = dict(schema=CACHE_SCHEMA, feeds=feeds)
    monkeypatch.setattr(manager, '_json', lambda name, *args: cache if name == 'feeds.json' else None)
    with pytest.raises(ValueError, match='cached address'):
        manager.matches(['8.8.8.8', '2606:4700:4700::1111'])
    assert manager.snapshot()['feed_state'] == 'unavailable'


@pytest.mark.parametrize('address', ['224.0.0.1', '255.255.255.255', 'ff02::1',
    '::ffff:8.8.8.8', '2606:4700::1%eth0'])
def test_ipsum_rejects_nonunicast_or_ambiguous_addresses(address):
    body = ('# Last update: '+NOW.strftime('%a, %d %b %Y %H:%M:%S +0000')
            +'\n'+address+' 4\n').encode()
    with pytest.raises(ValueError, match='Invalid IPsum'):
        parse_feed('ipsum', body, NOW)


@pytest.mark.parametrize('source', SOURCES)
def test_public_reference_feed_still_admits_and_matches_without_io(source, monkeypatch):
    feeds = [parse_feed(key, source_body(key), NOW) for key in SOURCES]
    manager = HostSecurity(now=lambda: NOW, downloader=lambda *_: pytest.fail('Unexpected download'))
    monkeypatch.setattr(manager, '_json', lambda *_: dict(schema=CACHE_SCHEMA, feeds=feeds))
    rows = manager.matches(['8.8.8.8', '2606:4700:4700::1111', 'ff02::1'])
    assert any(row['source'] == source for row in rows)
    assert all(row['ip'] != 'ff02::1' and row['action_status'] == 'not_attempted' for row in rows)


@pytest.mark.parametrize('old_value', ['newly_excluded', 'invalid_schema', 'bad_json', 'overflow_date'])
def test_explicit_refresh_replaces_unusable_cache_without_archiving_it(monkeypatch, old_value):
    from contextlib import nullcontext
    from copy import deepcopy
    from megalodon import host_security as module
    feeds=[parse_feed(source,source_body(source),NOW) for source in SOURCES]
    previous=dict(schema=CACHE_SCHEMA,feeds=deepcopy(feeds))
    invalid=dict(schema=CACHE_SCHEMA,feeds=deepcopy(feeds))
    invalid['feeds'][0]['entries']=[['8.0.0.0/5','SBL1']]
    if old_value=='overflow_date':
        invalid=deepcopy(previous)
        invalid['feeds'][0]['publisher_at']='9999-12-31T23:59:59Z'
    saved={'feeds.json':invalid if old_value=='newly_excluded' else {},'feeds.previous.json':previous}
    if old_value=='overflow_date':saved['feeds.json']=invalid
    manager=HostSecurity(now=lambda:NOW,downloader=source_body)
    def load(name,*args):
        if name=='feeds.json' and old_value=='bad_json' and saved.get(name)=={}:
            raise json.JSONDecodeError('Invalid old JSON','{',0)
        return deepcopy(saved.get(name))
    monkeypatch.setattr(manager,'locked',nullcontext)
    monkeypatch.setattr(manager,'_json',load)
    monkeypatch.setattr(manager,'_save',lambda name,value:saved.update({name:deepcopy(value)}))
    monkeypatch.setattr(module,'write',lambda *_:None)  # In-memory refresh transaction; no filesystem bypass claim.
    assert 'refreshed' in manager.execute('refresh')
    assert saved['feeds.previous.json']==previous
    assert manager._cache()==dict(schema=CACHE_SCHEMA,feeds=feeds)
    assert manager.matches(['8.8.8.8'])


def test_refresh_does_not_ignore_old_cache_io_failure(monkeypatch):
    from contextlib import nullcontext
    from megalodon import host_security as module
    manager=HostSecurity(now=lambda:NOW,downloader=source_body)
    saved=[]
    def load(name,*args):
        if name=='feeds.json':raise PermissionError('Unsafe or inaccessible file')
        return None
    monkeypatch.setattr(manager,'locked',nullcontext)
    monkeypatch.setattr(manager,'_json',load)
    monkeypatch.setattr(manager,'_save',lambda name,value:saved.append(name))
    monkeypatch.setattr(module,'write',lambda *_:None)
    with pytest.raises(PermissionError):manager.execute('refresh')
    assert saved==['refresh.json']


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


@pytest.mark.parametrize('code, ending, warning, accepted', [
    (0, b'finish=true\n', True, True),
    (78, b'finish=true\n', True, True),
    (78, b'', True, False),
    (78, b'finish=false\n', True, False),
    (78, b'finish=true\nfinish=true\n', True, False),
    (78, b'finish=true\n', False, False),
    (1, b'finish=true\n', True, False),
    (64, b'finish=true\n', True, False),
    (-9, b'finish=true\n', True, False),
])
def test_lynis_warning_exit_requires_completed_valid_warning_evidence(
        tmp_path, monkeypatch, code, ending, warning, accepted):
    """Exercise the execution adapter with synthetic files, never native Lynis."""
    from contextlib import nullcontext
    from copy import deepcopy
    from types import SimpleNamespace
    from megalodon import host_security as module
    from megalodon.host_findings import validate_summary

    audit = HostSecurity(now=lambda: NOW)
    audit.root = tmp_path
    monkeypatch.setattr(audit, 'locked', nullcontext)
    real_file, real_stat = Path.is_file, Path.stat
    monkeypatch.setattr(Path, 'is_file', lambda p: True if str(p) == '/usr/sbin/lynis' else real_file(p))
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **k:
                        SimpleNamespace(st_uid=0, st_mode=0o100755)
                        if str(p) == '/usr/sbin/lynis' else real_stat(p, *a, **k))
    report = b'report_version_major=1\nreport_version_minor=0\nlynis_version=3.1.6\n'
    if warning:
        report += b'warning[]=AUTH-0001|Review this synthetic setting|-|-\n'
    report += ending
    saved = {'audit.json': {'previous': 'summary'}, 'lynis-report.dat': b'previous report'}
    before = deepcopy(saved)
    writes = []
    def write(path, body):
        writes.append(path.name)
        saved[path.name] = deepcopy(body)
    monkeypatch.setattr(module, 'write', write)
    monkeypatch.setattr(audit, '_save', lambda name, body: write(tmp_path / name, body))
    def run(argv, work):
        assert argv[:3] == ['/usr/sbin/lynis', 'audit', 'system']
        assert '--no-plugins' in argv and '--upload' not in argv
        (work / 'lynis.dat').write_bytes(report)
        return b'private output must not appear in the result', code
    audit.runner = run
    if accepted:
        message = audit.execute('audit')
        assert writes == ['lynis-report.dat', 'audit.json']
        assert saved['lynis-report.dat'] == report
        summary = saved['audit.json']
        validate_summary('audit', summary, NOW)
        assert summary['metrics'] == {'warnings': 1, 'suggestions': 0}
        assert summary['review']['report_sha256'] == hashlib.sha256(report).hexdigest()
        assert ('exit 78' in message) == (code == 78)
        assert 'private output' not in message
    else:
        with pytest.raises(ValueError, match='prior audit summary is retained'):
            audit.execute('audit')
        assert writes == [] and saved == before


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
