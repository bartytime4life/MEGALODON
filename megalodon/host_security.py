"""Local host audits and dated threat context. No blocking, attribution or uploads."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import http.client
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import sys
import time

SCHEMA = 'megalodon-host-security-v1'
CACHE_SCHEMA = 'megalodon-threat-cache-v1'
ACTIONS = ('audit', 'baseline', 'check', 'refresh')
MAX_FILE = 12 * 1024 * 1024
MAX_FEED = 8 * 1024 * 1024
MAX_INDICATORS = 200_000
MAX_AGE = timedelta(hours=48)
SOURCES = {
    'drop-v4': ('www.spamhaus.org', '/drop/drop_v4.json'),
    'drop-v6': ('www.spamhaus.org', '/drop/drop_v6.json'),
    'ipsum': ('raw.githubusercontent.com', '/stamparm/ipsum/master/ipsum.txt'),
}
TERMS = {'drop-v4': 'https://www.spamhaus.org/blocklists/drop-fair-use-policy/',
         'drop-v6': 'https://www.spamhaus.org/blocklists/drop-fair-use-policy/',
         'ipsum': 'https://github.com/stamparm/ipsum/blob/master/LICENSE'}
AIDE_SCOPE = ('/usr/bin', '/usr/sbin', '/etc/ssh', '/etc/systemd/system')
# Conservative reference admission, not a routing/reachability assertion.
# Reject entire ranges overlapping special space, including interior addresses
# that ipaddress's endpoint-based network properties do not inspect.
_NONPUBLIC_V4 = tuple(ip_network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24',
    '192.168.0.0/16', '192.175.48.0/24', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'))
_UNICAST_V6 = ip_network('2000::/3')
_SPECIAL_V6 = tuple(ip_network(value) for value in (
    '2001::/23', '2001:db8::/32', '2002::/16', '3ffe::/16', '3fff::/20'))


def public_unicast(value):
    """Admit ordinary public unicast only, identically on ingest and reload."""
    if '%' in str(value):
        return False
    network = ip_network(str(value), strict=True)
    if not network.is_global:
        return False
    if network.version == 4:
        return not any(network.overlaps(special) for special in _NONPUBLIC_V4)
    return (network.subnet_of(_UNICAST_V6)
            and not any(network.overlaps(special) for special in _SPECIAL_V6))


def clock():
    return datetime.now(timezone.utc)


def stamp(value):
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def date(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ValueError('Invalid source time.')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError('Duplicate field.')
        result[key] = value
    return result


def read(path, maximum=MAX_FILE):
    from .local_install import _regular_owned_file, _validate_directory_chain
    _validate_directory_chain(path.parent)
    value = _regular_owned_file(path, maximum=maximum)
    if path.stat().st_mode & 0o077:
        raise ValueError('Host security files must be private.')
    return value


def write(path, value):
    from .local_install import _atomic_write, _owned_directory
    _owned_directory(path.parent, private=True)
    if os.path.lexists(path):
        read(path)
    if len(value) > MAX_FILE:
        raise ValueError('Host security file exceeds its bound.')
    _atomic_write(path, value, 0o600)


def fetch(source):
    """Fixed public HTTPS GET only; no redirects, proxies, credentials or local data."""
    host, target = SOURCES[source]
    connection = http.client.HTTPSConnection(host, timeout=10)
    deadline = time.monotonic() + 30
    try:
        connection.request('GET', target, headers={'User-Agent': 'MEGALODON-local-context/1', 'Accept-Encoding': 'identity'})
        response = connection.getresponse()
        if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity':
            raise ValueError('Threat publisher response unavailable.')
        declared = response.getheader('Content-Length')
        if declared is not None and (not re.fullmatch(r'[0-9]{1,9}', declared) or not 0 < int(declared) <= MAX_FEED):
            raise ValueError('Invalid or excessive threat download length.')
        body = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise ValueError('Threat download deadline exceeded.')
            part = response.read1(65536)
            if not part:
                if declared is not None and len(body) != int(declared):
                    raise ValueError('Threat download was incomplete.')
                return bytes(body)
            body.extend(part)
            if len(body) > MAX_FEED:
                raise ValueError('Threat feed exceeded download bound.')
    except (OSError, http.client.HTTPException):
        raise ValueError('Threat publisher download could not complete.') from None
    finally:
        connection.close()


def parse_feed(source, raw, now):
    if source not in SOURCES or not 0 < len(raw) <= MAX_FEED:
        raise ValueError('Invalid threat source or size.')
    lines = raw.decode('utf-8').splitlines()
    if len(lines) > MAX_INDICATORS + 100 or any(len(line) > 4096 for line in lines):
        raise ValueError('Threat feed line bound exceeded.')
    entries = []
    if source.startswith('drop-'):
        metadata = None
        for line in lines:
            row = json.loads(line, object_pairs_hook=pairs)
            if type(row) is not dict:
                raise ValueError('Invalid DROP record.')
            if row.get('type') == 'metadata':
                if metadata is not None:
                    raise ValueError('Duplicate DROP metadata.')
                metadata = row
                continue
            network = ip_network(row['cidr'], strict=True)
            if network.version != (4 if source == 'drop-v4' else 6) or not public_unicast(network):
                raise ValueError('Nonpublic or wrong-family DROP range.')
            if not re.fullmatch(r'SBL\d{1,12}', row['sblid']):
                raise ValueError('Invalid DROP reference.')
            entries.append([str(network), row['sblid']])
        if (metadata is None or type(metadata.get('timestamp')) is not int
                or metadata.get('records') != len(entries)):
            raise ValueError('DROP metadata/count missing or inconsistent.')
        # A publisher may associate the same range with several SBL records.
        # Preserve every reference while indexing each network only once.
        grouped = {}
        for network, reference in entries:
            grouped.setdefault(network, set()).add(reference)
        if any(len(references) > 8 for references in grouped.values()):
            raise ValueError('Excessive DROP references for one network.')
        entries = [[network, ', '.join(sorted(references))] for network, references in grouped.items()]
        generated = datetime.fromtimestamp(metadata['timestamp'], timezone.utc)
    else:
        generated = None
        for line in lines:
            if line.startswith('# Last update: '):
                if generated is not None:
                    raise ValueError('Duplicate IPsum date.')
                generated = parsedate_to_datetime(line.removeprefix('# Last update: '))
            elif line and not line.startswith('#'):
                address, score = line.split()
                address = ip_address(address)
                if not public_unicast(address) or not score.isdecimal() or not 1 <= int(score) <= 1000:
                    raise ValueError('Invalid IPsum record.')
                # Count is source-list occurrence, never an independent confidence score.
                if int(score) >= 3:
                    entries.append([str(address), int(score)])
    if generated is None or generated.tzinfo is None or not -300 <= (now-generated).total_seconds() <= MAX_AGE.total_seconds():
        raise ValueError('Publisher date is missing, future-dated or stale.')
    if not entries or len(entries) > MAX_INDICATORS or len({row[0] for row in entries}) != len(entries):
        raise ValueError('Threat indicator count is empty, excessive or duplicated.')
    host, target = SOURCES[source]
    return dict(source=source, url='https://' + host + target, terms=TERMS[source],
                publisher_at=stamp(generated), retrieved_at=stamp(now),
                expires_at=stamp(generated+MAX_AGE), sha256=hashlib.sha256(raw).hexdigest(),
                bytes=len(raw), entries=entries)


def run_tool(argv, workspace, timeout=300):
    """Bound process group, elapsed time, stdout and files created in private scratch."""
    process = subprocess.Popen(argv, cwd=workspace, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})
    output = bytearray()
    deadline = time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise ValueError('Host audit exceeded its five-minute deadline.')
                for path in workspace.iterdir():
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                        raise ValueError('Host audit scratch output exceeded its bound.')
                for key, _ in selector.select(.2):
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > 2*1024*1024:
                            raise ValueError('Host audit output exceeded its bound.')
        return bytes(output), process.wait()
    finally:
        # Reap the tool and terminate remaining descendants even after parent exit.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        process.stdout.close()


class HostSecurity:
    def __init__(self, home=None, *, downloader=fetch, runner=run_tool, now=clock):
        self.root = Path(home or Path.home()) / '.local/share/megalodon/support/host-security'
        self.downloader, self.runner, self.now = downloader, runner, now

    @contextmanager
    def locked(self):
        from .local_install import _owned_directory
        if fcntl is None:
            raise ValueError('Host security execution currently supports Linux only.')
        _owned_directory(self.root, private=True)
        path = self.root/'lock'
        fd = os.open(path, os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_nlink != 1:
                raise ValueError('Unsafe host security lock.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another host security command is running.') from None
            yield
        finally:
            os.close(fd)

    def _json(self, name, maximum=MAX_FILE):
        if not os.path.lexists(self.root/name):
            return None
        try:
            return json.loads(read(self.root/name, maximum), object_pairs_hook=pairs)
        except FileNotFoundError:
            return None

    def _save(self, name, value):
        write(self.root/name, json.dumps(value, sort_keys=True, separators=(',', ':')).encode())

    def _cache(self):
        value = self._json('feeds.json')
        if value is None:
            return None
        if type(value) is not dict or set(value) != {'schema', 'feeds'} or value['schema'] != CACHE_SCHEMA or type(value['feeds']) is not list or len(value['feeds']) != 3:
            raise ValueError('Invalid threat cache.')
        if {row['source'] for row in value['feeds']} != set(SOURCES):
            raise ValueError('Invalid threat source set.')
        for row in value['feeds']:
            source = row['source']
            if set(row) != {'source','url','terms','publisher_at','retrieved_at','expires_at','sha256','bytes','entries'}:
                raise ValueError('Invalid cached threat fields.')
            if (row['url'] != 'https://' + SOURCES[source][0] + SOURCES[source][1] or row['terms'] != TERMS[source]
                    or not re.fullmatch(r'[a-f0-9]{64}', row['sha256']) or type(row['bytes']) is not int or not 0 < row['bytes'] <= MAX_FEED
                    or date(row['expires_at']) != date(row['publisher_at']) + MAX_AGE
                    or date(row['retrieved_at']) < date(row['publisher_at']) - timedelta(minutes=5)
                    or date(row['publisher_at']) > self.now()+timedelta(minutes=5)
                    or type(row['entries']) is not list or not 0 < len(row['entries']) <= MAX_INDICATORS):
                raise ValueError('Invalid cached threat provenance.')
            seen = set()
            for entry in row['entries']:
                if type(entry) is not list or len(entry) != 2 or type(entry[0]) is not str or entry[0] in seen:
                    raise ValueError('Invalid cached indicator.')
                seen.add(entry[0])
                address = ip_network(entry[0], strict=True) if source.startswith('drop-') else ip_address(entry[0])
                if not public_unicast(address) or str(address) != entry[0]:
                    raise ValueError('Invalid cached address.')
                if source.startswith('drop-'):
                    if address.version != (4 if source == 'drop-v4' else 6) or type(entry[1]) is not str or not re.fullmatch(r'SBL\d{1,12}(?:, SBL\d{1,12}){0,7}',entry[1]):
                        raise ValueError('Invalid cached range reference.')
                elif type(entry[1]) is not int or not 3 <= entry[1] <= 1000:
                    raise ValueError('Invalid cached occurrence count.')
        return value

    def _baseline(self):
        value = self._json('baseline.json', 4096)
        if value is not None:
            if (type(value) is not dict or set(value) != {'created_at','scope','sha256','trust'}
                    or value['scope'] != list(AIDE_SCOPE) or value['trust'] != 'observed_not_known_clean'
                    or type(value['sha256']) is not str or not re.fullmatch(r'[a-f0-9]{64}', value['sha256'])
                    or date(value['created_at']) > self.now()+timedelta(minutes=5)):
                raise ValueError('Invalid AIDE baseline identity.')
        return value

    def snapshot(self):
        result = dict(schema=SCHEMA, audit=None, integrity=None, feeds=[], feed_state='unavailable',
                      baseline_present=False, message='Run a host audit or refresh threat context.', action_authority='none')
        try:
            for name in ('audit', 'integrity'):
                value = self._json(name+'.json', 32768)
                # Display only fields produced by our fixed summaries, never raw tool text.
                if value is not None:
                    if type(value) is not dict or set(value) != {'checked_at','message','metrics'} or type(value['metrics']) is not dict or any(type(v) is not int or v < 0 for v in value['metrics'].values()):
                        raise ValueError('Invalid host summary.')
                    date(value['checked_at'])
                    if type(value['message']) is not str or len(value['message']) > 512 or not value['message'].isprintable():
                        raise ValueError('Invalid host summary text.')
                    result[name] = value
            result['baseline_present'] = self._baseline() is not None
            cache = self._cache()
            if cache:
                for row in cache['feeds']:
                    result['feeds'].append({k:v for k,v in row.items() if k != 'entries'} | {'indicators':len(row['entries'])})
                result['feed_state'] = 'ready' if all(date(r['expires_at']) >= self.now() for r in cache['feeds']) else 'stale'
                result['message'] = 'Dated reference context only. A match is not proof of compromise or actor identity.'
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            result['feed_state'] = 'unavailable'
            result['message'] = 'Saved host security state could not be validated; review is required.'
        return result

    def matches(self, addresses):
        if type(addresses) is not list or len(addresses) > 256:
            raise ValueError('Match at most 256 observed IPs.')
        canonical = []
        for value in addresses:
            address = ip_address(value)
            if public_unicast(address):
                canonical.append(address)
        cache = self._cache()
        matches = []
        if cache:
            for row in cache['feeds']:
                if date(row['expires_at']) < self.now():
                    continue
                if row['source'] == 'ipsum':
                    index = dict(row['entries'])
                    selected = [(a, str(a), index[str(a)]) for a in canonical if str(a) in index]
                else:
                    # Prefix index avoids an address x range scan for every HUD refresh.
                    index = {}
                    for value, reference in row['entries']:
                        network = ip_network(value)
                        index.setdefault(network.prefixlen, {})[int(network.network_address)] = (value, reference)
                    selected = []
                    bits = 32 if row['source'] == 'drop-v4' else 128
                    for a in canonical:
                        if a.max_prefixlen != bits:
                            continue
                        for prefix, networks in index.items():
                            key = int(a) >> (bits-prefix) << (bits-prefix)
                            if key in networks:
                                selected.append((a, *networks[key]))
                for a, value, reference in selected:
                    matches.append(dict(ip=str(a), source=row['source'], indicator=value, reference=reference,
                                        publisher_at=row['publisher_at'], expires_at=row['expires_at'], sha256=row['sha256'],
                                        status='context_match', action_status='not_attempted'))
        return matches[:768]

    def execute(self, action):
        if sys.platform != 'linux':
            raise ValueError('Host security execution currently supports Linux only.')
        if action not in ACTIONS:
            raise ValueError('Choose a fixed host security action.')
        with self.locked():
            if action == 'refresh':
                attempt = self._json('refresh.json', 4096)
                if attempt and self.now() - date(attempt['attempted_at']) < timedelta(days=1):
                    raise ValueError('Threat refresh is limited to once per day, including failed attempts; the last valid cache is retained.')
                self._save('refresh.json', dict(attempted_at=stamp(self.now())))
                feeds = []
                for source in SOURCES:
                    raw = self.downloader(source)
                    write(self.root/(source+'.download'), raw)
                    try:
                        feeds.append(parse_feed(source, raw, self.now()))
                    except (ValueError, KeyError, TypeError) as exc:
                        raise ValueError(source+': '+str(exc)[:160]) from None
                value = dict(schema=CACHE_SCHEMA, feeds=feeds)
                try:
                    old = self._cache()
                except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
                    # Only a validated old cache is an archival candidate.
                    # A completed explicit refresh can replace obsolete data;
                    # private-file/ownership admission still runs in write().
                    old = None
                if old:
                    self._save('feeds.previous.json', old)
                self._save('feeds.json', value)
                return 'Threat reference cache refreshed. Matching remains local; no block was applied.'
            if action == 'baseline' and os.path.lexists(self.root/'baseline.json'):
                raise ValueError('An AIDE baseline already exists. Checks never replace the comparison baseline.')
            tool = 'lynis' if action == 'audit' else 'aide'
            binary = next((Path(p) for p in ('/usr/sbin/'+tool, '/usr/bin/'+tool) if Path(p).is_file()), None)
            if binary is None or binary.is_symlink() or binary.stat().st_uid != 0 or binary.stat().st_mode & 0o022:
                raise ValueError('Install the root-owned Ubuntu '+tool+' package first.')
            with tempfile.TemporaryDirectory(prefix='run-', dir=self.root) as directory:
                work = Path(directory)
                if action == 'audit':
                    argv = [str(binary), 'audit', 'system', '--quick', '--no-colors', '--no-plugins',
                            '--log-file', str(work/'lynis.log'), '--report-file', str(work/'lynis.dat')]
                    raw, code = self.runner(argv, work)
                    if code:
                        raise ValueError('Lynis did not complete; prior audit summary is retained.')
                    from .companion_automation import _read_bounded
                    report = _read_bounded(work/'lynis.dat', MAX_FILE)
                    if not 0 < len(report) <= MAX_FILE:
                        raise ValueError('Lynis report exceeded its bound.')
                    metrics = {'warnings':0, 'suggestions':0}
                    for line in report.decode('utf-8').splitlines():
                        if line.startswith('warning[]='): metrics['warnings'] += 1
                        if line.startswith('suggestion[]='): metrics['suggestions'] += 1
                    message = 'Unprivileged host audit completed; unreadable/root-only checks are outside coverage. Suggestions are not confirmed threats.'
                    self._save('audit.json', dict(checked_at=stamp(self.now()), message=message, metrics=metrics))
                    write(self.root/'lynis-report.dat', report)
                    return message
                database = self.root/'aide.db.gz'
                rules = '\n'.join(path + r'(/.*)?$ MEGALODON' for path in AIDE_SCOPE)
                config = ('database_in=file:'+str(database)+'\ndatabase_out=file:'+str(work/'new.db.gz')+
                          '\ngzip_dbout=yes\nreport_url=stdout\nreport_level=summary\nnum_workers=2\n'
                          'MEGALODON = p+u+g+s+m+sha256\n'+rules+'\n')
                if action == 'check':
                    baseline = self._baseline()
                    if baseline is None or hashlib.sha256(read(database)).hexdigest() != baseline['sha256'] or baseline['scope'] != list(AIDE_SCOPE):
                        raise ValueError('AIDE baseline is missing or its integrity check failed.')
                config_path = work/'aide.conf'
                config_path.write_text(config)
                raw, code = self.runner([str(binary), '--init' if action == 'baseline' else '--check', '--config='+str(config_path)], work)
                if code not in ((0,) if action == 'baseline' else tuple(range(8))):
                    raise ValueError('AIDE did not complete; the prior baseline and result are retained.')
                if action == 'baseline':
                    from .companion_automation import _read_bounded
                    body = _read_bounded(work/'new.db.gz', MAX_FILE)
                    if os.path.lexists(database):
                        raise ValueError('AIDE database already exists; preserve it before creating a new baseline.')
                    write(database, body)
                    self._save('baseline.json', dict(created_at=stamp(self.now()), scope=list(AIDE_SCOPE), sha256=hashlib.sha256(body).hexdigest(), trust='observed_not_known_clean'))
                metrics = dict(added_detected=int(bool(code&1)), removed_detected=int(bool(code&2)), changed_detected=int(bool(code&4)))
                message = ('Initial AIDE comparison baseline recorded; this does not certify a clean system.' if action == 'baseline' else
                           'AIDE found file changes; review the private report before accepting any new baseline.' if code else
                           'AIDE found no differences in its readable fixed scope; this does not prove the system is safe.')
                write(self.root/'aide-report.txt', raw)
                self._save('integrity.json', dict(checked_at=stamp(self.now()), message=message, metrics=metrics))
                return message


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('status', 'match', *ACTIONS))
    parser.add_argument('--ip', action='append', default=[], help='At most 256 literal observed IPs; matched locally, never transmitted')
    args = parser.parse_args(argv)
    if args.ip and args.action != 'match':
        parser.error('--ip is only available with match')
    manager = HostSecurity()
    try:
        value = manager.matches(args.ip) if args.action == 'match' else manager.snapshot() if args.action == 'status' else dict(message=manager.execute(args.action))
        print(json.dumps(value, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        print('Host security unavailable: '+str(exc)[:512])
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
