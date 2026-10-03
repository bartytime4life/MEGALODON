"""Bounded CLI sensor summaries. Separate from admitted packet/alert evidence."""
from collections import Counter
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sqlite3
import subprocess
import tempfile
from uuid import uuid4
from threading import Event, Lock, Thread

from .companion_automation import _run_fixed
from .managed_capture import now

MAX_LOG = 2 * 1024 * 1024
EVE_WINDOW = 256 * 1024
ZEEK_SCRIPT = '''event zeek_init() &priority=-100 {
  local streams = Log::active_streams;
  for (id in streams) if (id != Conn::LOG) Log::disable_stream(id);
}
'''


def zeek_binary(home):
    """Resolve the fixed Zeek name through the same locations as Setup."""
    from .tool_heartbeat import PROBES, _candidate_paths, _executable_ctime, _path_directories
    from .tool_locations import load_directories, trusted_executable
    try:
        configured = load_directories(Path(home))
    except ValueError:
        return None
    if 'zeek' in configured:
        return str(Path(configured['zeek']) / 'zeek') if trusted_executable(configured['zeek'], 'zeek') else None
    for candidate in _candidate_paths(PROBES['zeek'], _path_directories(), Path(home)):
        if _executable_ctime(candidate)[0] == 'yes':
            return candidate
    return None


def metric(label, value, unit=''):
    return dict(label=label, value=value, unit=unit)


def summarize_zeek(raw):
    if len(raw) > MAX_LOG:
        raise ValueError('Zeek log bound exceeded')
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if len(rows) > 4000 or any(type(r) is not dict or type(r.get('ts')) not in (float,int) for r in rows):
        raise ValueError('Invalid Zeek summary input')
    protocols = Counter(r.get('proto') for r in rows)
    two_way = sum(type(r.get('orig_pkts')) is int and type(r.get('resp_pkts')) is int
                  and r['orig_pkts'] > 0 and r['resp_pkts'] > 0 for r in rows)
    return [metric('Connections in sample',len(rows)), metric('Two-way connections',two_way),
            metric('TCP',protocols['tcp']), metric('UDP',protocols['udp'])]


def read_eve(path=Path('/var/log/suricata/eve.json')):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Expected regular EVE log')
        start = max(0, info.st_size-EVE_WINDOW)
        os.lseek(fd,start,os.SEEK_SET)
        raw = os.read(fd,EVE_WINDOW)
    finally:
        os.close(fd)
    if start:
        raw = raw.partition(b'\n')[2]
    raw = raw.rpartition(b'\n')[0]  # omit an in-progress trailing record
    kinds, timestamps = Counter(), []
    for line in raw.splitlines()[-1000:]:
        try:
            row = json.loads(line)
            stamp = datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
            if stamp.tzinfo is None or not -5 <= (datetime.now(timezone.utc)-stamp).total_seconds() <= 120:
                continue
            kind = row.get('event_type')
            if kind in {'alert','flow','dns','http','tls','stats','anomaly','ssh','quic'}:
                kinds[kind] += 1
                timestamps.append(stamp)
        except (ValueError,KeyError,TypeError,AttributeError):
            continue
    return (max(timestamps).astimezone(timezone.utc).isoformat().replace('+00:00','Z') if timestamps else None,
            [metric('Recent log records',sum(kinds.values())),metric('Alert records',kinds['alert']),
             metric('Flow records',kinds['flow']),metric('DNS records',kinds['dns']),
             metric('TLS records',kinds['tls']),metric('HTTP records',kinds['http'])])


class SupportSensors:
    def __init__(self, home):
        self.home = Path(home)
        self.root = self.home/'.local/share/megalodon/support/sensor-samples'
        self._lock, self._stop = Lock(), Event()
        self._threads = []
        self._decoder = None
        self.flow_ingestor = None
        self.evidence = None
        self._data = {key:dict(state='stopped',message='Background sensor summaries are stopped.',updated_at=None,metrics=[])
                      for key in ('zeek','suricata')}

    def snapshot(self):
        with self._lock:
            return deepcopy(self._data)

    def _publish(self,key,**value):
        with self._lock:
            self._data[key].update(value)

    def start(self,interface):
        if any(t.is_alive() for t in self._threads):
            return
        from .support_config import valid_interface
        valid_interface(interface)
        from .local_install import _owned_directory
        _owned_directory(self.root,private=True)
        self._stop.clear()
        self._threads = [Thread(target=self._zeek,args=(interface,),daemon=True,name='megalodon-zeek-sampler'),
                         Thread(target=self._suricata,daemon=True,name='megalodon-suricata-summary')]
        for thread in self._threads:
            thread.start()

    def _zeek(self,interface):
        binary = zeek_binary(self.home)
        if not binary:
            self._publish('zeek',state='needs_setup',message='Zeek is unavailable in the selected directory, PATH or known install locations.')
            return
        while not self._stop.is_set():
            self._publish('zeek',state='collecting',message='Sampling up to 10 seconds / 2,000 frames; flow counts stay separate from packet totals.')
            try:
                sample_started=now();sample_id=uuid4().hex
                raw,code = _run_fixed(['/usr/bin/dumpcap','-i',interface,'-p','-s','256','-q','-P','-w','-',
                                       '-a','duration:10','-c','2000'],2*1024*1024,15,self._stop)
                if self._stop.is_set():
                    break
                if code or len(raw)<24:
                    raise ValueError('Capture unavailable')
                reservation=self.evidence.working_reservation(4*1024**2) if self.evidence is not None and self.evidence.enabled else nullcontext()
                with reservation, tempfile.TemporaryDirectory(prefix='zeek-',dir=self.root) as directory:
                    env = {'PATH':'/usr/bin:/bin','HOME':directory,'LC_ALL':'C'}
                    # Raw frames remain in bounded memory and anonymous pipes.
                    process = subprocess.Popen([binary,'-r','-','LogAscii::use_json=T','-e',ZEEK_SCRIPT],
                        stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,cwd=directory,env=env)
                    with self._lock:
                        self._decoder = process
                    try:
                        if self._stop.is_set():
                            process.terminate()
                        process.communicate(input=raw,timeout=20)
                        if process.returncode:
                            raise ValueError('Zeek failed')
                        path = Path(directory)/'conn.log'
                        if path.exists():
                            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                            with os.fdopen(fd,'rb') as stream:
                                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):raise ValueError('Expected regular Zeek sample')
                                flow_rows=stream.read(MAX_LOG+1)
                        else:
                            flow_rows=b''
                        result=summarize_zeek(flow_rows)
                        if self.flow_ingestor is not None and not self._stop.is_set():
                            self.flow_ingestor.ingest_zeek_sample(flow_rows,sample_id=sample_id,interface=interface,
                                started_at=sample_started,finished_at=now())
                        if self.evidence is not None and self.evidence.enabled and not self._stop.is_set():
                            self.evidence.append_records('sensor_logs',[dict(observed_at=now(),source='zeek-sample',
                                data=dict(metrics=result,coverage=dict(kind='bounded_sample',continuous=False,interface=interface,
                                    started_at=sample_started,finished_at=now(),max_frames=2000,snapshot_bytes=256,nominal_interval_seconds=60)))])
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.wait()
                        with self._lock:
                            self._decoder = None
                self._publish('zeek',state='connected',message='Latest bounded Zeek sample; 256-byte snapshots and sampling gaps limit protocol coverage. No raw capture saved.',updated_at=now(),metrics=result)
            except (OSError,ValueError,sqlite3.Error,subprocess.SubprocessError):
                self._publish('zeek',state='error',message='Zeek sampling stopped: check capture access, executable and private workspace. Retry background tools.',metrics=[])
                return
            if self._stop.wait(50):
                break

    def _suricata(self):
        while not self._stop.is_set():
            try:
                stamp,metrics = read_eve()
                self._publish('suricata',state='connected' if stamp else 'stopped',updated_at=stamp,metrics=metrics if stamp else [],
                    message='Recent EVE tail (up to 256 KiB / 1,000 records / 2 minutes); counts overlap between reads and are separate from admitted findings.' if stamp else 'No recent EVE records in the bounded log tail. Configure the passive sensor or check its service.')
            except (OSError,ValueError):
                self._publish('suricata',state='needs_setup',message='Configure Suricata for the selected interface and grant read access to its EVE log.',metrics=[])
            self._stop.wait(5)

    def stop(self):
        self._stop.set()
        with self._lock:
            process = self._decoder
            if process and process.poll() is None:
                process.terminate()
        for thread in self._threads:
            thread.join(5)
        for key in self._data:
            self._publish(key,state='stopped',message='Sensor summary collection stopped; the system Suricata service is managed separately.')
