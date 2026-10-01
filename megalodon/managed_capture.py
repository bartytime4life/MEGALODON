"""Owned, finite dumpcap -> TShark metadata sessions for the local HUD.

Raw frames cross anonymous pipes only. The existing strict fields parser and
JSONL validator feed the existing store and detectors; no new evidence schema.
"""
from __future__ import annotations
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
from threading import Event, Lock, Thread
import time

from .capture import _jsonl_event
from .config import BlockingSettings
from .offline.tshark import FIELDS, parse_fields
from .storage import Store, StorageCapacityError
from .buffered_recording import BufferedRecording
from .validation import ValidationError

MAX_PACKETS = 50000
MAX_SECONDS = 900


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def capture_commands(interface):
    capture = ['/usr/bin/dumpcap', '-i', interface, '-p', '-s', '256', '-q',
               '-a', f'duration:{MAX_SECONDS}', '-c', str(MAX_PACKETS), '-P', '-w', '-']
    decode = ['/usr/bin/tshark', '-n', '-l', '-r', '-', '-T', 'fields',
              '-E', 'header=n', '-E', 'separator=/t', '-E', 'quote=n',
              '-E', 'occurrence=a', '-E', 'aggregator=,']
    for field in FIELDS:
        decode.extend(['-e', field])
    return capture, decode


class ManagedCapture:
    def __init__(self, settings, home, on_ready=None, *, popen=subprocess.Popen, connections=None):
        self.settings, self.home, self.on_ready, self.popen = settings, home, on_ready, popen
        self.connections = connections
        self.evidence = None
        self.flow_ingestor = None
        self._lock, self._stop = Lock(), Event()
        self._thread = None
        self._state = dict(state='idle', interface='', received=0, accepted=0, skipped=0,
                           timestamp_rejected=0,started_at=None, finished_at=None, message='No HUD capture started.')

    def snapshot(self):
        with self._lock:
            return dict(self._state)

    def start(self, interface):
        from .support_config import valid_interface, ConfigBusy
        valid_interface(interface)
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise ConfigBusy('A HUD capture is already running.')
            self._stop.clear()
            self._state.update(state='starting', interface=interface, received=0, accepted=0, skipped=0,timestamp_rejected=0,
                               started_at=now(), finished_at=None, message='Opening the selected interface…')
            self._thread = Thread(target=self._run, args=(interface,), daemon=True, name='megalodon-managed-capture')
            self._thread.start()

    def stop(self):
        self._stop.set()
        thread = self._thread
        if thread:
            thread.join(8)
            if thread.is_alive():
                raise ValueError('Capture shutdown has not completed; check status again.')

    def _run(self, interface):
        if self.evidence is not None and self.evidence.enabled and self.evidence.recording_mode=='connection_summaries':
            self._run_flows(interface)
            return
        processes = []
        run_id = None
        store = None
        service = None
        reason, failure = 'source_exhausted', None
        try:
            if self.connections is not None:
                self.connections.begin(interface)
            # A separate analyzer HOME prevents personal scripts/configuration
            # from changing this fixed parser. No raw capture path is created.
            env = {'PATH':'/usr/bin:/bin', 'HOME':str(self.home), 'LC_ALL':'C',
                   'XDG_CONFIG_HOME':str(self.home / 'config')}
            store = (self.evidence.packet_writer() if self.evidence is not None and self.evidence.enabled else
                     Store(self.settings.db_path, max_database_bytes=self.settings.storage.max_database_bytes))
            run_id = store.start_ingestion_run('jsonl')
            def recording_status(value):
                if self.evidence is not None:
                    with self.evidence.lock:self.evidence._recording = dict(value)
                with self._lock:
                    self._state.update(accepted=value['saved_records'],buffered=value['pending_records'],
                        buffered_bytes=value['pending_bytes'],oldest_pending_seconds=value['oldest_pending_seconds'],
                        write_failures=value['write_failures'],unconfirmed_records=value['unconfirmed_records'])
            service = BufferedRecording(replace(self.settings, blocking=BlockingSettings()), store,
                                        run_id=run_id,on_status=recording_status)
            if self.on_ready:
                self.on_ready()
            cap_argv, decode_argv = capture_commands(interface)
            cap = self.popen(cap_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            processes.append(cap)
            decoder = self.popen(decode_argv, stdin=cap.stdout, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=env, start_new_session=True)
            processes.append(decoder)
            cap.stdout.close()
            buffer = bytearray()
            deadline = time.monotonic() + MAX_SECONDS + 5
            with selectors.DefaultSelector() as selector:
                os.set_blocking(decoder.stdout.fileno(), False)
                selector.register(decoder.stdout, selectors.EVENT_READ)
                with self._lock:
                    self._state.update(state='running', message='Capture active; waiting for usable packet metadata. Drops are unknown.')
                while selector.get_map() and not self._stop.is_set():
                    service.flush_due()
                    if time.monotonic() > deadline:
                        raise ValueError('capture deadline')
                    for key, _ in selector.select(.2):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffer.extend(chunk)
                        while b'\n' in buffer:
                            row, _, buffer = buffer.partition(b'\n')
                            if self._state['received'] >= MAX_PACKETS:
                                raise ValueError('packet bound')
                            with self._lock:
                                self._state['received'] += 1
                            try:
                                event = parse_fields(row.decode('ascii'))
                                if event is not None:
                                    event = _jsonl_event(json.dumps(replace(event, interface=interface).to_dict()))
                            except (ValueError, UnicodeError):
                                event = None
                            if event is None:
                                with self._lock:
                                    self._state['skipped'] += 1
                                continue
                            try:
                                service.process(event, run_id=run_id)
                            except ValidationError as exc:
                                if str(exc) not in {'event timestamp precedes source high watermark','event timestamp exceeds allowed future skew'}:
                                    raise
                                # NIC queues can deliver timestamps out of order.
                                # Keep detector ordering strict; reject this row,
                                # account for the gap and continue finite intake.
                                with self._lock:
                                    self._state['skipped'] += 1
                                    self._state['timestamp_rejected'] += 1
                                continue
                            if self.connections is not None:
                                self.connections.observe(event)
                            with self._lock:
                                self._state['message'] = 'Observed metadata feeds the live view; ordinary records save in batches within two seconds. Findings save promptly. Capture drops are unknown.'
                        if len(buffer) > 1024:
                            raise ValueError('metadata row bound')
            if self._stop.is_set():
                reason = 'interrupted'
            elif buffer or decoder.wait(timeout=3) != 0 or cap.wait(timeout=3) != 0:
                raise ValueError('capture tool failed')
            elif self._state['received'] >= MAX_PACKETS:
                reason = 'event_limit_reached'
            service.flush()
        except StorageCapacityError as exc:
            reason, failure = 'failed', 'CAPTURE_ERROR'
            message = ('Packet storage limit reached. Existing records are preserved; increase the configured storage budget or review retention before restarting.'
                       if str(exc) == 'STORAGE_CAPACITY:HIGH_WATER' else
                       'Packet storage could not be validated. Existing records are preserved; review private storage access before restarting.')
            with self._lock:
                self._state.update(state='failed', message=message)
        except Exception:
            reason, failure = 'failed', 'CAPTURE_ERROR'
            with self._lock:
                self._state.update(state='failed', message='Capture could not continue. Check capture permissions, interface and private data-store access; accepted rows remain available.')
        finally:
            for process in reversed(processes):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            for process in reversed(processes):
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
                for stream in (process.stdout, process.stderr):
                    if stream and not stream.closed:
                        stream.close()
            if store:
                try:
                    if service is not None:service.flush()
                    if run_id is not None:
                        store.finish_ingestion_run(run_id, reason, failure_code=failure)
                except Exception:
                    with self._lock:
                        self._state.update(state='failed', message='Capture stopped but its receipt needs review before another ingestion run.')
                finally:
                    store.close()
            with self._lock:
                if self._state['state'] != 'failed':
                    self._state.update(state='stopped', message='HUD capture stopped. Stored metadata remains in the charts; start another session when needed.')
                self._state['finished_at'] = now()

    def _run_flows(self,interface):
        if self.connections is not None:self.connections.begin(interface)
        try:
            if self.flow_ingestor is None:raise ValueError('Flow source unavailable')
            self.flow_ingestor.start()
            while not self._stop.wait(1):
                status=self.flow_ingestor.snapshot()
                with self._lock:
                    self._state.update(state='running' if status['state']=='connected' else 'starting',
                        accepted=status['imported_flows'],received=status['accepted'],skipped=status['rejected'],
                        message=f'Connection summaries from {status["source"] or "local sensor"}. '+status['message'])
        except (OSError,ValueError):
            with self._lock:self._state.update(state='failed',message='Flow summary collection unavailable; check Sensors and Storage.')
        finally:
            with self._lock:
                if self._state['state']!='failed':self._state.update(state='stopped',message='Flow view stopped; retained summaries remain in Evidence.')
                self._state['finished_at']=now()
