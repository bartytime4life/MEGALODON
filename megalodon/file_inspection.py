"""One explicit local executable inspection, separate from core telemetry."""
from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
import secrets
from threading import Event, Lock, Thread
import time

from .file_inspection_contract import (MAX_INPUT, STATUS_SCHEMA, decode, fields,
    report, validate_identification, validate_structure)
from . import file_inspection_runtime as runtime
from . import file_inspection_sandbox as sandbox


class InspectionBusy(ValueError):
    pass


def normalize_lief(raw):
    value = decode(raw)
    if value == {'state': 'unsupported'} or value == {'state': 'failed'}:
        return value
    fields(value, ('state', 'structure'))
    if value['state'] != 'completed':
        raise ValueError('Unsupported structure result.')
    validate_structure(value['structure'])
    return value


def normalize_die(raw):
    """Discard filenames, offsets, free-form strings and all non-label output."""
    value = decode(raw)
    fields(value, ('detects',))
    if type(value['detects']) is not list or not 1 <= len(value['detects']) <= 16:
        raise ValueError('Invalid identification coverage.')
    result = []
    for detection in value['detects']:
        fields(detection, ('filetype', 'info', 'offset', 'parentfilepart', 'size', 'values'))
        if type(detection['values']) is not list or len(detection['values']) > 128:
            raise ValueError('Excessive identification records.')
        for item in detection['values']:
            fields(item, ('info', 'name', 'string', 'type', 'version'))
            if item['type'] in ('compiler', 'packer', 'protector', 'linker'):
                record = dict(kind=item['type'], name=item['name'])
                if record not in result:
                    result.append(record)
    return dict(state='completed', identification=validate_identification(result))


class FileInspection:
    def __init__(self, home=None, *, runner=sandbox.run, validator=runtime.validate):
        self.home = home
        self._runner, self._validator = runner, validator
        self._lock = Lock()
        self._availability_lock = Lock()
        self._state, self._job, self._report = 'idle', None, None
        self._cancel = Event()
        self._closed = False
        self._thread = None
        self._cached = None
        self._checked = 0.0

    def availability(self):
        with self._availability_lock:
            return self._availability()

    def _availability(self):
        # Passive file admission only; GET/page load cannot run an analyzer or
        # sandbox probe. The complete digest is checked again before submission.
        if self._cached is not None and time.monotonic() - self._checked < 5:
            return deepcopy(self._cached)
        try:
            if not sandbox.supported():
                value = dict(state='unsupported', message='Use non-root Linux x86-64 with Python 3.11 or 3.12 for this optional inspector.')
            else:
                self._validator(self.home)
                needed = ('/usr/bin/bwrap', '/usr/bin/systemd-run', '/usr/lib/x86_64-linux-gnu/libseccomp.so.2')
                if not all(Path(p).is_file() for p in needed):
                    raise ValueError('Missing isolation prerequisite.')
                value = dict(state='ready', message='Inspector files match the pinned runtime. Isolation is checked before each inspection.')
        except (OSError, ValueError, runtime.InstallError):
            value = dict(state='unavailable', message='Install or check the optional file inspector and its isolation prerequisites. Changed or incomplete files are refused.')
        self._cached, self._checked = value, time.monotonic()
        return deepcopy(value)

    def snapshot(self):
        available = self.availability()
        with self._lock:
            return dict(schema=STATUS_SCHEMA, state=self._state, job_id=self._job,
                        runtime=available, max_bytes=MAX_INPUT, report=deepcopy(self._report))

    def reserve(self, size):
        if type(size) is not int or not 1 <= size <= MAX_INPUT:
            raise ValueError('Choose one executable no larger than 64 MiB.')
        with self._lock:
            if self._closed:
                raise ValueError('Inspector is shutting down.')
            if self._state in ('receiving', 'running'):
                raise InspectionBusy('An inspection is already in progress.')
            self._state, self._job, self._report = 'receiving', secrets.token_hex(16), None
            self._cancel = Event()
            job = self._job
        try:
            # Repeat exact file admission outside the lock, after reservation.
            root = self._validator(self.home)
            fd = sandbox.sealed_input()
        except BaseException:
            self.abort(job)
            raise
        return job, fd, root

    def receiving_cancelled(self, job):
        with self._lock:
            return self._closed or job != self._job or self._cancel.is_set()

    def abort(self, job):
        with self._lock:
            if self._job == job:
                self._state = 'cancelled' if self._cancel.is_set() else 'failed'

    def submit(self, job, fd, size, root):
        """Take FD ownership only after the full bounded upload has arrived."""
        sandbox.seal(fd)
        with self._lock:
            if job != self._job or self._closed or self._cancel.is_set():
                self._state = 'cancelled'
                return False
            self._state = 'running'
            self._thread = Thread(target=self._work, args=(job, fd, size, root, self._cancel),
                                  name='megalodon-file-inspection', daemon=True)
            try:
                self._thread.start()
            except RuntimeError:
                self._thread = None
                self._state = 'failed'
                raise ValueError('Inspector worker could not start.') from None
        return True

    def _work(self, job, fd, size, root, cancelled):
        results = []
        deadline = time.monotonic() + 30
        try:
            # Probe the exact confinement before a native parser sees input.
            state, raw = self._runner(root, fd, 'lief', deadline=deadline, cancelled=cancelled, probe='confinement')
            admitted = state == 'completed' and decode(raw) == dict(network=True, fork=True, host_read=True, host_write=True, execute_input=True)
            if not admitted:
                state = state if state in ('cancelled', 'timed_out') else 'unavailable'
                results = [dict(state=state), dict(state=state)]
            else:
                for tool, normalizer in (('lief', normalize_lief), ('die', normalize_die)):
                    if cancelled.is_set():
                        results.append(dict(state='cancelled'))
                        continue
                    if tool == 'die' and results[0]['state'] == 'unsupported':
                        results.append(dict(state='unsupported'))
                        continue
                    state, raw = self._runner(root, fd, tool, deadline=deadline, cancelled=cancelled)
                    try:
                        result = normalizer(raw) if state == 'completed' else dict(state=state)
                    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
                        result = dict(state='failed')
                    results.append(result)
            value = report(size, results)
        except Exception:
            value = report(size, [dict(state='failed'), dict(state='failed')])
        finally:
            os.close(fd)
        with self._lock:
            if self._job == job:
                if cancelled.is_set():
                    # A late Cancel wins over publication of completed output.
                    value = report(size, [dict(state='cancelled'), dict(state='cancelled')])
                self._report = value
                self._state = value['state'] if value['state'] != 'unsupported' else 'failed'

    def cancel(self):
        with self._lock:
            if self._state in ('receiving', 'running'):
                self._cancel.set()
            # Receiving stays reserved until its request exits; running stays
            # reserved until the namespace is reaped. No overlap after Cancel.

    def close(self):
        with self._lock:
            self._closed = True
            self._cancel.set()
            thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
