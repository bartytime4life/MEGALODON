"""Bounded durable batching with a provisional detector, used by local capture."""
from copy import deepcopy
import json
from threading import RLock
import time

from .service import MegalodonService


class BufferedRecording:
    MAX_RECORDS = 256
    MAX_BYTES = 1024 * 1024
    MAX_SECONDS = 2
    QUEUE_RECORDS = 4096
    QUEUE_BYTES = 8 * 1024 * 1024

    def __init__(self, settings, store, *, run_id, monotonic=time.monotonic, on_status=None):
        self.service = MegalodonService(settings, store)
        self.store, self.run_id, self.monotonic = store, run_id, monotonic
        self.on_status = on_status
        self.lock = RLock()
        self.pending = []
        self.pending_bytes = 0
        self.started = None
        self.staged = None
        self.committed = self.commits = self.failures = self.unconfirmed = 0

    def snapshot(self):
        return dict(pending_records=len(self.pending), pending_bytes=self.pending_bytes,
                    oldest_pending_seconds=max(0, self.monotonic() - self.started) if self.started is not None else 0,
                    saved_records=self.committed, batch_commits=self.commits,
                    write_failures=self.failures, unconfirmed_records=self.unconfirmed,
                    queue_record_limit=self.QUEUE_RECORDS, queue_byte_limit=self.QUEUE_BYTES)

    def _notify(self):
        if self.on_status:
            self.on_status(self.snapshot())

    def process(self, event, *, run_id=None):
        with self.lock:
            self.flush_due()
            size = len(json.dumps(event.to_dict(), separators=(',', ':')).encode())
            if size > self.MAX_BYTES:
                raise ValueError('Packet metadata exceeds the recording batch bound.')
            if self.pending and self.pending_bytes + size > self.MAX_BYTES:
                self.flush()
            if len(self.pending) >= self.QUEUE_RECORDS or self.pending_bytes + size > self.QUEUE_BYTES:
                raise ValueError('Recording queue is full; intake must stop.')
            if self.staged is None:
                # Only this bounded provisional detector advances before persistence.
                # The committed detector is left untouched on any failed transaction.
                self.staged = deepcopy(self.service.detector)
            prepared = self.staged.prepare(event)
            try:
                detections = list(prepared.results)
                actions = [self.service._action_for_detection(item) for item in detections]
            except BaseException:
                prepared.rollback()
                raise
            prepared.commit()
            if not self.pending:
                self.started = self.monotonic()
            self.pending.append((event, detections, actions))
            self.pending_bytes += size
            if detections or actions or len(self.pending) >= self.MAX_RECORDS or self.pending_bytes >= self.MAX_BYTES:
                self.flush()
            self._notify()
            return detections

    def flush_due(self):
        with self.lock:
            if self.started is not None and self.monotonic() - self.started >= self.MAX_SECONDS:
                self.flush()
            self._notify()

    def flush(self):
        with self.lock:
            if not self.pending:
                return
            count = len(self.pending)
            try:
                self.store.record_event_bundles(self.pending, run_id=self.run_id)
            except BaseException:
                self.failures += 1
                self.unconfirmed += count
                self.pending.clear()
                self.pending_bytes = 0
                self.started = self.staged = None
                self._notify()
                raise
            self.service.detector = self.staged
            self.committed += count
            self.commits += 1
            self.pending.clear()
            self.pending_bytes = 0
            self.started = self.staged = None
            self._notify()
