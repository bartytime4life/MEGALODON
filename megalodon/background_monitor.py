"""Saved opt-in monitoring built from finite, individually receipted sessions."""
from threading import Event, Lock, Thread
import time


class BackgroundMonitor:
    def __init__(self, capture, geography, geography_enabled=lambda: False):
        self.capture, self.geography = capture, geography
        self.geography_enabled = geography_enabled
        self._lock, self._stop = Lock(), Event()
        self._thread = self._geo_thread = None
        self._state = dict(enabled=False,state='stopped',message='Background monitoring is stopped.',session_count=0)

    def snapshot(self):
        with self._lock:
            return dict(self._state)

    def start(self, interface):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._state.update(enabled=True,state='starting',message='Starting automatic traffic collection.',session_count=0)
            self._thread = Thread(target=self._run,args=(interface,),daemon=True,name='megalodon-background-monitor')
            self._thread.start()

    def refresh_geography(self):
        with self._lock:
            if self._geo_thread and self._geo_thread.is_alive():
                return
            self._geo_thread = Thread(target=self.geography.refresh,daemon=True,name='megalodon-geography')
            self._geo_thread.start()

    def _run(self, interface):
        next_geo = 0
        try:
            while not self._stop.is_set():
                if self.geography_enabled() and time.monotonic() >= next_geo:
                    self.refresh_geography()
                    next_geo = time.monotonic()+600
                status = self.capture.snapshot()
                if status['state']=='failed' and self._state['session_count']:
                    with self._lock:
                        self._state.update(state='failed',message='Capture stopped after an error. Check permissions, interface and storage, then enable monitoring again.')
                    return
                if status['state'] in {'idle','stopped','failed'}:
                    # Finite sessions and a brief visible gap keep receipts bounded.
                    if self._stop.wait(1):
                        break
                    from .support_config import ConfigBusy
                    try:
                        self.capture.start(interface)
                    except ConfigBusy:
                        # The preceding session can publish its final state just
                        # before its worker thread has completely returned.
                        self._stop.wait(.5)
                        continue
                    with self._lock:
                        self._state['session_count'] += 1
                with self._lock:
                    self._state.update(state='running' if status['state']=='running' else 'starting',
                                       message='Background traffic collection is enabled; finite sessions restart automatically while this HUD runs.')
                self._stop.wait(.5)
        except Exception:
            with self._lock:
                self._state.update(state='failed',message='Automatic collection could not start. Review the selected interface and capture access.')

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(5)
        self.capture.stop()
        with self._lock:
            self._state.update(enabled=False,state='stopped',message='Background monitoring stopped. Stored metadata is retained.')
