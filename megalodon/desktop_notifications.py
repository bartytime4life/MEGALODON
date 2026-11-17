"""Private, bounded desktop hints for newly committed local findings.

The trusted owner bootstraps current per-segment cursors before starting writers,
then calls observe only after persistence succeeds. No read endpoint should call
observe or tick. A notification is an attempted local hint, never proof that the
desktop displayed it, and carries no evidence content or response authority.
"""
from __future__ import annotations

from collections import OrderedDict
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from threading import Event, RLock, Thread, current_thread
import time

from . import execution_boundary
from .local_install import _atomic_write, _owned_directory, _regular_owned_file, _validate_directory_chain

SCHEMA = 'megalodon-desktop-notifications-v1'
MAX_SCOPES = 256
MAX_PENDING = 1000
MAX_STATE_BYTES = 64 * 1024
INTERVAL_SECONDS = 60
MAX_CURSOR = 2**63 - 1
SCOPE = re.compile(r'[a-z][a-z0-9_-]{0,31}:[a-f0-9]{32}')
ARGV = ('/usr/bin/notify-send', '--app-name=MEGALODON', '--urgency=normal',
        '--expire-time=10000', '--', 'MEGALODON findings',
        'New findings are available. Open MEGALODON to review the evidence.')
RESULTS = {'not_attempted', 'attempted', 'submitted', 'unavailable'}
REASONS = {'none', 'unsupported_platform', 'no_desktop_session', 'helper_unavailable',
           'helper_failed', 'helper_timeout', 'state_unavailable', 'clock_unavailable',
           'boundary_denied'}


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Invalid desktop notification state.')
        result[key] = value
    return result


def _cursor(scope, cursor):
    if (type(scope) is not str or SCOPE.fullmatch(scope) is None
            or type(cursor) is not int or not 0 <= cursor <= MAX_CURSOR):
        raise ValueError('Invalid committed notification cursor.')


def _timestamp(value):
    return type(value) in {int, float} and math.isfinite(value) and 0 <= value <= 253402300799


def _desktop_reason():
    if sys.platform != 'linux' or os.name != 'posix':
        return 'unsupported_platform'
    if not (os.environ.get('DISPLAY', '').strip() or os.environ.get('WAYLAND_DISPLAY', '').strip()):
        return 'no_desktop_session'
    # Do not search PATH or accept a command from settings/HTTP input.
    try:
        info = os.stat(ARGV[0])
        if not stat.S_ISREG(info.st_mode) or not os.access(ARGV[0], os.X_OK):
            return 'helper_unavailable'
    except OSError:
        return 'helper_unavailable'
    return None


class DesktopNotifications:
    """One runtime-owned notifier; the evidence owner serializes commit callbacks.

    Progress is persisted before queue admission and before each subprocess.
    Pending counts deliberately do not survive shutdown: findings remain in the
    HUD, while restarts never replay an old queue. At most one aggregate hint is
    attempted per minute, including failures. Scopes are immutable segment IDs;
    only newly committed callbacks may introduce a scope after bootstrap.
    """

    def __init__(self, *, home=None, enabled=False, clock=time.time,
                 monotonic=time.monotonic, runner=subprocess.run,
                 availability=_desktop_reason):
        execution_boundary.require_effects_allowed()
        if type(enabled) is not bool:
            raise ValueError('Desktop notifications require a boolean preference.')
        self.path = (Path.home() if home is None else Path(home)) / '.local/share/megalodon/desktop-notifications/state.json'
        self._clock, self._monotonic = clock, monotonic
        self._runner, self._availability = runner, availability
        self._lock = RLock()
        self._stop, self._thread = Event(), None
        self._enabled, self._closed, self._ready = enabled, False, False
        self._inflight = False
        self._failed = False
        self._pending, self._saturated = 0, False
        self._cursors = OrderedDict()
        self._last_attempt = None
        self._last_result, self._reason = 'not_attempted', 'none'
        self._next_attempt, self._last_mono = 0.0, None
        try:
            self._load()
        except (OSError, ValueError, TypeError):
            self._fail('state_unavailable')

    def _load(self):
        _validate_directory_chain(self.path.parent)
        if not os.path.lexists(self.path):
            return
        raw = self._read()
        value = json.loads(raw, object_pairs_hook=_pairs)
        fields = {'schema', 'enabled', 'cursors', 'last_attempt_at', 'last_result', 'reason'}
        if (type(value) is not dict or set(value) != fields or value['schema'] != SCHEMA
                or type(value['enabled']) is not bool
                or type(value['cursors']) is not list or len(value['cursors']) > MAX_SCOPES
                or type(value['last_result']) is not str or value['last_result'] not in RESULTS
                or type(value['reason']) is not str or value['reason'] not in REASONS
                or (value['last_attempt_at'] is not None and not _timestamp(value['last_attempt_at']))):
            raise ValueError('Invalid desktop notification state.')
        for item in value['cursors']:
            if type(item) is not list or len(item) != 2:
                raise ValueError('Invalid desktop notification state.')
            scope, cursor = item
            _cursor(scope, cursor)
            if scope in self._cursors:
                raise ValueError('Invalid desktop notification state.')
            self._cursors[scope] = cursor
        self._last_attempt = value['last_attempt_at']
        self._enabled = value['enabled']
        self._last_result, self._reason = value['last_result'], value['reason']

    def _read(self):
        raw = _regular_owned_file(self.path, maximum=MAX_STATE_BYTES)
        if self.path.lstat().st_mode & 0o077:
            raise ValueError('Desktop notification state must be private.')
        return raw

    def _save(self):
        execution_boundary.require_effects_allowed()
        _owned_directory(self.path.parent, private=True)
        if os.path.lexists(self.path):
            self._read()
        raw = json.dumps(dict(schema=SCHEMA, enabled=self._enabled, cursors=list(self._cursors.items()),
                              last_attempt_at=self._last_attempt,
                              last_result=self._last_result, reason=self._reason),
                         sort_keys=True, allow_nan=False).encode()
        if len(raw) > MAX_STATE_BYTES:
            raise ValueError('Desktop notification state exceeds its bound.')
        _atomic_write(self.path, raw, 0o600)

    def _persist(self):
        try:
            self._save()
            return True
        except execution_boundary.Stage0Denied:
            self._fail('boundary_denied')
        except (OSError, ValueError, TypeError):
            self._fail('state_unavailable')
        return False

    def _fail(self, reason):
        self._failed, self._pending = True, 0
        self._last_result, self._reason = 'unavailable', reason

    def _now(self):
        wall, mono = self._clock(), self._monotonic()
        if not _timestamp(wall) or type(mono) not in {int, float} or not math.isfinite(mono) or mono < 0:
            self._fail('clock_unavailable')
            return None
        if self._last_mono is not None and mono < self._last_mono:
            self._next_attempt = mono + INTERVAL_SECONDS
        self._last_mono = mono
        return wall, mono

    def bootstrap(self, cursors=None):
        """Skip current retained history once, before enabling commit callbacks."""
        execution_boundary.require_effects_allowed()
        cursors = {} if cursors is None else cursors
        if type(cursors) is not dict or len(cursors) > MAX_SCOPES:
            raise ValueError('Invalid notification startup cursors.')
        for scope, cursor in cursors.items():
            _cursor(scope, cursor)
        with self._lock:
            if self._closed or self._failed or self._ready:
                return False
            now = self._now()
            if now is None:
                return False
            wall, mono = now
            for scope, cursor in cursors.items():
                self._remember(scope, max(cursor, self._cursors.get(scope, 0)))
            # Across processes only wall time is comparable. A backwards wall
            # clock waits one full monotonic interval, never bypasses cooldown.
            remaining = (0 if self._last_attempt is None else
                         INTERVAL_SECONDS if wall < self._last_attempt else
                         max(0, INTERVAL_SECONDS - (wall - self._last_attempt)))
            self._next_attempt = mono + remaining
            if not self._persist():
                return False
            self._ready = True
            return True

    def _remember(self, scope, cursor):
        self._cursors[scope] = cursor
        self._cursors.move_to_end(scope)
        while len(self._cursors) > MAX_SCOPES:
            self._cursors.popitem(last=False)

    def observe(self, scope, cursor, *, count=1):
        """Admit an aggregate after its filtered findings are durably committed.

        count=0 advances progress for commits that contain no eligible finding.
        This API accepts no message, address, signature, executable or command.
        """
        execution_boundary.require_effects_allowed()
        _cursor(scope, cursor)
        if type(count) is not int or not 0 <= count <= MAX_CURSOR:
            raise ValueError('Invalid committed notification count.')
        with self._lock:
            if self._closed or self._failed or not self._ready or cursor <= self._cursors.get(scope, 0):
                return False
            self._remember(scope, cursor)
            if not self._persist():
                return False
            if self._enabled:
                self._saturated |= self._pending + count > MAX_PENDING
                self._pending = min(MAX_PENDING, self._pending + count)
            return True

    def configure(self, *, enabled):
        execution_boundary.require_effects_allowed()
        if type(enabled) is not bool:
            raise ValueError('Desktop notifications require a boolean preference.')
        with self._lock:
            if self._closed or self._failed:
                return False
            self._enabled = enabled
            if not enabled:
                self._pending, self._saturated = 0, False
            return self._persist()

    @property
    def enabled(self):
        with self._lock:
            return self._enabled and not self._closed and not self._failed

    def start(self):
        """Start the optional owner worker after bootstrap; never from a read."""
        execution_boundary.require_effects_allowed()
        with self._lock:
            if self._closed or self._failed or not self._ready or self._thread is not None:
                return False
            self._thread = Thread(target=self._loop, name='megalodon-desktop-notifications', daemon=True)
            self._thread.start()
            return True

    def _loop(self):
        while not self._stop.wait(1):
            try:
                self.tick()
            except execution_boundary.Stage0Denied:
                with self._lock:
                    self._fail('boundary_denied')
                return
            except Exception:
                # A hint worker failure cannot affect evidence collection.
                with self._lock:
                    self._fail('helper_failed')
                return

    def tick(self):
        """Attempt a generic hint from the runtime worker, never from HTTP GET."""
        execution_boundary.require_effects_allowed()
        with self._lock:
            if (self._closed or self._failed or self._inflight or not self._ready
                    or not self._enabled or not self._pending):
                return False
            now = self._now()
            if now is None:
                return False
            wall, mono = now
            if mono < self._next_attempt:
                return False
            self._next_attempt = mono + INTERVAL_SECONDS
            self._last_attempt = wall
            self._last_result, self._reason = 'attempted', 'none'
            self._pending, self._saturated = 0, False
            if not self._persist():
                return False
            self._inflight = True
        # The helper can take up to five seconds. Never hold the queue lock
        # while waiting: committed-evidence callbacks must remain independent.
        outcome, reason = 'unavailable', 'helper_failed'
        try:
            unavailable = self._availability()
            if self._stop.is_set():
                outcome, reason = 'attempted', 'none'
            elif unavailable is not None:
                reason = unavailable if unavailable in REASONS else 'helper_unavailable'
            else:
                execution_boundary.require_effects_allowed()
                result = self._runner(list(ARGV), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      shell=False, close_fds=True, timeout=5, check=False)
                outcome = 'submitted' if result.returncode == 0 else 'unavailable'
                reason = 'none' if result.returncode == 0 else 'helper_failed'
        except execution_boundary.Stage0Denied:
            reason = 'boundary_denied'
        except subprocess.TimeoutExpired:
            reason = 'helper_timeout'
        except OSError:
            reason = 'helper_failed'
        finally:
            with self._lock:
                self._inflight = False
                if not self._failed:
                    self._last_result, self._reason = outcome, reason
                    self._persist()
        return True

    def snapshot(self):
        """In-memory, read-only status; does not probe or launch the helper."""
        with self._lock:
            return dict(schema=SCHEMA, enabled=self._enabled,
                        state='closed' if self._closed else 'unavailable' if self._failed else
                              'disabled' if not self._enabled else 'ready' if self._ready else 'starting',
                        pending_count=self._pending, pending_limit=MAX_PENDING,
                        pending_saturated=self._saturated, interval_seconds=INTERVAL_SECONDS,
                        last_attempt_at=self._last_attempt, last_result=self._last_result,
                        reason=self._reason, delivery_verified=False, action_authority='none')

    def close(self):
        """Drop pending hints and stop admission; shutdown never emits a hint."""
        self._stop.set()
        with self._lock:
            self._closed, self._pending, self._saturated = True, 0, False
        if self._thread is not None and self._thread is not current_thread():
            self._thread.join(timeout=6)
