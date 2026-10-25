"""One cancellable keep-ready worker for the HUD's exact selected local model.

Only the existing admitted transport may load a model. No pulls, service starts,
profile rebinding or inference are performed. The five-minute lease expires
after the HUD stops; manual requests take priority over these background loads.
"""
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from time import monotonic

from . import ai_provider


def _key(settings):
    return (settings.enabled, settings.model, settings.model_digest,
            settings.compute_mode, settings.keep_warm, settings.max_context)


class ModelLifecycle:
    def __init__(self, settings, *, prepare=None, inspect=None, loaded=None,
                 clock=monotonic, poll_seconds=15, on_change=None):
        self.settings = settings
        self.prepare = prepare or ai_provider.prepare_model
        self.inspect = inspect or (lambda value: ai_provider.status(value, probe=False))
        self.loaded = loaded or ai_provider.loaded_model
        self.clock = clock
        self.poll_seconds = poll_seconds
        self.on_change = on_change
        self._lock = Lock()
        self._wake, self._stop = Event(), Event()
        self._thread = None
        self._identity = None
        self._next_attempt = 0
        self._renewed = None
        self._failures = 0
        self._value = dict(state='checking', message='Checking selected model.', error_code=None,
                           updated_at=None)

    def _publish(self, state, message, error=None):
        with self._lock:
            changed = (state, message, error) != (self._value['state'],self._value['message'],self._value['error_code'])
            self._value = dict(state=state, message=message, error_code=error,
                               updated_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        if changed and self.on_change is not None:
            self.on_change()

    def snapshot(self):
        with self._lock:
            value = dict(self._value)
            value['retry_in_seconds'] = max(0, round(self._next_attempt - self.clock()))
        return value

    def start(self):
        with self._lock:
            if self._thread is not None:
                return
            self._thread = Thread(target=self._run, name='megalodon-model-ready', daemon=True)
            self._thread.start()

    def request(self):
        # Cancellation is restricted to this worker, never an operator request.
        ai_provider.cancel_current(owner='hud-model-ready')
        if not self._stop.is_set():
            settings=self.settings()
            self._publish('checking' if settings.keep_warm else 'paused',
                          'Checking selected model.' if settings.keep_warm else 'Loads on demand; automatic recovery is off.')
        self._wake.set()

    def close(self):
        self._stop.set()
        self.request()
        if self._thread is not None:
            self._thread.join(3)

    def _step(self, *, force=False):
        settings = self.settings()
        identity = _key(settings)
        if identity != self._identity or force:
            self._identity = identity
            self._next_attempt = 0
            self._renewed = None
            self._failures = 0
            self._publish('checking', 'Checking selected model.')
        if not settings.enabled:
            self._publish('disabled', 'Choose an installed model to enable local AI.')
            return
        if not settings.keep_warm:
            self._publish('paused', 'Loads on demand; automatic recovery is off.')
            return
        if self.clock() < self._next_attempt:
            return
        try:
            observation = self.inspect(settings)
            state = observation.get('state')
            if state == 'model_loading':
                self._next_attempt = self.clock() + self.poll_seconds
                self._publish('checking', 'Local AI is busy; readiness checking resumes shortly.')
                return
            if state != 'model_available':
                code = {'ollama_unavailable':'OLLAMA_UNAVAILABLE', 'model_missing':'MODEL_MISSING',
                        'model_mismatch':'MODEL_MISMATCH', 'policy_rejection':'POLICY_REJECTION',
                        'model_not_local':'MODEL_NOT_LOCAL'}.get(state, 'PROVIDER_ERROR')
                raise ai_provider.AIProviderError(code)
            allocation = self.loaded(settings)
            if allocation.get('loaded') is not True or self._renewed is None or self.clock() - self._renewed >= 120:
                self._publish('loading', 'Loading selected model; traffic collection continues.')
                self.prepare(settings)
                if self._stop.is_set() or _key(self.settings()) != identity:
                    return
                # A successful empty-prompt response alone is not runtime proof.
                if self.loaded(settings).get('loaded') is not True:
                    raise ai_provider.AIProviderError('PROVIDER_ERROR')
                self._renewed = self.clock()
            self._failures = 0
            self._next_attempt = 0
            self._publish('ready', 'Selected model is loaded. Automatically recovers its local connection.')
        except ai_provider.AIProviderError as exc:
            if self._stop.is_set() or _key(self.settings()) != identity:
                return
            if exc.code in {'CONCURRENCY_LIMIT_REACHED', 'REQUEST_CANCELLED'}:
                self._next_attempt = self.clock() + self.poll_seconds
                self._publish('checking', 'Local AI is busy; readiness checking resumes shortly.')
                return
            self._failures += 1
            delay = min(120, 5 * 2 ** min(self._failures - 1, 5))
            self._next_attempt = self.clock() + delay
            from .model_telemetry import ERROR_STATES, MESSAGES
            message = MESSAGES.get(ERROR_STATES.get(exc.code), 'Selected model could not be loaded.')
            self._publish('retrying', message + ' Retrying automatically.', exc.code)

    def _run(self):
        force = False
        while not self._stop.is_set():
            try:
                self._step(force=force)
            except Exception:
                # An unexpected local error must not terminate recovery forever.
                self._next_attempt = self.clock() + 120
                self._publish('error', 'Model readiness check failed; retrying automatically.', 'LOCAL_ERROR')
            delay = self.poll_seconds
            if self._next_attempt > self.clock():
                delay = min(delay, max(.1, self._next_attempt - self.clock()))
            force = self._wake.wait(delay)
            self._wake.clear()
