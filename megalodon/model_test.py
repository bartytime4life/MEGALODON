"""In-memory result of one explicitly requested, fixed local-model probe."""
from datetime import datetime, timezone
from threading import Event, Lock
from time import monotonic

from . import ai_provider


MESSAGES = {
    'DISABLED':'Save an installed model in Setup before testing it.',
    'MODEL_MISSING':'The saved model is no longer installed. Refresh the list and select it again.',
    'MODEL_MISMATCH':'The saved model version changed. Refresh and save the model again before testing.',
    'MODEL_NOT_LOCAL':'This model is remote or lacks local text completion. Choose a local text model.',
    'POLICY_REJECTION':'The local model or Ollama listener did not pass its connection checks.',
    'OLLAMA_UNAVAILABLE':'Ollama is not reachable at 127.0.0.1:11434. Check its local service.',
    'REQUEST_TIMEOUT':'The model test reached its time limit. Choose a smaller model or retry explicitly.',
    'REQUEST_CANCELLED':'The local model test was cancelled.',
    'CONCURRENCY_LIMIT_REACHED':'Another local AI request is running. Retry the test after it finishes.',
    'CONCURRENCY_CONTROL_UNAVAILABLE':'The local request lock is unavailable. Review the private app permissions.',
    'INVALID_RESPONSE':'Ollama replied, but the fixed READY response check did not pass.',
    'PROVIDER_ERROR':'Ollama could not complete the test. Check model resources and its local service.',
}


def _key(settings):
    return settings.model, settings.model_digest, settings.compute_mode, settings.enabled


def _stamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


class ModelTest:
    def __init__(self, settings):
        self.settings=settings
        self._lock=Lock()
        self._cancel=Event()
        self._key=None
        self._value=None

    def snapshot(self):
        settings=self.settings()
        with self._lock:
            value=dict(self._value) if self._key==_key(settings) and self._value else dict(
                state='idle',message='No local response test has run for this selection.',
                started_at=None,finished_at=None,duration_ms=None,error_code=None)
        return dict(value,model=settings.model,compute_mode=settings.compute_mode,
                    selection_saved=settings.enabled is True,
                    timeout_seconds=min(settings.timeout_seconds,ai_provider.MODEL_TEST_MAX_SECONDS))

    def prepare(self):
        settings=self.settings()
        with self._lock:
            self._cancel=Event()
            self._key=_key(settings)
            self._value=dict(state='running',message='Testing one fixed local response; collection continues.',
                             started_at=_stamp(),finished_at=None,duration_ms=None,error_code=None)

    def cancel(self):
        with self._lock:
            self._cancel.set()

    def run(self):
        settings=self.settings()
        with self._lock:
            if self._key!=_key(settings) or not self._value or self._value['state']!='running':
                raise ValueError('Start the model test explicitly from Setup.')
            event=self._cancel
        start=monotonic()
        code=None
        try:
            ai_provider.test_selected_model(settings,cancel_event=event)
        except ai_provider.AIProviderError as exc:
            code=exc.code if exc.code in MESSAGES else 'PROVIDER_ERROR'
        except Exception:
            code='PROVIDER_ERROR'
        if event.is_set():code='REQUEST_CANCELLED'
        message=MESSAGES[code] if code else 'Local response test passed. Ollama returned READY. Live-analysis AI remains paused pending acceptance.'
        with self._lock:
            self._value.update(state='cancelled' if code=='REQUEST_CANCELLED' else 'failed' if code else 'passed',
                message=message,finished_at=_stamp(),duration_ms=max(0,round((monotonic()-start)*1000)),error_code=code)
        if code:raise ValueError(message)
        return message
