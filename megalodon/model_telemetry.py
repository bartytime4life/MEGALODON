"""Shared cached model observations. Refreshes never load or infer with a model."""
from datetime import datetime, timezone
from threading import Lock, Thread
from time import monotonic

from . import ai_provider


MESSAGES = {
    'cancelled': 'The local AI request was cancelled. You can retry when ready.',
    'generating': 'Local AI is working. Traffic collection continues in the background.',
    'model_not_local': 'This model is remote or does not support local text completion. Select another installed model.',
    'disabled': 'Not configured. Select an installed model in Setup.',
    'ollama_unavailable': 'Ollama is unavailable on this PC. Check its service in Setup.',
    'model_missing': 'The configured model is missing. Existing models are preserved.',
    'policy_rejection': 'The configured model identity or local listener did not pass verification.',
    'request_timeout': 'Ollama did not respond within the bounded time limit. Retry verification.',
    'invalid_response': 'The last model response was incomplete or invalid. Retry verification.',
    'provider_error': 'Ollama could not run the configured model. Retry verification and review its resources.',
    'model_loading': 'Another local model check is in progress.',
    'concurrency_unavailable': 'The local request lock is unavailable. Review the local service.',
}
ERROR_STATES = {'REQUEST_CANCELLED':'cancelled','PROVIDER_ERROR':'provider_error','REQUEST_TIMEOUT':'request_timeout',
                'INVALID_RESPONSE':'invalid_response','OLLAMA_UNAVAILABLE':'ollama_unavailable',
                'MODEL_MISSING':'model_missing','MODEL_MISMATCH':'policy_rejection','POLICY_REJECTION':'policy_rejection','MODEL_NOT_LOCAL':'model_not_local',
                'CONCURRENCY_LIMIT_REACHED':'model_loading','CONCURRENCY_CONTROL_UNAVAILABLE':'concurrency_unavailable'}


class ModelTelemetry:
    def __init__(self, settings, *, inspect=None, loaded=None, catalog=None):
        self.settings=settings
        self.inspect=inspect or (lambda value:ai_provider.status(value,probe=False))
        self.loaded=loaded or ai_provider.loaded_model
        self.catalog=catalog or ai_provider.model_catalog
        self._lock=Lock();self._thread=None;self._key=None;self._value=None;self._at=0.;self._pending=False

    def _refresh(self,settings,key):
        try:
            options=self.catalog()
            options.sort(key=lambda row:(row['name']!=settings.model,row['name']))
            result={**self.inspect(settings),'options':options[:64],'truncated':len(options)>64}
            runtime={}
            if result['state']=='model_available':
                try:runtime=self.loaded(settings)
                except ai_provider.AIProviderError:runtime={'loaded':None,'memory_bytes':None,'vram_bytes':None}
            result={**result,**runtime,'checked_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
        except ai_provider.AIProviderError as exc:
            result={'state':ERROR_STATES.get(exc.code,'invalid_response'),'checked_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
        except (OSError, ValueError, TypeError, KeyError):
            result={'state':'ollama_unavailable','checked_at':datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
        with self._lock:
            if self._key==key:
                if result['state']=='model_loading' and self._value:
                    result.update(options=self._value.get('options',[]),truncated=self._value.get('truncated',False))
                self._value=result;self._at=monotonic()
            self._pending=False

    def invalidate(self):
        with self._lock:self._at=0.

    def snapshot(self):
        settings=self.settings();key=(settings.enabled,settings.model,settings.model_digest,settings.compute_mode)
        with self._lock:
            if key!=self._key:self._key=key;self._value=None;self._at=0
            refresh_after=2 if (self._value or {}).get('state')=='model_loading' else 30
            if not self._pending and (self._value is None or monotonic()-self._at>=refresh_after):
                self._pending=True;self._thread=Thread(target=self._refresh,args=(settings,key),daemon=True,name='megalodon-model-status');self._thread.start()
            value=dict(self._value or {});stale=bool(self._value and monotonic()-self._at>90)
        observation=ai_provider.last_observation(settings)
        state=value.get('state','checking');accepted=observation.get('last_response_at')
        error=observation.get('error_code')
        if state=='model_available' and error:state=ERROR_STATES.get(error,'invalid_response')
        if stale:state='stale'
        if observation.get('running'):state='generating'
        verified=state=='model_available' and bool(accepted) and not error
        message=MESSAGES.get(state,'Checking the configured local model.' if state=='checking' else
            'Model observation is stale; checking again.' if state=='stale' else
            'Configured model is present; verify its response in Setup.' if not accepted else
            'Configured model is present. Last accepted response '+accepted+'.')
        workflow='connected' if verified else 'ready' if state=='model_available' else 'collecting' if state in ('checking','model_loading','generating') else 'needs_setup' if state=='disabled' else 'error'
        return dict(timeout_seconds=settings.timeout_seconds,running=bool(observation.get('running')),started_at=observation.get('started_at'),options=value.get('options',[]),truncated=value.get('truncated',False),compute_mode=settings.compute_mode,selected_digest=settings.model_digest,state=workflow,model=settings.model,model_state=state,model_present=value.get('state')=='model_available',
            message=(settings.model+' · '+('CPU' if settings.compute_mode=='cpu' else 'Ollama automatic compute')+' advice. '+message)[:512],updated_at=value.get('checked_at'),
            last_response_at=accepted,last_attempt_at=observation.get('last_attempt_at'),error_code=error,
            response_ms=observation.get('duration_ms'),inference_verified=verified,**{k:value.get(k) for k in ('loaded','memory_bytes','vram_bytes')})
