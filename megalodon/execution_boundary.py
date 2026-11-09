"""One-way Stage 0 application fence; not native process containment.

Only trusted Python launch code selects this mode. There is deliberately no
reset/enable-maintenance API and no environment, settings or request loader.
Start a fresh process: selection cannot undo effects or stop existing workers.
Normal installed-runtime behavior remains the default in a fresh process.
"""

from threading import Lock

DENIAL = "STAGE0_OFFLINE_EFFECT_DENIED"
_stage0_selected = False
_effects_entered = False
# Trusted import-time setup; never construct a lock on a denied invocation.
_admission_lock = Lock()


class Stage0Denied(ValueError):
    """Fixed, path-free refusal before an effectful entry point."""

    def __init__(self):
        super().__init__(DENIAL)


def select_stage0() -> None:
    """Latch the restrictive mode for this process; repeated selection is safe."""
    global _stage0_selected
    with _admission_lock:
        # Selection and admission share one transition boundary.
        selected = globals().get("_stage0_selected")
        if selected is not False and selected is not True:
            raise Stage0Denied()
        if globals().get("_effects_entered") is not False:
            # Selection cannot retroactively certify an admitted workflow.
            _stage0_selected = None
            raise Stage0Denied()
        _stage0_selected = True


def effects_denied() -> bool:
    """Unknown state refuses too; only the exact installed default permits."""
    with _admission_lock:
        return globals().get("_stage0_selected") is not False


def require_effects_allowed() -> None:
    global _effects_entered
    with _admission_lock:
        # Do not recursively acquire the non-reentrant lock through the public
        # query. Mark admission before releasing selection's same lock.
        if globals().get("_stage0_selected") is not False:
            raise Stage0Denied()
        _effects_entered = True


def status() -> dict:
    with _admission_lock:
        selected = globals().get("_stage0_selected")
    # Derive every field from the same snapshot, even if selection follows it.
    denied = selected is not False
    mode = ("installed_runtime" if selected is False else
            "stage0_offline" if selected is True else "unavailable")
    return {"schema": "megalodon-execution-boundary-v1", "mode": mode,
            "effectful_entries_denied": denied,
            "denial_code": DENIAL if denied else None,
            "scope": "application_entry_fences_not_os_containment",
            "acceptance_authority": False}
