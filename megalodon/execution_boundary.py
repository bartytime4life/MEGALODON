"""One-way Stage 0 application fence; not native process containment.

Only trusted Python launch code selects this mode. There is deliberately no
reset/enable-maintenance API and no environment, settings or request loader.
Start a fresh process: selection cannot undo effects or stop existing workers.
Normal installed-runtime behavior remains the default in a fresh process.
"""

DENIAL = "STAGE0_OFFLINE_EFFECT_DENIED"
_stage0_selected = False
_effects_entered = False


class Stage0Denied(ValueError):
    """Fixed, path-free refusal before an effectful entry point."""

    def __init__(self):
        super().__init__(DENIAL)


def select_stage0() -> None:
    """Latch the restrictive mode for this process; repeated selection is safe."""
    global _stage0_selected
    # Invalid/missing internal state must not be repaired into permission.
    selected = globals().get("_stage0_selected")
    if selected is not False and selected is not True:
        raise Stage0Denied()
    if globals().get("_effects_entered") is not False:
        # Cannot retroactively certify a process that entered an installed
        # workflow. Poison admission rather than silently continuing normally.
        _stage0_selected = None
        raise Stage0Denied()
    _stage0_selected = True


def effects_denied() -> bool:
    """Unknown state refuses too; only the exact installed default permits."""
    return globals().get("_stage0_selected") is not False


def require_effects_allowed() -> None:
    global _effects_entered
    if effects_denied():
        raise Stage0Denied()
    _effects_entered = True


def status() -> dict:
    selected = globals().get("_stage0_selected")
    mode = ("installed_runtime" if selected is False else
            "stage0_offline" if selected is True else "unavailable")
    return {"schema": "megalodon-execution-boundary-v1", "mode": mode,
            "effectful_entries_denied": effects_denied(),
            "denial_code": DENIAL if effects_denied() else None,
            "scope": "application_entry_fences_not_os_containment",
            "acceptance_authority": False}
