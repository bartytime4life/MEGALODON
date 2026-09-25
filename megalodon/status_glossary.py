"""Single source of truth for every status word shown in the HUD.

MEGALODON deliberately uses many narrow, truthful status vocabularies instead
of one collapsed "healthy/unhealthy" signal, because each check answers a
different question (executable presence is not process health is not data
coverage). That precision has a cost: the same English word ("unknown",
"not checked", "unavailable") means something different on different pages.
This module renders one glossary, grouped by what each check actually does,
so an operator can look a word up instead of guessing.

Groups tied to a real status vocabulary assert their labels cover every value
that vocabulary can produce. If a module adds or renames a status without
updating the matching group here, importing this module raises immediately
instead of letting the HUD and the glossary silently drift apart.
"""

from __future__ import annotations

from .capabilities import STATUSES as _CAPABILITY_STATUSES
from .readiness import STATUSES as _READINESS_STATUSES
from .runtime_status import STATUSES as _RUNTIME_STATUSES
from .tool_heartbeat import LIGHTS as _HEARTBEAT_LIGHTS
from .tool_installer import JOB_STATES as _JOB_STATES

GLOSSARY_ANCHOR_ID = "status-glossary"

# Each group: (heading, "where it appears", source vocabulary or None,
# tuple of (raw value or None, visible label, plain-English meaning)).
_GROUPS: tuple[tuple[str, str, frozenset[str] | None, tuple[tuple[str | None, str, str], ...]], ...] = (
    (
        "Executable presence", "Apps, Home", _READINESS_STATUSES,
        (
            ("executable_found", "Found candidate",
             "A known executable name was on the checked startup PATH. Installation method, version and compatibility are unverified."),
            ("not_found", "Not found",
             "Absent from that checked PATH; it may still exist elsewhere (a private install, a container, a different user)."),
            ("not_checked", "Not checked",
             "This app was not eligible for the executable-only startup check. No availability claim is possible."),
        ),
    ),
    (
        "Process & service state", "Apps, Home", _RUNTIME_STATUSES,
        (
            ("running", "Running",
             "A matching process name was observed at that moment. This does not prove the service is healthy or correctly configured."),
            ("not_running", "Not running",
             "No matching process name was found in this one-time snapshot."),
            ("not_applicable", "Not applicable",
             "Standalone tools have no expected background process, so its absence is not meaningful evidence."),
            ("not_checked", "Not checked",
             "The process list could not be read completely. This is never reported as “not running”."),
        ),
    ),
    (
        "Status light", "Apps", _HEARTBEAT_LIGHTS,
        (
            ("green", "Green",
             "Presence observed: the expected process is running, or a standalone tool is present."),
            ("amber", "Amber",
             "Installed, but its expected service is not running (for Qwen, the example model may not be downloaded)."),
            ("red", "Red", "Not installed."),
            ("grey", "Grey",
             "Could not be determined on this platform, or the first background check has not completed yet."),
        ),
    ),
    (
        "Install / start action", "Apps", _JOB_STATES,
        (
            ("idle", "Idle", "No install or start command has been run yet."),
            ("running", "Running", "The authorized command is currently executing."),
            ("succeeded", "Succeeded",
             "The command finished. Its effect is confirmed separately by the next status-light check, not by this state."),
            ("failed", "Failed",
             "The command exited with an error. The app card shows a terminal alternative when one exists."),
        ),
    ),
    (
        "MEGALODON support level", "Apps", _CAPABILITY_STATUSES,
        (
            ("implemented", "Implemented", "MEGALODON has a working data path for this tool."),
            ("optional", "Optional", "Supported, but not enabled by default."),
            ("evaluation_only", "Evaluation only", "A path exists but is unverified."),
            ("contract_only", "Contract only", "A data contract is defined; no importer exists yet."),
            ("manual_only", "Manual only", "Runs as a separate companion; MEGALODON does not import its results."),
            ("guest_only", "Guest only", "Available through a guest environment, not natively."),
            ("proposed", "Proposed", "Planned; not implemented."),
            ("unsupported", "Unsupported", "No path exists on this platform."),
        ),
    ),
    (
        "Data source & ingestion", "Home, Findings, Evidence", None,
        (
            (None, "Connected", "A selected audit store passed its bounded read check."),
            (None, "Not configured", "No data file was selected when this HUD started."),
            (None, "Running / Completed / Incomplete / Failed",
             "An ingestion receipt's own outcome. A completed receipt describes stored work, not sensor liveness."),
            (None, "Reconciliation required",
             "The receipt could not be reconciled with its source. Its events are excluded from Traffic and Findings until that is resolved."),
        ),
    ),
    (
        "Traffic availability & quality", "Traffic", None,
        (
            (None, "Available / Unavailable", "Whether any qualified metadata exists for the current window."),
            (None, "Degraded",
             "Some returned data was truncated, or an ingestion run behind it did not finish cleanly."),
            (None, "Unknown (quality)",
             "No degradation was detected. This is a different “unknown” from an unchecked presence or service "
             "state above — it means nothing wrong was found, not that the check was skipped."),
        ),
    ),
)

_CALLOUT = (
    "<strong>The same word means different things in different places.</strong> "
    "“Unknown” and “not checked” almost always mean the check could not answer the question, "
    "never a hidden bad result. The one exception is Traffic’s <strong>quality: unknown</strong> above, "
    "which means no problem was detected — read every status next to its label, not on its own."
)

_AI_NOTE = (
    "The Local AI control panel uses its own fixed set of states (disabled, unavailable, missing, ready, timed out, "
    "and so on), spelled out in full next to its Check button. They describe the local Ollama/Qwen check only, "
    "never a network or host finding."
)


def _validate() -> None:
    for heading, _where, vocabulary, terms in _GROUPS:
        if vocabulary is None:
            continue
        covered = {value for value, _label, _meaning in terms if value is not None}
        if covered != set(vocabulary):
            raise AssertionError(
                f"status glossary group {heading!r} covers {sorted(covered)} "
                f"but its source vocabulary is {sorted(vocabulary)}"
            )


_validate()


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_group(heading: str, where: str, terms: tuple[tuple[str | None, str, str], ...]) -> str:
    rows = "".join(
        f"<div><dt>{_escape(label)}</dt><dd>{_escape(meaning)}</dd></div>"
        for _value, label, meaning in terms
    )
    return (
        f'<div class="status-glossary-group"><h4>{_escape(heading)} '
        f'<span class="status-glossary-where">— {_escape(where)}</span></h4><dl>{rows}</dl></div>'
    )


def _render() -> str:
    groups_html = "".join(_render_group(heading, where, terms) for heading, where, _vocab, terms in _GROUPS)
    return (
        f'<div class="status-glossary" id="{GLOSSARY_ANCHOR_ID}">{groups_html}'
        f'<div class="status-glossary-group"><h4>Local AI status <span class="status-glossary-where">'
        f'— Local AI control</span></h4><p>{_AI_NOTE}</p></div>'
        f'</div><div class="status-glossary-callout">{_CALLOUT}</div>'
    )


STATUS_GLOSSARY_HTML = _render()

STATUS_GLOSSARY_CSS = """
.status-glossary { display: grid; gap: 16px; margin: 14px 0; }
.status-glossary-group h4 { margin: 0 0 6px; font-size: .84rem; color: var(--text); }
.status-glossary-where { color: var(--muted); font-size: .68rem; font-weight: 600; text-transform: none; }
.status-glossary-group dl { display: grid; gap: 6px; margin: 0; }
.status-glossary-group dl > div { display: grid; grid-template-columns: minmax(120px, .32fr) minmax(0, 1fr); gap: 4px 10px; }
.status-glossary-group dt { color: var(--cyan); font-size: .74rem; font-weight: 800; }
.status-glossary-group dd { margin: 0; color: var(--muted); font-size: .76rem; line-height: 1.5; }
.status-glossary-group > p { margin: 0; color: var(--muted); font-size: .78rem; line-height: 1.5; }
.status-glossary-callout { margin-top: 14px; padding: 12px 14px; border-left: 3px solid var(--amber); background: rgba(255, 209, 102, .045); font-size: .8rem; line-height: 1.55; }
@media (max-width: 560px) { .status-glossary-group dl > div { grid-template-columns: 1fr; } }
"""
