"""Read-only recovery gaps derived from an already captured host-security snapshot.

An AIDE baseline or comparison is not a backup or an attack attribution. This
projection never admits a restore target, opens a file, or starts a workflow.
"""
from datetime import datetime, timezone

from .host_findings import validate_summary
from .host_security import AIDE_SCOPE, SCHEMA as HOST_SCHEMA

SCHEMA = 'megalodon-recovery-readiness-v1'
_SOURCE_FIELDS = frozenset({
    'schema', 'audit', 'integrity', 'feeds', 'feed_state', 'baseline_present',
    'message', 'action_authority', 'audit_state', 'integrity_state',
})
_INTEGRITY_STATES = ('available', 'legacy', 'missing', 'unavailable')


def review(host_security, *, now=None):
    """Project bounded observations without inferring recovery eligibility.

    The source snapshot owns report/file readback. We validate its integrity
    summary again, then copy only fixed enums, its timestamp, and boolean change
    categories. Malformed or contradictory source data clears all observation
    fields. Readiness remains unavailable for every valid source state as well.
"""
    result = dict(
        schema=SCHEMA, state='unavailable', action_authority='none',
        action_status='not_attempted', restore_eligible=False,
        baseline_state='unknown', integrity_state='unavailable',
        integrity_operation=None, checked_at=None, change_categories=None,
        scope=list(AIDE_SCOPE), backup_state='not_integrated',
        causality_state='unavailable', conflict_state='not_assessed',
    )
    try:
        if (type(host_security) is not dict or len(host_security) != len(_SOURCE_FIELDS)
                or set(host_security) != _SOURCE_FIELDS
                or host_security['schema'] != HOST_SCHEMA
                or host_security['action_authority'] != 'none'
                or type(host_security['baseline_present']) is not bool
                or type(host_security['integrity_state']) is not str
                or host_security['integrity_state'] not in _INTEGRITY_STATES):
            return result
        state = host_security['integrity_state']
        summary = host_security['integrity']
        if state in ('missing', 'unavailable'):
            if summary is not None:
                return result
        else:
            observed_now = datetime.now(timezone.utc) if now is None else now
            if (type(observed_now) is not datetime or observed_now.tzinfo is None
                    or observed_now.utcoffset() is None):
                return result
            validate_summary('integrity', summary, observed_now)
            if (state == 'available') != ('review' in summary):
                return result
            result['checked_at'] = summary['checked_at']
            if state == 'available':
                result['integrity_operation'] = summary['review']['operation']
                result['change_categories'] = [
                    name for name in ('added', 'removed', 'changed')
                    if summary['metrics'][name + '_detected']
                ]
        result['baseline_state'] = 'present' if host_security['baseline_present'] else 'missing'
        result['integrity_state'] = state
    except (ValueError, TypeError, KeyError, OverflowError):
        # Never return partial observation success after a failed validation.
        result.update(baseline_state='unknown', integrity_state='unavailable',
                      integrity_operation=None, checked_at=None, change_categories=None)
    return result
