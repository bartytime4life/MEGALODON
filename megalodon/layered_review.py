"""Bounded co-occurrence review of fixed, source-qualified network signals.

This module has no collector, model, database or response authority. It combines
review metadata, never packet/flow counts or claims of independent detection.
"""
from collections import defaultdict
import ipaddress
import re

from .evidence_storage import epoch, utc
from .security_patterns import candidate, stable, MAX_DEPENDENCIES

MAX_INPUTS = 64
MAX_REVIEWS = 8
MAX_REFERENCES = 48
FAMILIES = {
    'PORT_SCAN': 'discovery', 'HOST_FANOUT': 'discovery',
    'SYN_FLOOD': 'traffic_volume',
    'DNS_TUNNELING': 'dns', 'PORT_53_BURST': 'dns',
    'REGULAR_INTERVAL': 'cadence',
    'NEW_DESTINATION_PORT': 'baseline_change',
    'PROTOCOL_SHIFT': 'baseline_change', 'SERVICE_SHIFT': 'baseline_change',
}
IDENTIFIER = re.compile(r'[a-f0-9]{32}')
REFERENCE = re.compile(r'[a-f0-9]{32}:[1-9][0-9]{0,18}')
LIMIT_GAP = 'Layered review work limit reached; additional signal combinations were not assessed.'
INVALID_GAP = 'A signal with incomplete or invalid provenance was excluded from layered review.'
BOUNDARY = ('Signals share a recorded address, interface and hour, not a verified host identity or attack sequence. '
            'Sensors may observe the same traffic; independent corroboration is not established.')
SHARED_SUPPORT = ('The selected signals cite some of the same retained observations; '
                  'different rule families do not add independent evidence.')
SEPARATED_SUPPORT = ('Recorded support extents are separated in time; same-hour grouping does not establish '
                     'one activity sequence or continuous address ownership.')
UNKNOWN_TIMING = 'Comparable component support times are unavailable; temporal proximity was not assessed.'
UNKNOWN_AUTHORIZATION = ('Authorized activity and address ownership context are unavailable; '
                         'metadata alone cannot distinguish approved work from suspicious activity.')
TIMED_RULES = {'HOST_FANOUT', 'REGULAR_INTERVAL', 'PORT_53_BURST'}


def _support_extent(signal, start, end):
    """Only these fixed rules record extents of their actual supporting set.

    Missing/invalid optional timing is unknown, never a reason to lose a review.
    An extent is not continuous activity, verified clock provenance or identity.
    """
    facts = signal.get('facts')
    if signal['rule'] not in TIMED_RULES or type(facts) is not dict:
        return None
    try:
        first, last = epoch(facts['first_seen']), epoch(facts['last_seen'])
        return (first, last) if start <= first <= last < end else None
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return None


def _qualification(pair, start, end):
    shared = len(set(pair[0]['evidence_refs']) & set(pair[1]['evidence_refs']))
    extents = [_support_extent(v, start, end) for v in pair]
    relation, gap = 'unavailable', None
    notes = [SHARED_SUPPORT] if shared else []
    if all(v is not None for v in extents):
        gap = round(max(0, max(v[0] for v in extents) - min(v[1] for v in extents)), 6)
        relation = 'separated' if gap > 0 else 'overlapping_extents'
        if gap > 0:
            notes.append(SEPARATED_SUPPORT)
    else:
        notes.append(UNKNOWN_TIMING)
    return dict(reference_scope='selected_reference_pages', shared_reference_count=shared,
                support_time_relation=relation, support_time_gap_seconds=gap,
                authorization_context='unavailable'), notes


def _text(value, maximum):
    return (type(value) is str and 0 < len(value) <= maximum
            and value.isprintable() and len(value.encode('utf-8')) <= maximum)


def _signal(item, start, end):
    """Select bounded application facts; never copy arbitrary evidence fields."""
    if type(item) is not dict or item.get('rule') not in FAMILIES:
        return None
    address = item['device']
    if (type(address) is not str or len(address) > 45 or '%' in address
            or str(ipaddress.ip_address(address)) != address):
        raise ValueError
    interface = item['interface']
    if not _text(interface, 64) or interface == 'unreported':
        raise ValueError
    if (not _text(item['sensor'], 128) or item['measurement'] not in {'packet', 'flow', 'finding'}
            or type(item['id']) is not str or not IDENTIFIER.fullmatch(item['id'])
            or epoch(item['start']) != start or epoch(item['end']) != end
            or epoch(item['source_start']) > start or item['action_status'] != 'not_attempted'):
        raise ValueError
    refs, segments = item['evidence_refs'], item['source_segments']
    if (type(refs) is not list or not 1 <= len(refs) <= 24
            or type(segments) is not list or not 1 <= len(segments) <= MAX_DEPENDENCIES
            or any(type(s) is not str or not IDENTIFIER.fullmatch(s) for s in segments)
            or any(type(r) is not str or not REFERENCE.fullmatch(r)
                   or r.split(':')[0] not in segments for r in refs)):
        raise ValueError
    gaps = item['missing_information']
    if type(gaps) is not list or len(gaps) > 18 or any(not _text(g, 512) for g in gaps):
        raise ValueError
    return (address, interface), item


def layered_reviews(items, start, end):
    """One deterministic two-family review per address/interface/completed hour.

    Callers supply the current hourly candidates only. No feedback, model text,
    old reviews, learned thresholds or recursively derived reviews are inputs.
    """
    if (type(items) is not list or type(start) not in {int, float}
            or type(end) not in {int, float} or end - start != 3600):
        raise ValueError('Layered review requires one completed hourly candidate list.')
    # utc rejects non-finite / out-of-range timestamps before any grouping.
    utc(start); utc(end)
    groups = defaultdict(list)
    gaps = [LIMIT_GAP] if len(items) > MAX_INPUTS else []
    for item in items[:MAX_INPUTS]:
        try:
            value = _signal(item, start, end)
            if value is not None:
                key, signal = value
                groups[key].append(signal)
        except (KeyError, TypeError, ValueError, OverflowError, OSError, UnicodeError):
            if INVALID_GAP not in gaps:
                gaps.append(INVALID_GAP)
    reviews = []
    for key, signals in sorted(groups.items()):
        ordered = sorted(signals, key=lambda v: (v['rule'], v['sensor'], v['measurement'], v['id']))
        first = ordered[0]
        second = next((v for v in ordered if FAMILIES[v['rule']] != FAMILIES[first['rule']]), None)
        if second is None:
            continue
        if len(reviews) >= MAX_REVIEWS:
            if LIMIT_GAP not in gaps:
                gaps.append(LIMIT_GAP)
            break
        pair = [first, second]
        segments = sorted({s for v in pair for s in v['source_segments']})
        if len(segments) > MAX_DEPENDENCIES:
            if LIMIT_GAP not in gaps:
                gaps.append(LIMIT_GAP)
            continue
        refs = sorted({r for v in pair for r in v['evidence_refs']})
        assert len(refs) <= MAX_REFERENCES
        qualification, qualification_notes = _qualification(pair, start, end)
        facts = dict(window_seconds=3600, relationship='same_address_interface_hour',
            signals=[dict(rule=v['rule'], sensor=v['sensor'], measurement=v['measurement']) for v in pair],
            independent_corroboration=False, attack_sequence_established=False,
            evidence_qualification=qualification)
        source_gaps = list(dict.fromkeys([*qualification_notes,
            *(g for v in pair for g in v['missing_information'])]))
        if len(source_gaps) > 15:
            source_gaps = source_gaps[:14] + ['Additional component coverage notes exceed this combined review; inspect the individual signals.']
        # Keep one component coverage note inside Findings' four-note page,
        # even when both shared support and unavailable timing need disclosure.
        source_gaps.insert(0, BOUNDARY + ' ' + UNKNOWN_AUTHORIZATION)
        review = candidate('LAYERED_ACTIVITY', (*key, 'Separate source-qualified signals', 'signal co-occurrence'),
            start, end, facts, refs, segments, gaps=source_gaps,
            source_start=min(epoch(v['source_start']) for v in pair))
        # Both complete bounded reference lists are retained, not silently cut
        # to the generic candidate's 24-reference display budget.
        review['evidence_refs'] = refs
        review['label'] = 'Layered activity to review'
        review['fingerprint'] = stable(['layered-activity-v1', key, facts['signals']])
        reviews.append(review)
    return reviews, gaps
