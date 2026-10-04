"""Bounded admission of committed endpoint metadata into the pure context contract."""
from hashlib import sha256
from ipaddress import ip_address
import json
import re
import sqlite3

from .ai_context import build_context, ContextError, INPUT_SCHEMA, FACTS, FLAGS, PROTOCOLS, RULES, SOURCE_KINDS, TRANSPORTS
from .evidence_storage import epoch
from .retained_history import RetainedEvidenceReader
from .security_patterns import MAX_RECORDS


def _project(row):
    data = row['data']
    if SOURCE_KINDS.get(row['source']) != row['category']:
        raise ValueError('Unqualified endpoint source')
    # A scope is one application-owned segment and admitted interface. Unknown
    # interfaces stay inside that segment; no cross-segment identity is inferred.
    interface = data.get('interface')
    if interface is None:
        interface = ''
    if type(interface) is not str or not re.fullmatch(r'[A-Za-z0-9_.:-]{0,15}', interface):
        raise ValueError('Unqualified endpoint interface')
    scope = sha256((row['id'].split(':')[0] + ':' + interface).encode()).hexdigest()[:32]
    result = dict(ref=row['id'], source=row['source'], kind=row['category'], scope_id=scope,
                  observed_at=int(epoch(row['observed_at'])), src_ip=str(ip_address(data['src_ip'])),
                  dst_ip=str(ip_address(data['dst_ip'])), missing={})
    protocol = data.get('protocol')
    if type(protocol) is str and protocol in PROTOCOLS:
        result['protocol'] = protocol
    for field in ('src_port', 'dst_port'):
        value = data.get(field)
        if protocol in TRANSPORTS and type(value) is int and 0 <= value <= 65535:
            result[field] = value
    flags = data.get('tcp_flags')
    if type(flags) is str and len(flags) <= 128:
        try:
            flags = json.loads(flags)
        except ValueError:
            flags = None
    if (protocol == 'TCP' and type(flags) is list and len(flags) <= len(FLAGS)
            and all(type(f) is str and f in FLAGS for f in flags) and len(set(flags)) == len(flags)):
        result['tcp_flags'] = flags
    findings = data.get('findings')
    if (row['category'] == 'packets' and type(findings) is list and len(findings) <= 3
            and all(type(f) is dict and type(f.get('id')) is int and 0 < f['id'] < 2**53
                    and type(f.get('rule_id')) is str and f['rule_id'] in RULES for f in findings)):
        result['findings'] = [dict(id=f['id'], rule=f['rule_id']) for f in findings]
    for field in FACTS - result.keys():
        reason = 'not_collected' if data.get(field) is None else 'not_qualified'
        if field == 'findings' and row['category'] == 'flows':
            reason = 'not_qualified'
        if field in {'src_port', 'dst_port'} and protocol in {'ICMP', 'ICMPV6'}:
            reason = 'not_applicable'
        if field == 'tcp_flags' and protocol in {'UDP', 'ICMP', 'ICMPV6', 'SCTP'}:
            reason = 'not_applicable'
        result['missing'][field] = reason
    return result


def _library_references(knowledge, requested=None):
    """Resolve exact identities only from the validated local library API."""
    try:
        members = knowledge.for_pattern('OBSERVED_ACTIVITY')
    except (OSError, ValueError, sqlite3.Error):
        raise ContextError('REFERENCE_UNAVAILABLE') from None
    if type(members) is not list or len(members) > 3:
        raise ContextError('REFERENCE_UNAVAILABLE')
    allowed = {}
    for row in members:
        if type(row) is not dict or any(type(row.get(key)) is not str for key in ('id','source','edition','identifier')):
            raise ContextError('REFERENCE_UNAVAILABLE')
        identity = f"{row['source']}@{row['edition']}:{row['identifier']}"
        if row['id'] != identity or identity in allowed:
            raise ContextError('REFERENCE_UNAVAILABLE')
        allowed[identity] = dict(source=row['source'],edition=row['edition'],id=row['identifier'])
    if requested is None:
        requested = tuple(allowed)
    if (type(requested) is not tuple or len(requested) > 3 or
            any(type(identity) is not str for identity in requested) or len(set(requested)) != len(requested)
            or any(identity not in allowed for identity in requested)):
        raise ContextError('UNKNOWN_REFERENCE')
    return [allowed[identity] for identity in requested]


def retained_context(evidence, address, now, *, comparison_reason=None, references=None, strict_expiry=False):
    """Read at most 20,000 candidates and select at most 24 matching records.

    Use completed integer seconds, never future observations. A size-limited
    prefix is explicitly marked truncated; original evidence is never rewritten.
    Comparisons and reference claims are intentionally unavailable on this path.
    """
    address = str(ip_address(address))
    end = int(now)
    reader = RetainedEvidenceReader(evidence)
    sources, gaps = reader._sources(end - 3600, end, categories={'packets', 'flows'})
    selected, dependencies = [], {}
    scanned = 0
    truncated = False
    missing = {'incomplete_window'}  # Selection does not certify full capture coverage.
    for gap in gaps:
        missing.add(gap if gap == 'sensor_disagreement' else 'source_gap')
    for entry, watermark in reversed(sources):
        expires = int(epoch(entry.get('first_at') or entry['created_at']) + evidence.retention_days * 86400)
        if expires <= now:
            if strict_expiry:
                raise ContextError('SOURCE_EXPIRED')
            missing.add('source_gap')
            continue
        cursor = 0
        try:
            while cursor < watermark:
                pages = reader._pages(entry, watermark, end - 3600, end, after=cursor,
                                      page_size=min(512, MAX_RECORDS-scanned))
                try:
                    page, count = next(pages, ([], 0))
                    cursor = reader.read_cursor
                finally:
                    pages.close()
                if not count:
                    break
                scanned += count
                for row in page:
                    try:
                        if address not in (str(ip_address(row['data'].get('src_ip'))), str(ip_address(row['data'].get('dst_ip')))):
                            continue
                        projected = _project(row)
                        # Validate each row before admitting it; one malformed row
                        # cannot erase other committed observations.
                        dependency = dict(id=entry['id'], kind=entry['category'], expires_at=expires)
                        build_context(dict(schema=INPUT_SCHEMA, subject=address, window=dict(start=end-3600,end=end), as_of=end,
                            sources=[dependency], records=[projected], coverage=dict(truncated=False,missing=[]),
                            comparison=dict(state='unavailable',reason='not_requested'), references=[]))
                    except (ValueError, TypeError, KeyError, OverflowError):
                        missing.add('source_gap')
                        continue
                    selected.append(projected)
                    dependencies[entry['id']] = dependency
                    if len(selected) == 24:
                        break
                if len(selected) == 24 or scanned >= MAX_RECORDS:
                    truncated = True
                    break
        except (OSError, ValueError, sqlite3.Error):
            missing.add('source_gap')
        if truncated:
            break
    while True:
        used = {r['ref'].split(':')[0] for r in selected}
        reasons = sorted(missing | ({'no_qualified_records'} if not selected else set()))
        comparison = ('not_requested' if comparison_reason is None else
                      'truncated' if truncated else
                      'incomplete_hours' if 'source_gap' in reasons or 'sensor_disagreement' in reasons else
                      comparison_reason)
        try:
            return build_context(dict(schema=INPUT_SCHEMA, subject=address, window=dict(start=end-3600,end=end), as_of=end,
                sources=[dependencies[k] for k in sorted(used)], records=selected,
                coverage=dict(truncated=truncated,missing=reasons),
                comparison=dict(state='unavailable',reason=comparison), references=references if references is not None else []))
        except ContextError as exc:
            if exc.code not in {'CONTEXT_TOO_LARGE', 'INPUT_TOO_LARGE'} or not selected:
                raise
            selected.pop()
            truncated = True


def context_available(evidence, context, now):
    """Revalidate actual source units, including policy changes and compaction."""
    if not evidence.enabled:
        return False
    with evidence.lock:
        entries = {e['id']:e for e in evidence._catalog['entries']}
        for dep in context['dependencies']:
            entry = entries.get(dep['id'])
            if (entry is None or entry['state'] not in {'open', 'closed'} or entry.get('compacted_to')
                    or entry['category'] != dep['kind'] or not evidence.derived_available(entry)
                    or dep['expires_at'] <= now
                    or epoch(entry.get('first_at') or entry['created_at']) + evidence.retention_days * 86400 <= now):
                return False
    return True


def facts_text(context):
    if not context['groups']:
        return 'Insufficient context: no qualified retained observations for this address in the selected hour. Safety is unknown.'
    counts = '; '.join(f"{g['source']}: {g['record_count']} {g['measurement'].replace('_', ' ')}" for g in context['groups'])
    return counts + '. Selected records only; complete traffic coverage and safety are unknown.'
