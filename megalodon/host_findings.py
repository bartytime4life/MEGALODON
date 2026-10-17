"""Bounded local audit observations. These are never detector/action records."""
from datetime import datetime, timedelta, timezone
import hashlib
import re

SCHEMA = 'megalodon-host-review-v1'
MAX_ITEMS = 16
MAX_OBSERVATIONS = 10_000
REPORTS = {'audit': 'lynis-report.dat', 'integrity': 'aide-report.txt'}
KINDS = {'warning': 'configuration_warning', 'suggestion': 'configuration_suggestion'}


def _text(value, maximum):
    return type(value) is str and 0 < len(value) <= maximum and value.isprintable() and len(value.encode('utf-8')) <= maximum


def _date(value):
    if type(value) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value):
        raise ValueError('Invalid host observation time.')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def _digest(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def lynis_review(raw):
    """Keep IDs/descriptions only; never expose tool-provided commands or URLs."""
    metrics = dict(warnings=0, suggestions=0)
    selected = {kind: [] for kind in KINDS}
    versions = {}
    # split on LF, not splitlines(): embedded control characters must be refused.
    for number, line in enumerate(raw.decode('utf-8').split('\n'), 1):
        for key, expected in (('report_version_major', '1'), ('report_version_minor', '0')):
            if line.startswith(key + '='):
                if key in versions or line != key + '=' + expected:
                    raise ValueError('Unsupported Lynis report version.')
                versions[key] = expected
        for kind, category in KINDS.items():
            prefix = kind + '[]='
            if not line.startswith(prefix):
                continue
            if len(line) > 4096 or not line.isprintable():
                raise ValueError('Invalid Lynis finding line.')
            fields = line[len(prefix):].split('|')
            if len(fields) == 5 and fields[-1] == '':
                fields.pop()  # Lynis also emits a terminal field separator.
            if (len(fields) != 4 or not re.fullmatch(r'[A-Z][A-Z0-9-]{0,31}', fields[0])
                    or not _text(fields[1], 240)):
                raise ValueError('Unsupported Lynis finding format.')
            metrics[kind + 's'] += 1
            if sum(metrics.values()) > MAX_OBSERVATIONS:
                raise ValueError('Too many Lynis observations.')
            if len(selected[kind]) < MAX_ITEMS:
                selected[kind].append(dict(kind=category, rule=fields[0], text=fields[1], line=number))
    if len(versions) != 2:
        raise ValueError('Lynis report version is missing.')
    items = (selected['warning'] + selected['suggestion'])[:MAX_ITEMS]
    return metrics, dict(schema=SCHEMA, operation='audit', report_sha256=hashlib.sha256(raw).hexdigest(),
                         items=items, omitted=sum(metrics.values()) - len(items))


def aide_review(raw, operation, baseline, code):
    return dict(schema=SCHEMA, operation=operation, report_sha256=hashlib.sha256(raw).hexdigest(),
                baseline_created_at=baseline['created_at'], baseline_sha256=baseline['sha256'], exit_code=code)


def validate_summary(source, value, now):
    """Admit legacy aggregate summaries without inventing missing provenance."""
    fields = {'checked_at', 'message', 'metrics'}
    if type(value) is not dict or set(value) not in (fields, fields | {'review'}):
        raise ValueError('Invalid host summary fields.')
    observed = _date(value['checked_at'])
    if observed > now + timedelta(minutes=5) or not _text(value['message'], 512):
        raise ValueError('Invalid host summary time or text.')
    metrics = value['metrics']
    expected = {'warnings', 'suggestions'} if source == 'audit' else {'added_detected', 'removed_detected', 'changed_detected'}
    maximum = MAX_OBSERVATIONS if source == 'audit' else 1
    if (type(metrics) is not dict or set(metrics) != expected
            or any(type(v) is not int or not 0 <= v <= maximum for v in metrics.values())
            or (source == 'audit' and sum(metrics.values()) > MAX_OBSERVATIONS)):
        raise ValueError('Invalid host summary metrics.')
    review = value.get('review')
    if 'review' not in value:
        return
    if type(review) is not dict or review.get('schema') != SCHEMA or not _digest(review.get('report_sha256')):
        raise ValueError('Invalid host review identity.')
    common = {'schema', 'operation', 'report_sha256'}
    if source == 'audit':
        if (set(review) != common | {'items', 'omitted'} or review['operation'] != 'audit'
                or type(review['items']) is not list or len(review['items']) > MAX_ITEMS
                or type(review['omitted']) is not int or review['omitted'] < 0
                or len(review['items']) != min(MAX_ITEMS, sum(metrics.values()))
                or len(review['items']) + review['omitted'] != sum(metrics.values())):
            raise ValueError('Invalid Lynis review bounds.')
        lines = set()
        counts = dict.fromkeys(KINDS.values(), 0)
        for item in review['items']:
            if (type(item) is not dict or set(item) != {'kind', 'rule', 'text', 'line'}
                    or type(item['kind']) is not str or item['kind'] not in counts
                    or type(item['rule']) is not str or not re.fullmatch(r'[A-Z][A-Z0-9-]{0,31}', item['rule'])
                    or not _text(item['text'], 240) or type(item['line']) is not int
                    or not 1 <= item['line'] <= 12 * 1024 * 1024 or item['line'] in lines):
                raise ValueError('Invalid Lynis review item.')
            lines.add(item['line'])
            counts[item['kind']] += 1
        if counts['configuration_warning'] > metrics['warnings'] or counts['configuration_suggestion'] > metrics['suggestions']:
            raise ValueError('Contradictory Lynis counts.')
    else:
        if (set(review) != common | {'baseline_created_at', 'baseline_sha256', 'exit_code'}
                or type(review['exit_code']) is not int or not 0 <= review['exit_code'] <= 7
                or any(metrics[key] != int(bool(review['exit_code'] & bit)) for key, bit in
                       [('added_detected', 1), ('removed_detected', 2), ('changed_detected', 4)])
                or review['operation'] not in ('baseline', 'check') or not _digest(review['baseline_sha256'])
                or _date(review['baseline_created_at']) > observed
                or (review['operation'] == 'baseline' and any(metrics.values()))):
            raise ValueError('Invalid AIDE comparison identity.')
