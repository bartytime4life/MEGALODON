"""Bounded display-only executable inspection. No sample content or action authority."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re

MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
MAX_SLICES = 16
REPORT_SCHEMA = 'megalodon-file-inspection-report-v1'
STATUS_SCHEMA = 'megalodon-file-inspection-status-v1'
TOOL_STATES = {'completed', 'unavailable', 'unsupported', 'failed', 'timed_out', 'cancelled'}
CLUES = {
    'writable_executable': ('Writable and executable region',
        'A region can be both written and executed. Some legitimate runtimes need this; review the publisher and purpose.'),
    'packed': ('Packing or protection identified',
        'Packing can make a program harder to inspect. Legitimate software also uses it. This is a clue, not a malware verdict.'),
}
UNKNOWNS = [
    'Static inspection cannot establish whether a file is safe or malicious.',
    'Publisher identity, signature trust and runtime behavior were not verified.',
    'Existing ClamAV scan counts do not establish that this particular file was scanned.',
]
NEXT_STEP = 'Check the download source and publisher. If uncertain, leave the file unopened and seek an independent review.'


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate inspection field.')
        result[key] = value
    return result


def decode(raw):
    if type(raw) is not bytes or len(raw) > MAX_OUTPUT:
        raise ValueError('Inspection output exceeds its limit.')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid number.')))


def fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError('Unsupported inspection fields.')


def count(value, maximum=2147483647, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid inspection count.')


def label(value):
    if (type(value) is not str or not 1 <= len(value) <= 120
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._+()/,:@\-]*', value)):
        raise ValueError('Invalid inspection label.')


def validate_structure(value):
    fields(value, ('format', 'slices_detected', 'slices'))
    if value['format'] not in ('ELF', 'PE', 'Mach-O'):
        raise ValueError('Unsupported executable format.')
    count(value['slices_detected'], MAX_SLICES, 1)
    slices = value['slices']
    if type(slices) is not list or len(slices) != value['slices_detected']:
        raise ValueError('Invalid executable slice coverage.')
    if value['format'] != 'Mach-O' and value['slices_detected'] != 1:
        raise ValueError('Unexpected executable slices.')
    for item in slices:
        fields(item, ('architecture', 'bits', 'sections', 'imports', 'writable_executable'))
        label(item['architecture'])
        if type(item['bits']) is not int or item['bits'] not in (32, 64):
            raise ValueError('Invalid executable bit width.')
        for key in ('sections', 'imports', 'writable_executable'):
            count(item[key])
    return value


def validate_identification(value):
    if type(value) is not list or len(value) > 32:
        raise ValueError('Excessive executable labels.')
    for item in value:
        fields(item, ('kind', 'name'))
        if item['kind'] not in ('compiler', 'packer', 'protector', 'linker'):
            raise ValueError('Unsupported executable label.')
        label(item['name'])
    return value


def validate_report(value):
    fields(value, ('schema', 'inspected_at', 'size_bytes', 'state', 'structure',
                   'identification', 'tools', 'clues', 'unknowns', 'next_step'))
    if value['schema'] != REPORT_SCHEMA or value['state'] not in {
            'completed', 'partial', 'failed', 'cancelled', 'unsupported'}:
        raise ValueError('Unsupported inspection report.')
    stamp = value['inspected_at']
    if type(stamp) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', stamp):
        raise ValueError('Invalid inspection time.')
    datetime.strptime(stamp, '%Y-%m-%dT%H:%M:%SZ')
    count(value['size_bytes'], MAX_INPUT, 1)
    if value['structure'] is not None:
        validate_structure(value['structure'])
    validate_identification(value['identification'])
    if type(value['tools']) is not list or len(value['tools']) != 2:
        raise ValueError('Invalid tool coverage.')
    for item, identifier in zip(value['tools'], ('lief', 'die')):
        fields(item, ('id', 'state'))
        if item['id'] != identifier or item['state'] not in TOOL_STATES:
            raise ValueError('Invalid tool coverage.')
    if type(value['clues']) is not list or len(value['clues']) > 16:
        raise ValueError('Excessive inspection clues.')
    for item in value['clues']:
        fields(item, ('code', 'title', 'meaning'))
        if item['code'] not in CLUES or (item['title'], item['meaning']) != CLUES[item['code']]:
            raise ValueError('Unknown inspection clue.')
    if (value['unknowns'] != UNKNOWNS or value['next_step'] != NEXT_STEP
            or len(json.dumps(value, allow_nan=False).encode()) > MAX_OUTPUT):
        raise ValueError('Unsupported inspection explanation.')
    states = [item['state'] for item in value['tools']]
    if (value['structure'] is not None) != (states[0] == 'completed'):
        raise ValueError('Structure does not match tool coverage.')
    if states[1] != 'completed' and value['identification']:
        raise ValueError('Identification does not match tool coverage.')
    expected = ('cancelled' if 'cancelled' in states else
                'completed' if states == ['completed', 'completed'] else
                'partial' if 'completed' in states else
                'unsupported' if states == ['unsupported', 'unsupported'] else 'failed')
    if value['state'] != expected:
        raise ValueError('Report does not match tool coverage.')
    return value


def report(size, results):
    structure = results[0].get('structure') if results[0]['state'] == 'completed' else None
    identification = results[1].get('identification', []) if results[1]['state'] == 'completed' else []
    states = [r['state'] for r in results]
    state = ('cancelled' if 'cancelled' in states else
             'completed' if states == ['completed', 'completed'] else
             'partial' if 'completed' in states else
             'unsupported' if states == ['unsupported', 'unsupported'] else 'failed')
    clues = []
    if structure and any(s['writable_executable'] for s in structure['slices']):
        clues.append('writable_executable')
    if any(item['kind'] in ('packer', 'protector') for item in identification):
        clues.append('packed')
    value = dict(schema=REPORT_SCHEMA, inspected_at=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                 size_bytes=size, state=state, structure=structure, identification=identification,
                 tools=[dict(id=k, state=r['state']) for k, r in zip(('lief', 'die'), results)],
                 clues=[dict(code=k, title=CLUES[k][0], meaning=CLUES[k][1]) for k in clues],
                 unknowns=list(UNKNOWNS), next_step=NEXT_STEP)
    return validate_report(value)

