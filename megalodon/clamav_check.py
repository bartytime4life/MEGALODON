"""Operator-requested local scanner test. Only the official 68-byte EICAR fixture is accepted."""
import hashlib
import os
from pathlib import Path
import re
import stat
from tempfile import TemporaryDirectory

from .clamav_summary import MARKER, summarize_report

EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
CONTROL = b'MEGALODON ordinary file for the local scanner check.\n'
SCANNER = '/usr/bin/clamscan'
PREPARE = ('Save the official 68-byte EICAR file as eicar.com in Downloads, then try again. '
           'If another security tool stopped the download, this check could not reach ClamAV.')


def _fixture(home):
    """Pin Downloads and reject links, devices, pipes, and all other content before scanning."""
    directory = os.open(home/'Downloads', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open('eicar.com', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb', buffering=0) as stream:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size != 68:
                raise ValueError(PREPARE)
            data = stream.read(69)
    finally:
        os.close(directory)
    if hashlib.sha256(data).hexdigest() != EICAR_SHA256:
        raise ValueError(PREPARE)
    return data


def _version(run):
    raw, code = run([SCANNER, '--version'], 1024, 15)
    version = re.fullmatch(rb'ClamAV (\d+(?:\.\d+){1,3})/([1-9][0-9]{0,9})/[^\r\n]{1,80}\s*', raw)
    if code or not version:
        raise ValueError('ClamAV or its installed signature database could not be verified.')
    return tuple(field.decode('ascii') for field in version.groups())


def _scan(root, name, data, engine, run):
    path = root/name
    with path.open('xb') as target:
        target.write(data)
    raw, code = run([SCANNER, '--infected', '--', str(path)], 16384, 120)
    summary = summarize_report(raw, code)
    before, _, tail = raw.partition(MARKER.encode())
    if not re.search(rb'^Known viruses: [1-9][0-9]{0,9}\r?$', tail, re.M):
        raise ValueError('The scan did not report loaded signatures.')
    if (summary['engine_version'] != engine or summary['scanned_files'] != 1
            or summary['scanned_directories'] != 0):
        raise ValueError('ClamAV did not report one completed file scan.')
    # An interceptor may remove or replace a fixture. Never call that a missed detection.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb', buffering=0) as target:
        if not stat.S_ISREG(os.fstat(fd).st_mode) or target.read(len(data)+1) != data:
            raise ValueError('The test file changed during the scan.')
    before = before.strip()
    matches = summary['infected_files']
    detection = re.fullmatch(re.escape(os.fsencode(path)) + rb': ([A-Za-z0-9_.-]{1,128}) FOUND', before)
    if (matches and not detection) or (not matches and before):
        raise ValueError('File output and scan counts disagree.')
    return dict(scanned=1, matched=matches), bool(detection and detection[1].lower() == b'eicar-test-signature')


def run_check(home, run):
    result = dict(state='unavailable', message='', engine=None, database=None, clean=None, test=None)
    try:
        fixture = _fixture(home)
    except (OSError, ValueError):
        result['message'] = PREPARE
        return result
    try:
        result['engine'], result['database'] = version = _version(run)
        with TemporaryDirectory(prefix='megalodon-scanner-') as temp:
            root = Path(temp)
            result['clean'], _ = _scan(root, 'ordinary.txt', CONTROL, version[0], run)
            if result['clean']['matched']:
                result['message'] = 'ClamAV flagged the ordinary file. The comparison is unreliable.'
                return result
            result['test'], recognized = _scan(root, 'reference.txt', fixture, version[0], run)
        if _version(run) != version:
            result['message'] = 'ClamAV or its signatures changed during the check. Try again.'
        elif recognized:
            result.update(state='recognized', message='ClamAV recognized the test file and left the ordinary file alone.')
        elif result['test']['matched']:
            result['message'] = 'ClamAV flagged the test file, but the result did not identify EICAR.'
        else:
            result.update(state='missed', message='ClamAV scanned both files and missed the EICAR test file.')
    except (OSError, ValueError):
        result['message'] = 'Could not verify both scans. Check that ClamAV and its signatures are installed and the files stayed available.'
    return result
