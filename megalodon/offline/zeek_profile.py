"""One explicit, digest-bound Zeek 8.0.10 metadata-file admission boundary.

This API checks the declared profile and source bytes; it neither authenticates
an installed producer nor starts Zeek. The generic replay/CLI stays unverified.
"""

from __future__ import annotations

import hashlib
import hmac
from decimal import Decimal
import os
import re
import stat
import time
from types import MappingProxyType
from typing import Mapping

from . import zeek
from .common import (Batch, Limits, OfflineError, _identity, open_input,
                     require_unprivileged_linux)


PRODUCER_PROFILE = 'zeek-8.0.10-conn-json-tsv-v1'
DECLARED_VERSION = '8.0.10'
CONFIGURATION_DIGEST = 'sha256:be7b117ee3a229884e6a6289fc3140ae32373df26a7b58b1616e87ce4092b0ed'
SOURCE_ARCHIVE_DIGEST = 'sha256:dbb1cb6c1eac27a8883ee4bd229a378b2f1253fa18e16cdeaaef8a00f124ddf1'
BINARY_DIGEST = 'sha256:9a373fa2f32469432273af0c793455af59a34195a88beb9963c8d2e0e648f161'
ADMISSION_KEYS = frozenset({
    'producer_profile', 'declared_version', 'format', 'source_archive_digest',
    'binary_digest', 'configuration_digest', 'expected_digest',
    'expected_records', 'source_id', 'run_id',
})
_DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
_IDENTIFIER = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')


def _admission(value: object, limits: Limits) -> dict:
    # Validate and snapshot every declaration before inspecting a source path.
    if (type(value) is not dict or len(value) != len(ADMISSION_KEYS)
            or set(value) != ADMISSION_KEYS):
        raise OfflineError('ZEEK_PROFILE_ADMISSION')
    if any(type(value[k]) is not str for k in ADMISSION_KEYS - {'expected_records'}):
        raise OfflineError('ZEEK_PROFILE_ADMISSION')
    if (value['producer_profile'] != PRODUCER_PROFILE
            or value['declared_version'] != DECLARED_VERSION
            or value['format'] not in ('json', 'tsv')
            or value['source_archive_digest'] != SOURCE_ARCHIVE_DIGEST
            or value['binary_digest'] != BINARY_DIGEST
            or value['configuration_digest'] != CONFIGURATION_DIGEST):
        raise OfflineError('ZEEK_PROFILE_MISMATCH')
    for key in ('configuration_digest', 'expected_digest'):
        if not _DIGEST.fullmatch(value[key]):
            raise OfflineError('ZEEK_PROFILE_DIGEST')
    for key in ('source_id', 'run_id'):
        if not _IDENTIFIER.fullmatch(value[key]):
            raise OfflineError('ZEEK_PROFILE_ADMISSION')
    if (type(value['expected_records']) is not int
            or not 1 <= value['expected_records'] <= limits.records):
        raise OfflineError('ZEEK_PROFILE_RECORD_COUNT')
    return dict(value)


def _tick(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise OfflineError('TIMEOUT')


def _lines(fd: int, limits: Limits, deadline: float, digest):
    total = 0
    with os.fdopen(os.dup(fd), 'rb') as stream:
        while True:
            _tick(deadline)
            raw = stream.readline(limits.line_bytes + 1)
            if not raw:
                return
            total += len(raw)
            if total > limits.input_bytes or len(raw) > limits.line_bytes:
                raise OfflineError('INPUT_SIZE_LIMIT')
            try:
                text = raw.decode('ascii')
            except UnicodeDecodeError:
                raise OfflineError('INVALID_ENCODING') from None
            digest.update(raw)
            yield text.removesuffix('\n')


def read_completed_conn(root: str, relative: str, *, admission: dict,
                        limits: Limits = Limits()) -> tuple[Batch, Mapping]:
    """Read one private completed metadata file, returning only in-memory data.

    Digests and source/run identifiers are operator declarations, not signatures
    or build attestation. No database, report, watcher, network or native process
    is used. File/line/record limits and a cooperative deadline apply; this cannot
    interrupt a stalled kernel read or establish capture completeness.
    """
    if type(limits) is not Limits:
        raise OfflineError('INVALID_LIMIT')
    declared = _admission(admission, limits)
    require_unprivileged_linux()
    deadline = time.monotonic() + limits.timeout_seconds
    digest = hashlib.sha256()
    with open_input(root, relative, limits) as (fd, size):
        source = os.fstat(fd)
        directory = os.stat(root, follow_symlinks=False)
        if (directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) & 0o077
                or source.st_uid != os.geteuid()
                or stat.S_IMODE(source.st_mode) not in (0o400, 0o600)):
            raise OfflineError('PRIVATE_ZEEK_PROFILE_INPUT_REQUIRED')
        stream = _lines(fd, limits, deadline, digest)
        if declared['format'] == 'json':
            parsed = []
            for text in stream:
                if len(parsed) >= limits.records:
                    raise OfflineError('RECORD_LIMIT')
                value = zeek.json_object(text)
                record = zeek.parse_flow(value)
                # The declared default writer omits unset JSON fields. UID and
                # missed_bytes are logged non-optional fields in this profile.
                if (not {'uid', 'missed_bytes'} <= value.keys()
                        or any(v is None for v in value.values())
                        or any(type(v) is not int for k, v in value.items()
                               if zeek.TYPES[k] in ('port', 'count'))
                        or any(not isinstance(v, (int, Decimal)) for k, v in value.items()
                               if zeek.TYPES[k] in ('time', 'interval'))):
                    raise OfflineError('ZEEK_PROFILE_FIELDS')
                parsed.append(record)
            records = tuple(parsed)
        else:
            fields = None
            opened = False

            def observed_headers():
                nonlocal fields, opened
                for text in stream:
                    if text.startswith('#fields\t'):
                        fields = text.split('\t')[1:]
                    if text.startswith('#open\t'):
                        opened = True
                    if not text.startswith('#') and fields == list(zeek.TYPES):
                        values = text.split('\t')
                        if (len(values) == len(fields)
                                and any(values[fields.index(key)] == '-'
                                        for key in ('uid', 'missed_bytes'))):
                            raise OfflineError('ZEEK_PROFILE_FIELDS')
                    yield text

            records = zeek._tsv_records(observed_headers(), limits)
            if not opened or fields != list(zeek.TYPES):
                raise OfflineError('ZEEK_PROFILE_FIELDS')
        _tick(deadline)
        if len(records) != declared['expected_records']:
            raise OfflineError('ZEEK_PROFILE_RECORD_COUNT')
        actual = 'sha256:' + digest.hexdigest()
        if not hmac.compare_digest(actual, declared['expected_digest']):
            raise OfflineError('ZEEK_PROFILE_DIGEST')
        if _identity(os.stat(root, follow_symlinks=False)) != _identity(directory):
            raise OfflineError('INPUT_CHANGED')
        _tick(deadline)
        batch = Batch(zeek.ADAPTERS[declared['format']], 'flow', records,
                      len(records), 0, size, DECLARED_VERSION,
                      'operator_declared_unverified')
    # Return only after open_input's final identity and descriptor-close checks.
    receipt = MappingProxyType({
        'schema': 'zeek-profile-reader-receipt-v1', 'status': 'complete',
        'producer_profile': PRODUCER_PROFILE, 'record_count': len(records),
        'count_unit': 'flow', 'source_digest_status': 'matches_operator_expectation',
        'source_snapshot_status': 'metadata_unchanged_not_atomic',
        'producer_identity_status': 'operator_declared_unverified',
        'native_qualification': 'not_run', 'action_status': 'not_attempted',
        'durable_write_status': 'not_attempted',
        'provenance': MappingProxyType(declared),
    })
    return batch, receipt
