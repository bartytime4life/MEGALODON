"""Private, local-only reports; a complete manifest is the commit marker."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
from datetime import datetime, timezone
import csv
import io
import json
import os
import re
import uuid
from typing import Iterator

from .analysis import baseline, candidates, redacted_records
from .common import Batch, Limits, OfflineError, _parts, open_directory

REPORT_NAMES = ('records.jsonl', 'records.csv', 'baseline.json', 'candidates.jsonl')
COLUMNS = ('record', 'record_kind', 'offset_us', 'src', 'dst', 'protocol', 'src_port',
           'dst_port', 'byte_count', 'tcp_flags', 'orig_packets', 'resp_packets',
           'duration_us', 'conn_state')


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def case_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,47}', value):
        raise OfflineError('INVALID_CASE_ID')
    return value


def manifest(case: str, source: str, limits: Limits) -> dict:
    return {'schema': 'offline-run-v1', 'run_id': uuid.uuid4().hex,
            'case_id': case_id(case), 'source': source,
            'started_at': datetime.now(timezone.utc).isoformat(), 'status': 'failed',
            'limits': asdict(limits),
            'version_probe_limits': ({'timeout_seconds': 5, 'stdout_bytes': 8192, 'stderr_bytes': 4096}
                                     if source == 'tshark' else None),
            'accepted_records': 0, 'rejected_records': None,
            'candidate_count': 0, 'action_status': 'not_attempted',
            'egress': 'not_implemented_policy_required', 'capture_hash': 'not_computed',
            'redaction': 'run_local_rank_labels_relative_time_v1', 'reports': []}


@contextmanager
def output_directory(path: str) -> Iterator[int]:
    """New directory only; retain a descriptor rather than re-resolving paths."""
    parts = _parts(path, absolute=True)
    if not parts:
        raise OfflineError('INVALID_OUTPUT_PATH')
    parent = open_directory('/' + '/'.join(parts[:-1]))
    directory = None
    try:
        os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
        directory = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=parent)
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise OfflineError('PRIVATE_OUTPUT_REQUIRED')
        yield directory
    except OSError:
        raise OfflineError('OUTPUT_IO_ERROR') from None
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def _write(directory: int, name: str, content: bytes) -> None:
    if name not in (*REPORT_NAMES, 'manifest.json'):
        raise OfflineError('INVALID_REPORT_NAME')
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=directory)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def finish(directory: int, receipt: dict, limits: Limits, *, batch: Batch | None = None,
           reference: dict | None = None, failure: str | None = None) -> dict:
    """Do not expose partial records on failed analysis; publish the manifest last."""
    content = {}
    if failure is None and batch is not None:
        findings = candidates(batch, reference)
        rows = redacted_records(batch)
        text = io.StringIO(newline='')
        writer = csv.DictWriter(text, fieldnames=COLUMNS, lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)  # Only typed numbers, fixed enums, and generated labels.
        content = {'records.jsonl': b''.join(json_bytes(row) for row in rows),
                   'records.csv': text.getvalue().encode('ascii'),
                   'baseline.json': json_bytes(baseline(batch)),
                   'candidates.jsonl': b''.join(json_bytes(item) for item in findings)}
        receipt.update(status='complete', accepted_records=len(batch.records), rejected_records=0,
                       scanned_records=batch.scanned, skipped_unsupported_records=batch.skipped,
                       input_bytes=batch.input_bytes, adapter=batch.adapter, record_kind=batch.kind,
                       tool_version=batch.tool_version, tool_version_basis=batch.version_basis,
                       byte_count_basis='frame_length' if batch.kind == 'packet' else 'orig_plus_resp_ip_bytes',
                       candidate_count=len(findings), reference_baseline_used=reference is not None,
                       reports=list(REPORT_NAMES))
    else:
        receipt.update(status='failed', failure_code=failure or 'NO_BATCH', reports=[],
                       accepted_records=0, rejected_records=None, candidate_count=0)
    receipt['ended_at'] = datetime.now(timezone.utc).isoformat()
    receipt_bytes = json_bytes(receipt)
    if len(receipt_bytes) + sum(map(len, content.values())) > limits.report_bytes:
        raise OfflineError('REPORT_SIZE_LIMIT')
    written = []
    try:
        for name, data in content.items():
            written.append(name)
            _write(directory, name, data)
        written.append('manifest.json')
        _write(directory, 'manifest.json', receipt_bytes)
        os.fsync(directory)
    except OSError:
        # Only our fixed report names in our new private directory; never follow user paths.
        for name in written:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        raise OfflineError('REPORT_IO_ERROR') from None
    return receipt
