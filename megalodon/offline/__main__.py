"""Explicit offline entry point, deliberately independent of live policy settings."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os

from . import tshark, zeek
from .common import Limits, OfflineError, open_input, require_unprivileged_linux
from .reports import finish, manifest, output_directory


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, 'INVALID_ARGUMENTS\n')  # Do not echo untrusted argument values.


def read_reference(root: str, relative: str, limits: Limits) -> dict:
    bounded = replace(limits, input_bytes=min(limits.input_bytes, 1024 * 1024))
    data = bytearray()
    with open_input(root, relative, bounded) as (fd, _):
        while True:
            chunk = os.read(fd, min(65536, bounded.input_bytes - len(data) + 1))
            if not chunk:
                break
            if len(data) + len(chunk) > bounded.input_bytes:
                raise OfflineError('BASELINE_SIZE_LIMIT')
            data.extend(chunk)
    try:
        return zeek.json_object(data.decode('ascii'))
    except UnicodeDecodeError:
        raise OfflineError('INVALID_BASELINE_ENCODING') from None


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description='Bounded offline metadata analysis; local reports only.', allow_abbrev=False)
    parser.add_argument('--source', choices=('tshark', 'zeek-json', 'zeek-tsv'), required=True)
    parser.add_argument('--input-root', required=True, help='Absolute local directory; no symlink components.')
    parser.add_argument('--input', required=True, help='Relative file below input-root.')
    parser.add_argument('--output', required=True, help='Absolute NEW private report directory.')
    parser.add_argument('--case', required=True, help='Non-sensitive case identifier, beginning with a letter.')
    parser.add_argument('--zeek-version', help='Required operator-declared producer version for Zeek input.')
    parser.add_argument('--reference-baseline', help='Optional baseline.json relative to input-root.')
    parser.add_argument('--max-records', type=int, default=10_000)
    parser.add_argument('--timeout', type=int, default=30)
    args = parser.parse_args(argv)
    saved = False
    failure = None
    receipt = None
    try:
        require_unprivileged_linux()
        limits = Limits(records=args.max_records, timeout_seconds=args.timeout)
        receipt = manifest(args.case, args.source, limits)
        if (args.source == 'tshark') == (args.zeek_version is not None):
            raise OfflineError('INVALID_VERSION_ARGUMENT')
        with output_directory(args.output) as directory:
            try:
                if args.source == 'tshark':
                    batch = tshark.replay(args.input_root, args.input, limits)
                else:
                    batch = zeek.replay(args.input_root, args.input, format=args.source.removeprefix('zeek-'),
                                        producer_version=args.zeek_version, limits=limits)
                reference = (read_reference(args.input_root, args.reference_baseline, limits)
                             if args.reference_baseline else None)
                finish(directory, receipt, limits, batch=batch, reference=reference)
                saved = True
            except (OfflineError, OSError) as exc:
                failure = str(exc) if isinstance(exc, OfflineError) else 'LOCAL_IO_ERROR'
                finish(directory, receipt, limits, failure=failure)
                saved = True
    except (OfflineError, OSError) as exc:
        failure = str(exc) if isinstance(exc, OfflineError) else 'LOCAL_IO_ERROR'
    summary = {'status': 'failed' if failure else 'complete', 'manifest_written': saved,
               'accepted_records': receipt['accepted_records'] if saved else 0,
               'candidate_count': receipt['candidate_count'] if saved else 0,
               'action_status': 'not_attempted'}
    if failure:
        summary['failure_code'] = failure
    print(json.dumps(summary, sort_keys=True))
    return 1 if failure else 0


if __name__ == '__main__':
    raise SystemExit(main())
