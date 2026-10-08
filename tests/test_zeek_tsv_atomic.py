"""Synthetic whole-file TSV evidence; no selected-producer qualification.

Uses unittest so the bounded regressions also run without third-party packages.
The Linux privilege precondition is stubbed as in test_offline.py; these tests
prove importer/report behavior, not native process containment or host acceptance.
"""

from collections import Counter
from contextlib import ExitStack, contextmanager, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from megalodon.offline import __main__ as offline_cli, reports, zeek
from megalodon.offline.common import OfflineError


FIXTURE = Path(__file__).parent / 'fixtures' / 'zeek_tsv_atomic' / 'mixed-protocol.tsv'


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor-relative offline replay')
class ZeekTsvAtomicTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='megalodon-zeek-atomic-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'conn.log'
        self.original = FIXTURE.read_bytes()
        self.assertEqual(hashlib.sha256(self.original).hexdigest(),
                         'eb66f58142f8a2f2dd033b1f55e7ad67896d3085f2d6343c82481b0172d58739')
        # The negative row is last, after all 26 valid connection records.
        lines = self.original.splitlines(keepends=True)
        self.valid = b''.join(lines[:-2] + lines[-1:])

    @contextmanager
    def offline_only(self):
        writes = []
        real_open = os.open

        def observe_open(path, flags, *args, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                writes.append(path)
            return real_open(path, flags, *args, **kwargs)

        # Tripwires execute around the real replay and report entry points.
        forbidden = (
            'socket.socket', 'socket.getaddrinfo', 'socket.gethostbyname',
            'socket.gethostbyname_ex', 'subprocess.Popen', 'subprocess.run',
            'os.system', 'os.popen', 'os.kill', 'os.killpg',
            'os.fork', 'os.posix_spawn', 'os.posix_spawnp',
            'sqlite3.connect', 'threading.Thread.start',
            'multiprocessing.process.BaseProcess.start',
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(zeek, 'require_unprivileged_linux'))
            stack.enter_context(patch.object(offline_cli, 'require_unprivileged_linux'))
            stack.enter_context(patch.object(os, 'open', side_effect=observe_open))
            for target in forbidden:
                guard = stack.enter_context(patch(target, side_effect=AssertionError(target)))
                stack.callback(guard.assert_not_called)
            yield writes

    def assert_source_unchanged(self, expected, before):
        self.assertEqual(self.source.read_bytes(), expected)
        after = self.source.stat()
        for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            self.assertEqual(getattr(after, name), getattr(before, name), name)
        self.assertEqual(FIXTURE.read_bytes(), self.original)

    def args(self, output):
        return ['--source', 'zeek-tsv', '--input-root', str(self.root),
                '--input', 'conn.log', '--output', str(output), '--case', 'synthetic1',
                '--zeek-version', '8.0.10']

    def assert_failed_run(self, data, code, name='run'):
        self.source.write_bytes(data)
        before = self.source.stat()
        output = self.root / name
        stdout = io.StringIO()
        with self.offline_only() as writes, redirect_stdout(stdout):
            self.assertEqual(offline_cli.main(self.args(output)), 1)
        self.assertEqual(json.loads(stdout.getvalue()), {
            'status': 'failed', 'manifest_written': True, 'accepted_records': 0,
            'candidate_count': 0, 'action_status': 'not_attempted', 'failure_code': code,
        })
        self.assertEqual(writes, ['manifest.json'])
        self.assertEqual({p.name for p in output.iterdir()}, {'manifest.json'})
        self.assertEqual({p.name for p in self.root.iterdir()}, {'conn.log', name})
        receipt = json.loads((output / 'manifest.json').read_bytes())
        self.assertEqual(receipt['status'], 'failed')
        self.assertEqual(receipt['failure_code'], code)
        self.assertEqual(receipt['accepted_records'], 0)
        self.assertIsNone(receipt['rejected_records'])
        self.assertEqual(receipt['candidate_count'], 0)
        self.assertEqual(receipt['reports'], [])
        self.assertEqual(receipt['action_status'], 'not_attempted')
        self.assert_source_unchanged(data, before)
        return receipt

    def test_valid_prefix_is_an_unverified_synthetic_positive_control(self):
        self.source.write_bytes(self.valid)
        before = self.source.stat()
        output = self.root / 'run'
        stdout = io.StringIO()
        with self.offline_only() as writes, redirect_stdout(stdout):
            batch = zeek.replay(str(self.root), 'conn.log', format='tsv', producer_version='8.0.10')
            self.assertEqual(offline_cli.main(self.args(output)), 0)
        self.assertEqual(Counter(r.protocol for r in batch.records),
                         {'TCP': 13, 'UDP': 11, 'ICMP': 2})
        self.assertEqual(batch.scanned, 26)
        self.assertEqual(batch.skipped, 0)
        self.assertEqual(batch.tool_version, '8.0.10')
        self.assertEqual(batch.version_basis, 'operator_declared_unverified')
        receipt = json.loads((output / 'manifest.json').read_bytes())
        self.assertEqual(receipt['status'], 'complete')
        self.assertEqual(receipt['accepted_records'], 26)
        self.assertEqual(receipt['tool_version_basis'], 'operator_declared_unverified')
        self.assertEqual(set(writes), {*reports.REPORT_NAMES, 'manifest.json'})
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'complete')
        self.assert_source_unchanged(self.valid, before)

    def test_mixed_protocol_replay_refuses_the_complete_input(self):
        self.source.write_bytes(self.original)
        before = self.source.stat()
        with self.offline_only() as writes:
            with self.assertRaises(OfflineError) as caught:
                zeek.replay(str(self.root), 'conn.log', format='tsv', producer_version='8.0.10')
        self.assertEqual(str(caught.exception), 'UNSUPPORTED_ZEEK_PROTOCOL')
        self.assertEqual(writes, [])
        self.assertEqual({p.name for p in self.root.iterdir()}, {'conn.log'})
        self.assert_source_unchanged(self.original, before)

    def test_mixed_protocol_cli_publishes_only_a_failed_manifest(self):
        self.assert_failed_run(self.original, 'UNSUPPORTED_ZEEK_PROTOCOL')

    def test_missing_close_after_valid_records_cannot_publish_success(self):
        data = b''.join(self.valid.splitlines(keepends=True)[:-1])
        self.assert_failed_run(data, 'INCOMPLETE_ZEEK_LOG')

    def test_malformed_terminal_record_cannot_publish_the_valid_prefix(self):
        lines = self.original.splitlines(keepends=True)
        # A truncated final row, with no closing header, follows the valid prefix.
        data = b''.join(lines[:-2]) + b'1788710426\tsynthetic027\t192.0.2.10\n'
        self.assert_failed_run(data, 'ZEEK_COLUMN_MISMATCH')

    def interrupted_lines(self, error):
        real_lines = zeek.lines

        def stream(fd, limits):
            for text in real_lines(fd, limits):
                # Interrupt only after all valid rows traversed the real reader.
                if text.startswith('#close\t'):
                    raise error
                yield text
        return patch.object(zeek, 'lines', stream)

    def test_read_error_after_valid_records_publishes_only_failure(self):
        with self.interrupted_lines(OSError('synthetic read interruption')):
            self.assert_failed_run(self.valid, 'INPUT_IO_ERROR')

    def test_keyboard_interrupt_after_valid_records_never_commits_reports(self):
        self.source.write_bytes(self.valid)
        before = self.source.stat()
        output = self.root / 'run'
        stdout = io.StringIO()
        with self.offline_only() as writes, redirect_stdout(stdout):
            with self.interrupted_lines(KeyboardInterrupt()):
                with self.assertRaises(KeyboardInterrupt):
                    offline_cli.main(self.args(output))
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(writes, [])
        self.assertEqual(list(output.iterdir()), [])
        self.assert_source_unchanged(self.valid, before)


if __name__ == '__main__':
    unittest.main()
