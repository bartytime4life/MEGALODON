"""Digest-bound synthetic JSON/TSV evidence for #445, not native qualification.

Run with stdlib unittest when pytest is unavailable. Privilege checks are
stubbed as in test_offline.py; tripwires prove exercised Python paths only.
"""

from contextlib import ExitStack, contextmanager, redirect_stdout
from dataclasses import asdict
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
from megalodon.offline.common import Batch, Limits, OfflineError
from megalodon.offline_projection import load_offline_projection


PACKET = (Path(__file__).parents[1] / 'contracts' / 'zeek-conn-log' / 'v1'
          / 'qualification')
FILES = ('fixtures/accepted.jsonl', 'fixtures/accepted.tsv', 'fixtures/rejected.json')
UNVERIFIED = {'status': 'unverified', 'producer_profile': 'not_qualified',
              'completeness': 'not_attested'}


def packet():
    manifest = json.loads((PACKET / 'manifest.json').read_bytes())
    assert [item['path'] for item in manifest['files']] == list(FILES)
    for item in manifest['files']:
        data = (PACKET / item['path']).read_bytes()
        assert len(data) == item['size_bytes'], item['path']
        assert hashlib.sha256(data).hexdigest() == item['sha256'], item['path']
    return manifest


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor-relative replay')
class ZeekCandidatePacketTests(unittest.TestCase):
    def setUp(self):
        self.manifest = packet()
        self.originals = {path: (PACKET / path).read_bytes() for path in FILES}
        self.rejected = json.loads(self.originals['fixtures/rejected.json'])
        self.temporary = tempfile.TemporaryDirectory(prefix='megalodon-zeek-packet-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'conn.log'

    @contextmanager
    def offline_only(self, output=None):
        """Permit only report writes in the one explicit disposable directory."""
        writes = []
        writable_fds = {}
        real_open, real_mkdir = os.open, os.mkdir

        def checked_open(path, flags, *args, **kwargs):
            if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
                self.assertIsNotNone(output)
                self.assertIn(path, (*reports.REPORT_NAMES, 'manifest.json'))
                target = os.fstat(kwargs['dir_fd'])
                expected = output.stat()
                self.assertEqual((target.st_dev, target.st_ino),
                                 (expected.st_dev, expected.st_ino))
                writes.append(path)
            fd = real_open(path, flags, *args, **kwargs)
            if flags & (os.O_WRONLY | os.O_RDWR):
                info = os.fstat(fd)
                writable_fds[fd] = (info.st_dev, info.st_ino)
            return fd

        def checked_mkdir(path, *args, **kwargs):
            self.assertIsNotNone(output)
            self.assertEqual(path, output.name)
            target = os.fstat(kwargs['dir_fd'])
            expected = self.root.stat()
            self.assertEqual((target.st_dev, target.st_ino),
                             (expected.st_dev, expected.st_ino))
            return real_mkdir(path, *args, **kwargs)

        def read_only_open(real):
            def checked(file, mode='r', *args, **kwargs):
                if any(flag in mode for flag in 'wax+'):
                    self.assertIs(type(file), int)
                    self.assertIn(file, writable_fds)
                    info = os.fstat(file)
                    self.assertEqual((info.st_dev, info.st_ino), writable_fds[file])
                return real(file, mode, *args, **kwargs)
            return checked

        forbidden = (
            'socket.socket', 'socket.getaddrinfo', 'socket.gethostbyname',
            'socket.gethostbyname_ex', 'socket.gethostbyaddr',
            'subprocess.Popen', 'subprocess.run', 'os.system', 'os.popen',
            'os.kill', 'os.killpg', 'os.fork', 'os.posix_spawn', 'os.posix_spawnp',
            'os.execl', 'os.execle', 'os.execlp', 'os.execlpe', 'os.execv',
            'os.execve', 'os.execvp', 'os.execvpe', 'sqlite3.connect',
            'threading.Thread.start', 'multiprocessing.process.BaseProcess.start',
            'os.unlink', 'os.remove', 'os.rename', 'os.replace', 'os.link',
            'os.symlink', 'os.chmod', 'os.chown', 'os.utime',
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(zeek, 'require_unprivileged_linux'))
            stack.enter_context(patch.object(offline_cli, 'require_unprivileged_linux'))
            stack.enter_context(patch.object(os, 'open', side_effect=checked_open))
            stack.enter_context(patch.object(os, 'mkdir', side_effect=checked_mkdir))
            stack.enter_context(patch('builtins.open', side_effect=read_only_open(open)))
            stack.enter_context(patch('io.open', side_effect=read_only_open(io.open)))
            for target in forbidden:
                guard = stack.enter_context(patch(target, side_effect=AssertionError(target)))
                stack.callback(guard.assert_not_called)
            yield writes

    def unchanged(self, data, before):
        self.assertEqual(self.source.read_bytes(), data)
        after = self.source.stat()
        for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'):
            self.assertEqual(getattr(before, key), getattr(after, key), key)
        for path, original in self.originals.items():
            self.assertEqual((PACKET / path).read_bytes(), original)

    def replay(self, data, format, limits=Limits()):
        self.source.write_bytes(data)
        before = self.source.stat()
        try:
            with self.offline_only() as writes:
                batch = zeek.replay(str(self.root), 'conn.log', format=format,
                                    producer_version='8.0.10', limits=limits)
            self.assertEqual(writes, [])
            return batch
        finally:
            self.unchanged(data, before)

    def cli(self, data, format, name, version='8.0.10'):
        self.source.write_bytes(data)
        before = self.source.stat()
        output = self.root / name
        stdout = io.StringIO()
        with self.offline_only(output) as writes, redirect_stdout(stdout):
            code = offline_cli.main([
                '--source', 'zeek-' + format, '--input-root', str(self.root),
                '--input', 'conn.log', '--output', str(output), '--case', 'synthetic1',
                '--zeek-version', version,
            ])
        self.unchanged(data, before)
        receipt = json.loads((output / 'manifest.json').read_bytes())
        return code, json.loads(stdout.getvalue()), receipt, output, writes

    def test_packet_preserves_the_selected_candidate_and_unmet_native_gates(self):
        self.assertEqual(self.manifest['candidate_version'], '8.0.10')
        self.assertEqual(self.manifest['evidence_basis'], 'synthetic_metadata_only')
        self.assertEqual(self.manifest['qualification_status'], 'NOT_QUALIFIED')
        self.assertEqual(self.manifest['native_fixture_generation'], 'NOT_RUN')
        self.assertEqual(self.manifest['installed_producer_parity'], 'NOT_RUN')
        self.assertEqual(self.manifest['source_to_binary_chain'], 'UNKNOWN')
        self.assertEqual(self.manifest['loaded_scripts_and_writer_settings'], 'UNKNOWN')
        producer = json.loads((PACKET.parent / 'producer' / 'schema.json').read_bytes())
        admission = producer['$defs']['admission']['properties']
        self.assertTrue(admission['producer_profile']['const'].startswith('zeek-PLACEHOLDER-'))
        self.assertEqual(self.manifest['field_order'], list(zeek.TYPES))
        self.assertEqual(self.manifest['field_types'], list(zeek.TYPES.values()))
        self.assertEqual(self.manifest['negative_case_count'], len(self.rejected))
        self.assertEqual(len({case['id'] for case in self.rejected}), len(self.rejected))

    def test_positive_json_tsv_have_exact_normalized_time_counter_and_icmp_parity(self):
        batches = [self.replay(self.originals['fixtures/accepted.' + extension], format)
                   for format, extension in (('json', 'jsonl'), ('tsv', 'tsv'))]
        self.assertEqual(batches[0].records, batches[1].records)
        actual = []
        for record in batches[0].records:
            value = asdict(record)
            value['observed_at'] = record.observed_at.isoformat()
            actual.append(value)
        self.assertEqual(actual, self.manifest['expected_records'])
        self.assertEqual([r.duration_us for r in batches[0].records], [1, 2500000, None, 0])
        for batch in batches:
            self.assertEqual((batch.kind, batch.scanned, batch.skipped), ('flow', 4, 0))
            self.assertEqual(batch.version_basis, 'operator_declared_unverified')

    def test_all_negative_cases_refuse_the_whole_replay_with_exact_codes(self):
        for case in self.rejected:
            with self.subTest(case=case['id']):
                with self.assertRaises(OfflineError) as caught:
                    self.replay(case['raw'].encode('ascii'), case['format'])
                self.assertEqual(str(caught.exception), case['code'])

    def test_negative_cli_cases_publish_only_failure_never_an_accepted_prefix(self):
        for index, case in enumerate(self.rejected):
            with self.subTest(case=case['id']):
                code, summary, receipt, output, writes = self.cli(
                    case['raw'].encode('ascii'), case['format'], 'failure' + str(index))
                self.assertEqual(code, 1)
                self.assertEqual(summary['failure_code'], case['code'])
                self.assertEqual(receipt['failure_code'], case['code'])
                self.assertEqual(writes, ['manifest.json'])
                self.assertEqual({p.name for p in output.iterdir()}, {'manifest.json'})
                for item in (summary, receipt):
                    self.assertEqual(item['status'], 'failed')
                    self.assertEqual(item['accepted_records'], 0)
                    self.assertEqual(item['candidate_count'], 0)
                    self.assertEqual(item['action_status'], 'not_attempted')
                self.assertEqual(receipt['reports'], [])
                self.assertIsNone(receipt['rejected_records'])

    def test_successful_cli_reports_match_across_formats_and_remain_unverified(self):
        outputs = []
        for format, extension in (('json', 'jsonl'), ('tsv', 'tsv')):
            code, summary, receipt, output, writes = self.cli(
                self.originals['fixtures/accepted.' + extension], format, 'success' + format)
            self.assertEqual(code, 0)
            self.assertEqual(summary['accepted_records'], 4)
            self.assertEqual(receipt['tool_version_basis'], 'operator_declared_unverified')
            self.assertEqual(receipt['source_quality'], UNVERIFIED)
            self.assertEqual(summary['source_quality'], UNVERIFIED)
            self.assertEqual(receipt['byte_count_basis'], 'orig_plus_resp_ip_bytes')
            self.assertEqual(receipt['action_status'], 'not_attempted')
            self.assertEqual(set(writes), {*reports.REPORT_NAMES, 'manifest.json'})
            self.assertEqual(writes[-1], 'manifest.json')
            with self.offline_only():
                projection = load_offline_projection(output)
            self.assertEqual(projection['run']['accepted_records'], 4)
            outputs.append(output)
        for name in ('records.jsonl', 'records.csv', 'candidates.jsonl'):
            self.assertEqual((outputs[0] / name).read_bytes(), (outputs[1] / name).read_bytes())

    def test_record_limit_after_a_valid_prefix_cannot_return_a_batch(self):
        for format, extension in (('json', 'jsonl'), ('tsv', 'tsv')):
            with self.subTest(format=format), self.assertRaisesRegex(OfflineError, '^RECORD_LIMIT$'):
                self.replay(self.originals['fixtures/accepted.' + extension], format, Limits(records=3))

    def test_tshark_packet_report_does_not_inherit_zeek_qualification_fields(self):
        batch = Batch('tshark-fields-v1', 'packet', (), 0, 0, 1, '4.2.2', 'subprocess_version')
        output = self.root / 'packet'
        with self.offline_only(output):
            with reports.output_directory(str(output)) as directory:
                receipt = reports.finish(directory, reports.manifest('synthetic1', 'tshark', Limits()),
                                         Limits(), batch=batch)
        self.assertNotIn('source_quality', receipt)
        with self.offline_only():
            self.assertEqual(load_offline_projection(output)['run']['source'], 'tshark')
        path = output / 'manifest.json'
        path.write_bytes(reports.json_bytes({**receipt, 'source_quality': UNVERIFIED}))
        with self.offline_only(), self.assertRaisesRegex(OfflineError, '^INVALID_OFFLINE_MANIFEST$'):
            load_offline_projection(output)

    def test_projection_accepts_legacy_zeek_and_refuses_false_quality_claims(self):
        _, _, receipt, output, _ = self.cli(
            self.originals['fixtures/accepted.jsonl'], 'json', 'projection')
        path = output / 'manifest.json'
        legacy = dict(receipt)
        del legacy['source_quality']
        path.write_bytes(reports.json_bytes(legacy))
        with self.offline_only():
            self.assertEqual(load_offline_projection(output)['run']['accepted_records'], 4)
        for quality in (None, 'healthy', [], {},
                        {**UNVERIFIED, 'status': 'healthy'},
                        {**UNVERIFIED, 'producer_profile': 'qualified'},
                        {**UNVERIFIED, 'completeness': 'complete'},
                        {**UNVERIFIED, 'unknown': 'field'}):
            with self.subTest(quality=quality):
                path.write_bytes(reports.json_bytes({**receipt, 'source_quality': quality}))
                with self.offline_only(), self.assertRaisesRegex(OfflineError, '^INVALID_OFFLINE_MANIFEST$'):
                    load_offline_projection(output)

    def test_unknown_declared_version_is_not_promoted_to_a_qualified_profile(self):
        for format, extension in (('json', 'jsonl'), ('tsv', 'tsv')):
            code, summary, receipt, _, _ = self.cli(
                self.originals['fixtures/accepted.' + extension], format, 'unknown' + format, '9.9.9')
            self.assertEqual(code, 0)
            self.assertEqual(receipt['tool_version'], '9.9.9')
            self.assertEqual(receipt['tool_version_basis'], 'operator_declared_unverified')
            self.assertEqual(receipt['source_quality'], UNVERIFIED)
            self.assertEqual(summary['source_quality'], UNVERIFIED)

    def test_line_aligned_json_truncation_has_no_producer_completeness_attestation(self):
        original = self.originals['fixtures/accepted.jsonl']
        shortened = b''.join(original.splitlines(keepends=True)[:-1])
        self.assertNotEqual(hashlib.sha256(shortened).digest(), hashlib.sha256(original).digest())
        batch = self.replay(shortened, 'json')
        self.assertEqual(batch.scanned, 3)
        self.assertEqual(batch.version_basis, 'operator_declared_unverified')
        code, summary, receipt, _, _ = self.cli(shortened, 'json', 'shortened')
        self.assertEqual(code, 0)
        self.assertEqual(receipt['accepted_records'], 3)
        self.assertEqual(receipt['source_quality'], UNVERIFIED)
        self.assertEqual(summary['source_quality'], UNVERIFIED)


if __name__ == '__main__':
    unittest.main()
