"""Finite synthetic checks for exact-profile admission; never start Zeek."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from megalodon.offline import zeek_profile as profile
from megalodon.offline.common import Limits, OfflineError
import test_zeek_candidate_packet as candidate_tests


PACKET = candidate_tests.PACKET
PRODUCER = PACKET.parent / 'producer'
ADMISSIONS = json.loads((PRODUCER / 'fixtures' / 'admissions.json').read_bytes())


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux descriptor-relative input')
class ZeekProfileAdmissionTests(unittest.TestCase):
    offline_only = candidate_tests.ZeekCandidatePacketTests.offline_only
    unchanged = candidate_tests.ZeekCandidatePacketTests.unchanged

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='megalodon-zeek-profile-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'conn.log'
        self.originals = {name: (PACKET / name).read_bytes() for name in (
            'fixtures/accepted.jsonl', 'fixtures/accepted.tsv', 'fixtures/rejected.json')}

    @contextmanager
    def guarded(self):
        with self.offline_only() as writes, patch.object(profile, 'require_unprivileged_linux'):
            yield
        self.assertEqual(writes, [])

    def read(self, data, admission, limits=Limits()):
        self.source.write_bytes(data)
        self.source.chmod(0o600)
        before = self.source.stat()
        try:
            with self.guarded():
                return profile.read_completed_conn(str(self.root), 'conn.log',
                                                   admission=admission, limits=limits)
        finally:
            self.unchanged(data, before)

    def data(self, admission):
        ext = 'jsonl' if admission['format'] == 'json' else 'tsv'
        return self.originals['fixtures/accepted.' + ext]

    def test_exact_profile_and_configuration_are_bound_to_the_schema(self):
        schema = json.loads((PRODUCER / 'schema.json').read_bytes())
        properties = schema['$defs']['admission']['properties']
        self.assertEqual(set(schema['$defs']['admission']['required']), profile.ADMISSION_KEYS)
        self.assertFalse(schema['$defs']['admission']['additionalProperties'])
        self.assertEqual(properties['producer_profile']['const'], profile.PRODUCER_PROFILE)
        self.assertEqual(properties['declared_version']['const'], profile.DECLARED_VERSION)
        self.assertEqual(properties['configuration_digest']['const'], profile.CONFIGURATION_DIGEST)
        raw = (PRODUCER / 'configuration.json').read_bytes()
        self.assertEqual('sha256:' + hashlib.sha256(raw).hexdigest(), profile.CONFIGURATION_DIGEST)
        manifest = json.loads((PACKET / 'manifest.json').read_bytes())
        self.assertEqual(manifest['declared_profile'], profile.PRODUCER_PROFILE)
        self.assertEqual(manifest['declared_configuration_digest'], profile.CONFIGURATION_DIGEST)
        entry = manifest['admission_fixtures']
        self.assertEqual(entry['path'], 'producer/fixtures/admissions.json')
        raw = (PRODUCER / 'fixtures' / 'admissions.json').read_bytes()
        self.assertEqual(len(raw), entry['size_bytes'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), entry['sha256'])

    def test_json_tsv_match_and_receipts_remain_unverified_immutable_and_in_memory(self):
        results = []
        for admission in ADMISSIONS:
            batch, receipt = self.read(self.data(admission), admission)
            self.assertEqual(batch.version_basis, 'operator_declared_unverified')
            self.assertEqual(batch.scanned, 4)
            self.assertEqual(receipt['producer_identity_status'], 'operator_declared_unverified')
            self.assertEqual(receipt['native_qualification'], 'not_run')
            self.assertEqual(receipt['source_digest_status'], 'matches_operator_expectation')
            self.assertEqual(receipt['action_status'], 'not_attempted')
            self.assertEqual(receipt['durable_write_status'], 'not_attempted')
            self.assertEqual(dict(receipt['provenance']), admission)
            with self.assertRaises(TypeError):
                receipt['status'] = 'healthy'
            with self.assertRaises(TypeError):
                receipt['provenance']['producer_profile'] = 'changed'
            results.append(batch.records)
        self.assertEqual(results[0], results[1])
        self.assertEqual({p.name for p in self.root.iterdir()}, {'conn.log'})

    def test_bad_admission_refuses_before_privilege_or_source_inspection(self):
        original = ADMISSIONS[0]
        cases = [({}, 'ZEEK_PROFILE_ADMISSION'), (None, 'ZEEK_PROFILE_ADMISSION')]
        for key, value, code in (
            ('producer_profile', 'unknown', 'ZEEK_PROFILE_MISMATCH'),
            ('declared_version', '9.0.0', 'ZEEK_PROFILE_MISMATCH'),
            ('declared_version', [], 'ZEEK_PROFILE_ADMISSION'),
            ('format', 'csv', 'ZEEK_PROFILE_MISMATCH'),
            ('format', {}, 'ZEEK_PROFILE_ADMISSION'),
            ('source_archive_digest', 'sha256:' + '0' * 64, 'ZEEK_PROFILE_MISMATCH'),
            ('binary_digest', 'sha256:' + '0' * 64, 'ZEEK_PROFILE_MISMATCH'),
            ('configuration_digest', 'sha256:' + '0' * 64, 'ZEEK_PROFILE_MISMATCH'),
            ('expected_digest', 'sha256:' + 'A' * 64, 'ZEEK_PROFILE_DIGEST'),
            ('expected_digest', 'sha256:' + 'a' * 63, 'ZEEK_PROFILE_DIGEST'),
            ('expected_digest', 'sha256:' + 'a' * 64 + '\n', 'ZEEK_PROFILE_DIGEST'),
            ('source_id', 'https://example.invalid', 'ZEEK_PROFILE_ADMISSION'),
            ('source_id', 'Synthetic\n', 'ZEEK_PROFILE_ADMISSION'),
            ('source_id', 'a' * 65, 'ZEEK_PROFILE_ADMISSION'),
            ('run_id', '../escape', 'ZEEK_PROFILE_ADMISSION'),
            ('expected_records', True, 'ZEEK_PROFILE_RECORD_COUNT'),
            ('expected_records', 0, 'ZEEK_PROFILE_RECORD_COUNT'),
            ('expected_records', 10001, 'ZEEK_PROFILE_RECORD_COUNT'),
        ):
            cases.append(({**original, key: value}, code))
        cases.append(({**original, 'extra': 'field'}, 'ZEEK_PROFILE_ADMISSION'))
        for value, code in cases:
            with self.subTest(value=value), patch.object(profile, 'open_input') as opened:
                with patch.object(profile, 'require_unprivileged_linux') as privilege:
                    with self.assertRaisesRegex(OfflineError, '^' + code + '$'):
                        profile.read_completed_conn(str(self.root), 'missing', admission=value)
                opened.assert_not_called()
                privilege.assert_not_called()

    def test_all_37_bad_files_refuse_without_publishing_a_valid_prefix(self):
        for case in json.loads(self.originals['fixtures/rejected.json']):
            admission = next(a for a in ADMISSIONS if a['format'] == case['format'])
            data = case['raw'].encode('ascii')
            admission = {**admission, 'expected_digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
            with self.subTest(case=case['id']), self.assertRaisesRegex(OfflineError, '^' + case['code'] + '$'):
                self.read(data, admission)

    def test_line_aligned_truncation_refuses_by_count_and_independent_digest(self):
        for admission in ADMISSIONS:
            lines = self.data(admission).splitlines(keepends=True)
            shortened = b''.join(lines[:-1] if admission['format'] == 'json' else lines[:-2] + lines[-1:])
            with self.subTest(format=admission['format']):
                with self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_RECORD_COUNT$'):
                    self.read(shortened, admission)
                with self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_DIGEST$'):
                    self.read(shortened, {**admission, 'expected_records': 3})

    def test_same_records_different_bytes_refuse_the_expected_digest(self):
        for admission in ADMISSIONS:
            data = self.data(admission).replace(b'SyntheticTCP', b'SyntheticALT')
            with self.subTest(format=admission['format']), self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_DIGEST$'):
                self.read(data, admission)

    def test_json_writer_drift_and_missing_native_fields_refuse(self):
        admission = ADMISSIONS[0]
        data = self.data(admission)
        for changed in (data.replace(b'"uid":"SyntheticTCP",', b'', 1),
                        data.replace(b'"missed_bytes":0,', b'', 1),
                        data.replace(b'"service":"ssl"', b'"service":null', 1),
                        data.replace(b'"ts":1700000000.123456', b'"ts":"1700000000.123456"', 1),
                        data.replace(b'"duration":0.000001', b'"duration":"0.000001"', 1),
                        data.replace(b'"orig_pkts":3', b'"orig_pkts":"3"', 1)):
            with self.subTest(changed=changed[:40]), self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_FIELDS$'):
                self.read(changed, admission)

    def test_tsv_profile_requires_open_and_full_declared_field_order(self):
        admission = ADMISSIONS[1]
        data = self.data(admission)
        changed = b''.join(line for line in data.splitlines(keepends=True) if not line.startswith(b'#open'))
        with self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_FIELDS$'):
            self.read(changed, admission)
        lines = []
        for line in data.splitlines(keepends=True):
            if line.startswith((b'#fields\t', b'#types\t')):
                prefix, *cells = line.rstrip(b'\n').split(b'\t')
                cells[0], cells[1] = cells[1], cells[0]
                line = b'\t'.join([prefix, *cells]) + b'\n'
            elif not line.startswith(b'#'):
                cells = line.rstrip(b'\n').split(b'\t')
                cells[0], cells[1] = cells[1], cells[0]
                line = b'\t'.join(cells) + b'\n'
            lines.append(line)
        with self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_FIELDS$'):
            self.read(b''.join(lines), admission)

    def test_tsv_unset_mandatory_fields_refuse_after_a_valid_prefix(self):
        admission = ADMISSIONS[1]
        lines = self.data(admission).splitlines(keepends=True)
        first_row = next(line for line in lines if not line.startswith(b'#'))
        for field in ('uid', 'missed_bytes'):
            cells = first_row.rstrip(b'\n').split(b'\t')
            cells[list(profile.zeek.TYPES).index(field)] = b'-'
            data = b''.join(lines[:-1]) + b'\t'.join(cells) + b'\n' + lines[-1]
            declared = {**admission, 'expected_records': 5,
                        'expected_digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
            with self.subTest(field=field), self.assertRaisesRegex(OfflineError, '^ZEEK_PROFILE_FIELDS$'):
                self.read(data, declared)

    def test_private_modes_symlinks_and_hardlinks_refuse(self):
        admission = ADMISSIONS[0]
        self.source.write_bytes(self.data(admission))
        self.source.chmod(0o644)
        with self.guarded(), self.assertRaisesRegex(OfflineError, '^PRIVATE_ZEEK_PROFILE_INPUT_REQUIRED$'):
            profile.read_completed_conn(str(self.root), 'conn.log', admission=admission)
        self.source.chmod(0o600)
        self.root.chmod(0o755)
        try:
            with self.guarded(), self.assertRaisesRegex(OfflineError, '^PRIVATE_ZEEK_PROFILE_INPUT_REQUIRED$'):
                profile.read_completed_conn(str(self.root), 'conn.log', admission=admission)
        finally:
            self.root.chmod(0o700)
        alias = self.root / 'alias'
        alias.symlink_to(self.source)
        with self.guarded(), self.assertRaisesRegex(OfflineError, '^INPUT_IO_ERROR$'):
            profile.read_completed_conn(str(self.root), 'alias', admission=admission)
        alias.unlink()
        os.link(self.source, alias)
        with self.guarded(), self.assertRaisesRegex(OfflineError, '^REGULAR_SINGLE_LINK_FILE_REQUIRED$'):
            profile.read_completed_conn(str(self.root), 'conn.log', admission=admission)

    def test_record_line_and_cooperative_time_limits_refuse(self):
        admission = ADMISSIONS[0]
        with self.assertRaisesRegex(OfflineError, '^RECORD_LIMIT$'):
            self.read(self.data(admission), {**admission, 'expected_records': 3}, Limits(records=3))
        with self.assertRaisesRegex(OfflineError, '^INPUT_SIZE_LIMIT$'):
            self.read(self.data(admission), admission, Limits(line_bytes=10))
        with patch.object(profile.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(OfflineError, '^TIMEOUT$'):
                self.read(self.data(admission), admission)

    def test_source_change_after_digest_check_cannot_return_a_batch(self):
        admission = ADMISSIONS[0]
        self.source.write_bytes(self.data(admission))
        self.source.chmod(0o600)
        writer = os.open(self.source, os.O_WRONLY | os.O_APPEND)
        self.addCleanup(os.close, writer)
        real_lines = profile._lines

        def changed_source(*args):
            yield from real_lines(*args)
            # Deliberate external-writer fault; the reader itself never writes.
            os.write(writer, b'\n')

        with patch.object(profile, '_lines', changed_source), self.guarded():
            with self.assertRaisesRegex(OfflineError, '^INPUT_CHANGED$'):
                profile.read_completed_conn(str(self.root), 'conn.log', admission=admission)

    def test_descriptor_close_failure_cannot_return_success(self):
        admission = ADMISSIONS[0]
        self.source.write_bytes(self.data(admission))
        self.source.chmod(0o600)
        real_close = os.close
        failed = False

        def fail_once(fd):
            nonlocal failed
            real_close(fd)
            if not failed:
                failed = True
                raise OSError('synthetic descriptor close failure')

        with self.guarded(), patch.object(os, 'close', side_effect=fail_once):
            with self.assertRaisesRegex(OfflineError, '^INPUT_IO_ERROR$'):
                profile.read_completed_conn(str(self.root), 'conn.log', admission=admission)

    def test_resource_limit_object_is_validated_before_source_io(self):
        with patch.object(profile, 'open_input') as opened:
            with self.assertRaisesRegex(OfflineError, '^INVALID_LIMIT$'):
                profile.read_completed_conn(str(self.root), 'missing', admission=ADMISSIONS[0], limits={})
        opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
