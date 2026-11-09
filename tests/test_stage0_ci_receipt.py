"""Synthetic CI input validation; no provider, native tool or install runs."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('stage0_ci_receipt', ROOT / 'tools/stage0_ci_receipt.py')
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


def inputs():
    binding = {'status': 'validated', 'binding': json.loads(
        (ROOT / 'config/model-bindings/qwen.unbound.json').read_text())}
    readiness = {
        'state': 'UNBOUND', 'binding_status': 'UNBOUND',
        'tools_used_or_authorized': False,
        'gate_failures': ['OWNER_MODEL_BINDING_NOT_RECORDED'],
        'authority': {key: False for key in (
            'contacts_provider', 'starts_provider', 'pulls_model', 'changes_host',
            'attests_loaded_bytes', 'accepts_model', 'grants_detector_authority',
            'grants_action_authority', 'authorizes_release', 'authorizes_deployment')},
    }
    boundary = {'schema': 'megalodon-execution-boundary-v1', 'mode': 'stage0_offline',
                'effectful_entries_denied': True, 'denial_code': 'STAGE0_OFFLINE_EFFECT_DENIED',
                'scope': 'application_entry_fences_not_os_containment', 'acceptance_authority': False}
    root = ElementTree.Element('testsuites')
    suite = ElementTree.SubElement(root, 'testsuite')
    for cls, name in sorted(receipt.REQUIRED_CASES):
        ElementTree.SubElement(suite, 'testcase', classname='tests.synthetic.' + cls, name=name)
    return binding, readiness, boundary, ElementTree.tostring(root)


class Stage0CIReceiptTests(unittest.TestCase):
    def setUp(self):
        self.binding, self.readiness, self.boundary, self.junit = inputs()

    def build(self, **changes):
        values = dict(commit='a' * 40, tree='b' * 40,
                      binding_raw=encode(self.binding), readiness_raw=encode(self.readiness),
                      boundary_raw=encode(self.boundary), junit_raw=self.junit)
        values.update(changes)
        return receipt.build_receipt(**values)

    def test_valid_receipt_is_deterministic_and_grants_no_authority(self):
        value = self.build()
        self.assertEqual(value, self.build())
        self.assertEqual(value['junit_testcases']['passed'], 9)
        self.assertEqual(value['binding_state'], 'UNBOUND')
        self.assertTrue(all(v is False for v in value['authority'].values()))
        self.assertIsNone(value['tripwire_counts'])
        self.assertEqual(value['source_package_parity'], 'NOT_RUN')
        self.assertTrue(all(v == 'NOT_RUN' for v in value['native_lanes'].values()))

    def test_identity_must_be_exact_canonical_git_sha(self):
        for value in ('', 'a' * 39, 'A' * 40, 'private/path', None):
            for field in ('commit', 'tree'):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.build(**{field: value})

    def test_bound_models_or_non_boolean_authority_are_refused(self):
        damaged = deepcopy(self.binding)
        damaged['binding']['status'] = 'BOUND'
        with self.assertRaises(ValueError):
            self.build(binding_raw=encode(damaged))
        for invalid in (True, None, 0, 'false'):
            damaged = deepcopy(self.readiness)
            damaged['authority']['changes_host'] = invalid
            with self.subTest(value=invalid), self.assertRaises(ValueError):
                self.build(readiness_raw=encode(damaged))
        damaged = deepcopy(self.readiness)
        damaged['authority'] = {}
        with self.assertRaises(ValueError):
            self.build(readiness_raw=encode(damaged))

    def test_wrong_boundary_or_missing_holds_are_refused(self):
        for key, invalid in (('mode', 'installed_runtime'), ('acceptance_authority', 0),
                             ('effectful_entries_denied', 1), ('denial_code', 'OTHER')):
            damaged = {**self.boundary, key: invalid}
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build(boundary_raw=encode(damaged))
        damaged = {**self.readiness, 'gate_failures': []}
        with self.assertRaises(ValueError):
            self.build(readiness_raw=encode(damaged))

    def test_missing_skipped_failed_or_error_required_case_refuses(self):
        for outcome in ('missing', 'skipped', 'failure', 'error'):
            root = ElementTree.fromstring(self.junit)
            case = root.find('.//testcase')
            if outcome == 'missing':
                root.find('testsuite').remove(case)
            else:
                ElementTree.SubElement(case, outcome)
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                self.build(junit_raw=ElementTree.tostring(root))

    def test_duplicate_json_oversize_and_xml_entities_refuse(self):
        for raw in (b'{"status":"validated","status":"validated"}', b'NaN', b'[' * 5000):
            with self.subTest(raw=raw[:30]), self.assertRaises((ValueError, RecursionError)):
                self.build(binding_raw=raw)
        with self.assertRaises(ValueError):
            self.build(junit_raw=b'x' * (receipt.MAX_BYTES + 1))
        raw = b'<!DOCTYPE testsuites [<!ENTITY x "unsafe">]>' + self.junit
        with self.assertRaises(ValueError):
            self.build(junit_raw=raw)

    def test_suite_level_errors_do_not_become_a_passing_receipt(self):
        for kind in ('error', 'errors', 'failures'):
            root = ElementTree.fromstring(self.junit)
            suite = root.find('testsuite')
            if kind == 'error':
                ElementTree.SubElement(suite, 'error')
            else:
                suite.set(kind, '1')
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.build(junit_raw=ElementTree.tostring(root))

    def test_cli_reads_inputs_and_outputs_only_bounded_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            argv = ['--commit', 'a' * 40, '--tree', 'b' * 40]
            for key, raw in zip(('binding', 'readiness', 'boundary', 'junit'),
                                (encode(self.binding), encode(self.readiness), encode(self.boundary), self.junit)):
                path = Path(directory) / key
                path.write_bytes(raw)
                argv += ['--' + key, str(path)]
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(receipt.main(argv), 0)
            self.assertEqual(json.loads(out.getvalue()), self.build())
            self.assertNotIn(directory, out.getvalue())
            (Path(directory) / 'binding').write_text('{"private":"not disclosed"}')
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
                self.assertEqual(receipt.main(argv), 2)
            self.assertEqual(out.getvalue(), '')
            self.assertEqual(err.getvalue(), receipt.DENIAL + '\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
