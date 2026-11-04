"""Require complete executable coverage at both untrusted report boundaries."""
from copy import deepcopy
import json
import shutil
import subprocess
import unittest

from megalodon.dashboard_file_inspection import FILE_INSPECTION_JS
from megalodon.file_inspection import normalize_lief
from megalodon.file_inspection_contract import report, validate_structure


def structure(detected=2, covered=2, kind='Mach-O'):
    row = dict(architecture='ARM64', bits=64, sections=4, imports=2,
               writable_executable=0)
    return dict(format=kind, slices_detected=detected,
                slices=[deepcopy(row) for _ in range(covered)])


class CoverageTests(unittest.TestCase):
    def test_complete_supported_structures(self):
        for kind, number in [('ELF', 1), ('PE', 1), ('Mach-O', 1),
                             ('Mach-O', 2), ('Mach-O', 16)]:
            with self.subTest(kind=kind, number=number):
                value = structure(number, number, kind)
                self.assertEqual(validate_structure(value), value)

    def test_missing_slices_are_refused(self):
        for detected, covered in [(2, 1), (16, 1), (16, 15)]:
            with self.subTest(detected=detected, covered=covered):
                with self.assertRaises(ValueError):
                    validate_structure(structure(detected, covered))

    def test_normalizer_refuses_success_with_missing_slices(self):
        raw = json.dumps(dict(state='completed', structure=structure(2, 1))).encode()
        with self.assertRaises(ValueError):
            normalize_lief(raw)

    def test_report_cannot_relabel_incomplete_structure_as_completed(self):
        with self.assertRaises(ValueError):
            report(64, [dict(state='completed', structure=structure(2, 1)),
                        dict(state='completed', identification=[])])

    @unittest.skipUnless(shutil.which('node'), 'Node unavailable')
    def test_browser_rejects_incomplete_and_excessive_coverage(self):
        valid = report(64, [dict(state='completed', structure=structure()),
                           dict(state='completed', identification=[])])
        candidates = []
        for detected, covered, kind in [(2, 1, 'Mach-O'), (16, 15, 'Mach-O'),
                (17, 1, 'Mach-O'), (2, 2, 'ELF'), (2, 2, 'PE')]:
            candidate = deepcopy(valid)
            candidate['structure'] = structure(detected, covered, kind)
            candidates.append(candidate)
        script = """
const fs=require('fs'),vm=require('vm'),assert=require('assert/strict');
const p=JSON.parse(fs.readFileSync(0,'utf8'));
const c={document:{getElementById:()=>null},TextEncoder};vm.createContext(c);
vm.runInContext(p.code,c);
assert.equal(c.validFileInspectionReport(p.valid),true);
for(const candidate of p.invalid)assert.equal(c.validFileInspectionReport(candidate),false);
"""
        result = subprocess.run([shutil.which('node'), '-e', script],
            input=json.dumps(dict(code=FILE_INSPECTION_JS, valid=valid, invalid=candidates)),
            text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
