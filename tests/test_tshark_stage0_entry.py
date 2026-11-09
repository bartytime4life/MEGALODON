"""Selected-mode replay refuses before preflight; no native tool runs."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from megalodon.offline import tshark

def fresh_boundary():
    path = ROOT / 'megalodon/execution_boundary.py'
    spec = importlib.util.spec_from_file_location('isolated_boundary_under_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class TSharkStage0EntryTests(unittest.TestCase):

    def setUp(self):
        self.boundary = fresh_boundary()

    def test_selected_replay_refuses_before_any_preflight(self):
        b = self.boundary
        b.select_stage0()

        def forbidden(*args, **kwargs):
            self.fail('native replay reached preflight')
        with patch.dict(sys.modules, {'megalodon.execution_boundary': b}), patch.object(tshark, 'require_unprivileged_linux', forbidden), patch.object(tshark.os, 'lstat', forbidden), patch.object(tshark.os, 'getxattr', forbidden), patch.object(tshark.os, 'pread', forbidden), patch.object(tshark, '_bounded_process', forbidden), patch.object(tshark, 'open_input', forbidden), patch.object(tshark.tempfile, 'TemporaryDirectory', forbidden):
            for root, relative in (('/not-opened', 'synthetic.pcap'), (None, None)):
                with self.subTest(relative=relative), self.assertRaises(b.Stage0Denied):
                    tshark.replay(root, relative)

    def test_ordinary_mode_still_reaches_privilege_admission(self):

        class PreflightReached(Exception):
            pass
        with patch.dict(sys.modules, {'megalodon.execution_boundary': self.boundary}), patch.object(tshark, 'require_unprivileged_linux', side_effect=PreflightReached):
            with self.assertRaises(PreflightReached):
                tshark.replay('/not-opened', 'synthetic.pcap')

if __name__ == "__main__":
    unittest.main(verbosity=2)
