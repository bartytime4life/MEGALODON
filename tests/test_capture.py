from __future__ import annotations

from io import StringIO
import unittest

from megalodon.capture import CaptureError, iter_jsonl


class CaptureTests(unittest.TestCase):
    def test_jsonl_rejects_non_object_records(self):
        with self.assertRaises(CaptureError):
            list(iter_jsonl(StringIO("[1, 2, 3]\n")))
