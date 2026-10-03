"""Test fixtures for paths that must pass owner-only ancestry checks."""
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.fixture
def private_tmp_path():
    # pytest's usual tmp_path lives below /tmp, which is world-writable.
    with TemporaryDirectory(prefix='megalodon-test-', dir=Path.home()) as root:
        yield Path(root)
