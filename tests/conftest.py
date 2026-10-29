"""Test fixtures for paths that must pass owner-only ancestry checks."""
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.fixture
def private_tmp_path():
    # pytest's usual tmp_path lives below /tmp, which is world-writable.
    with TemporaryDirectory(prefix='megalodon-test-', dir=Path.home()) as root:
        yield Path(root)


@pytest.fixture
def synthetic_runtime_binding(monkeypatch):
    """Exercise dormant lower layers with fakes; never evidence of acceptance.

    Opt-in only: production has no switch that lifts its UNBOUND release fence.
    Runtime gate tests must not request this fixture.
    """
    from megalodon import local_model_runtime
    monkeypatch.setattr(local_model_runtime, "binding_failure", lambda: None)
