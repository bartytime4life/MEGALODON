"""Test fixtures for paths that must pass owner-only ancestry checks."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.fixture(autouse=True)
def _reference_umask():
    """Run every test under the 022 umask that the hosted runners use.

    Ubuntu desktops with user private groups default to umask 0002. Directories
    a test creates would then inherit group-write, and the owner-only ancestry
    checks in storage and local_install correctly refuse them. Subprocesses
    inherit the pinned value. Tests that need another umask set and restore
    their own inside this window.
    """
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


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
