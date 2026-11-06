"""Test fixtures for paths that must pass owner-only ancestry checks."""
from pathlib import Path
from tempfile import TemporaryDirectory
import threading

import pytest

# Longest wait for one leftover daemon thread; measured joins stay under 0.2 s.
STRAY_THREAD_JOIN_SECONDS = 10


@pytest.fixture(autouse=True)
def _quiesce_background_threads():
    """Let each test's leftover MEGALODON daemon threads finish before the next test.

    Support-configuration snapshots start short daemon review threads
    (``megalodon-persistence-review``, ``megalodon-process-review``) that a test
    does not wait for. Left running, they reach later tests that require a
    single-threaded process, such as the CLI ``--max-seconds`` gate, and fail
    them depending on scheduling. Joining here keeps the suite order-independent
    without changing product code. A thread that outlives the bound is left
    alone rather than failing an unrelated test.
    """
    yield
    main = threading.main_thread()
    for thread in threading.enumerate():
        if thread is not main and thread.name.startswith('megalodon-'):
            thread.join(STRAY_THREAD_JOIN_SECONDS)


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
