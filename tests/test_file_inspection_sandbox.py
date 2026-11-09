"""Isolation setup failures stay bounded without launching a native parser."""
import ctypes
import os
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest

from megalodon import file_inspection_sandbox as sandbox


def test_input_setup_failure_closes_its_descriptor(monkeypatch):
    descriptor = os.memfd_create('synthetic-inspection-input')
    monkeypatch.setattr(sandbox.os, 'memfd_create', Mock(return_value=descriptor))
    monkeypatch.setattr(sandbox.os, 'fchmod', Mock(side_effect=OSError('synthetic mode failure')))
    try:
        with pytest.raises(OSError, match='synthetic mode failure'):
            sandbox.sealed_input()
        with pytest.raises(OSError):
            os.fstat(descriptor)
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


@pytest.mark.parametrize('error', [OSError('synthetic descriptor failure'),
    sandbox.SandboxUnavailable('synthetic filter refusal'),
    ctypes.ArgumentError('synthetic filter argument failure')])
def test_filter_setup_failure_returns_unavailable_without_launch(monkeypatch, error):
    def fail(**_):
        raise error
    command, launch = Mock(), Mock()
    monkeypatch.setattr(sandbox, '_filter', fail)
    monkeypatch.setattr(sandbox, 'command', command)
    monkeypatch.setattr(sandbox.subprocess, 'Popen', launch)

    assert sandbox.run(Path('/unused'), -1, 'die', deadline=0,
                       cancelled=Event()) == ('unavailable', b'')
    command.assert_not_called()
    launch.assert_not_called()


def test_filter_descriptor_failure_releases_seccomp_context(monkeypatch):
    api = Mock()
    api.seccomp_init.return_value = 123
    monkeypatch.setattr(sandbox.ctypes, 'CDLL', Mock(return_value=api))
    monkeypatch.setattr(sandbox.os, 'memfd_create', Mock(side_effect=OSError('synthetic descriptor failure')))

    with pytest.raises(OSError, match='synthetic descriptor failure'):
        sandbox._filter()

    api.seccomp_release.assert_called_once_with(123)


def test_filter_rule_failure_closes_descriptor_and_releases_context(monkeypatch):
    api = Mock()
    api.seccomp_init.return_value = 123
    api.seccomp_syscall_resolve_name.return_value = 1
    api.seccomp_rule_add.return_value = 1
    descriptor = os.memfd_create('synthetic-inspection-filter')
    monkeypatch.setattr(sandbox.ctypes, 'CDLL', Mock(return_value=api))
    monkeypatch.setattr(sandbox.os, 'memfd_create', Mock(return_value=descriptor))

    try:
        with pytest.raises(sandbox.SandboxUnavailable):
            sandbox._filter()
        with pytest.raises(OSError):
            os.fstat(descriptor)
        api.seccomp_release.assert_called_once_with(123)
    finally:
        # Do not leak the test descriptor when checking a broken implementation.
        try:
            os.close(descriptor)
        except OSError:
            pass


@pytest.mark.parametrize('stage', ['command', 'launch'])
def test_setup_failure_after_filter_closes_its_descriptor(monkeypatch, stage):
    descriptor = os.memfd_create('synthetic-inspection-filter')
    monkeypatch.setattr(sandbox, '_filter', Mock(return_value=descriptor))
    command = Mock(side_effect=ValueError('synthetic command failure')) if stage == 'command' else Mock(return_value=[])
    launch = Mock(side_effect=OSError('synthetic launch failure'))
    monkeypatch.setattr(sandbox, 'command', command)
    monkeypatch.setattr(sandbox.subprocess, 'Popen', launch)
    source = os.memfd_create('synthetic-inspection-input')
    try:
        assert sandbox.run(Path('/unused'), source, 'lief', deadline=0,
                           cancelled=Event()) == ('unavailable', b'')
        with pytest.raises(OSError):
            os.fstat(descriptor)
        if stage == 'command':
            launch.assert_not_called()
        else:
            launch.assert_called_once()
        assert os.fstat(source).st_size == 0, 'The caller retains its input FD.'
    finally:
        os.close(source)
        try:
            os.close(descriptor)
        except OSError:
            pass
