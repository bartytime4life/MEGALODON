import ctypes
import errno

import pytest

from megalodon import process_privileges as privileges


class FakeCaps:
    def __init__(self, words):
        self.words = words
        self.writes = []
        self.get_error = self.set_error = False
        self.retain = False

    def capget(self, header, data):
        assert header._obj.version == 0x20080522
        assert header._obj.pid == 0
        if self.get_error:
            ctypes.set_errno(errno.EPERM)
            return -1
        for target, source in zip(data, self.words):
            target.effective, target.permitted, target.inheritable = source
        return 0

    def capset(self, header, data):
        self.writes.append([(word.effective, word.permitted, word.inheritable) for word in data])
        if self.set_error:
            ctypes.set_errno(errno.EPERM)
            return -1
        if not self.retain:
            self.words = self.writes[-1]
        return 0


@pytest.fixture
def caps(monkeypatch):
    api = FakeCaps([(1, 3, 7), (4, 12, 8)])
    monkeypatch.setattr(privileges.sys, "platform", "linux")
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(privileges, "_capability_api", lambda: api)
    return api


def test_discards_both_inheritable_words_and_preserves_other_sets(caps):
    privileges.drop_inherited_capabilities()
    assert caps.writes == [[(1, 3, 0), (4, 12, 0)]]
    privileges.drop_inherited_capabilities()
    assert len(caps.writes) == 1


@pytest.mark.parametrize("failure", ["get_error", "set_error"])
def test_system_errors_refuse_startup(caps, failure):
    setattr(caps, failure, True)
    with pytest.raises(OSError) as error:
        privileges.drop_inherited_capabilities()
    assert error.value.errno == errno.EPERM


def test_rechecks_actual_capabilities_after_write(caps):
    caps.retain = True
    with pytest.raises(ValueError, match="not cleared"):
        privileges.drop_inherited_capabilities()


@pytest.mark.parametrize("platform,uid", [("darwin", 1000), ("linux", 0)])
def test_leaves_other_launch_contexts_to_existing_admission_checks(caps, monkeypatch, platform, uid):
    monkeypatch.setattr(privileges.sys, "platform", platform)
    monkeypatch.setattr(privileges.os, "geteuid", lambda: uid)
    privileges.drop_inherited_capabilities()
    assert caps.writes == []
