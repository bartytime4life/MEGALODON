"""A sticky folder above a search-path folder: it protects a root-owned folder below it, and nothing else."""
from __future__ import annotations

import os
import stat
from types import SimpleNamespace

from megalodon import hardening_drift as hd
from test_hardening_drift import GOOD, reviewer, root, rules  # noqa: F401


def test_a_sticky_folder_above_a_root_owned_path_folder_is_not_a_way_in(root, tmp_path):  # noqa: F811
    manifest = tmp_path / "hardening.json"
    hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    os.chmod(root / "opt", 0o1777)                  # like /tmp: anyone can add, nobody can move root's /opt/tools
    assert hd.check(manifest, review=reviewer(GOOD), budget=30)["findings"] == []


def test_a_sticky_path_folder_itself_still_counts(root, tmp_path):  # noqa: F811
    manifest = tmp_path / "hardening.json"
    hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    os.chmod(root / "opt/tools", 0o1777)            # anyone can still add a program to it
    assert rules(hd.check(manifest, review=reviewer(GOOD), budget=30)) == [
        ("CRITICAL", "PATH_FOLDER_WRITABLE", "file:/opt/tools")]


def test_a_sticky_folder_above_a_path_folder_that_does_not_exist_counts(root, tmp_path):  # noqa: F811
    manifest = tmp_path / "hardening.json"
    (root / "etc/environment").write_text('PATH="/usr/bin:/srv/later/bin"\n')
    (root / "srv").mkdir()
    hd.baseline(manifest, root=str(root), review=reviewer(GOOD), budget=30)
    os.chmod(root / "srv", 0o1777)                  # anyone can create /srv/later, and with it the path folder
    assert rules(hd.check(manifest, review=reviewer(GOOD), budget=30)) == [
        ("CRITICAL", "PATH_FOLDER_WRITABLE", "file:/srv")]


def test_the_sticky_bit_protects_only_root_s_own_folder_in_root_s_own_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(hd, "TRUSTED_UID", 0)
    sticky = SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
    owned = {"root-owned": 0, "another-owner": 1234}
    monkeypatch.setattr(hd.os, "lstat", lambda path: SimpleNamespace(st_uid=owned[os.path.basename(str(path))]))
    assert hd._sticky_protects(sticky, tmp_path / "root-owned")
    assert not hd._sticky_protects(sticky, tmp_path / "another-owner"), "its owner can move it"
    assert not hd._sticky_protects(SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=1234),
                                   tmp_path / "root-owned"), "the folder's owner can move anything in it"
    assert not hd._sticky_protects(SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0),
                                   tmp_path / "root-owned"), "without the sticky bit anyone can rename"
    assert not hd._sticky_protects(sticky, None), "the path folder itself"
