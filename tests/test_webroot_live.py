"""`webroot watch`: each file judged as it is written, and a script dropped and soon deleted reported even though no
check ever sees it."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys
import time

import pytest

from megalodon import cli
from megalodon import webroot_watch as ww
from test_webroot_watch import OBFUSCATED, SHELL_CALL, site  # noqa: F401

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="inotify")


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def watching(site, tmp_path, clock=None):  # noqa: F811
    manifest = tmp_path / "webroot.json"
    ww.baseline(manifest, web_roots=[str(site)])
    found, warned = [], []
    watcher = ww.Watcher(manifest, found.append, warn=warned.append, clock=clock or time.monotonic)
    return watcher, found, warned


def settle(watcher):
    """Handle the events the kernel has queued, until it has none."""
    out = []
    for _ in range(20):
        events = watcher.notify.events(0.2)
        if not events:
            break
        out += watcher.handle(events)
    return out


def rules(found):
    return sorted((f["rule_id"], Path(f["path"]).name) for f in found)


@linux
def test_a_script_dropped_used_and_deleted_between_checks_is_reported(site, tmp_path):  # noqa: F811
    clock = Clock()
    watcher, found, _ = watching(site, tmp_path, clock)
    try:
        assert watcher.rescan() == [], "nothing changed since the baseline"
        shell = site / "html/wp-content/uploads/2026/cache.php"
        shell.write_text(SHELL_CALL)
        assert rules(settle(watcher)) == [("SCRIPT_IN_UPLOAD_FOLDER", "cache.php"), ("WEB_SHELL_PATTERN", "cache.php")]
        assert all(f["live"] and f["sha256"] for f in found)
        shell.write_text(SHELL_CALL)                       # written again, the same: nothing new
        assert settle(watcher) == []
        clock.now += 90
        shell.unlink()
        gone = settle(watcher)
        assert [(f["rule_id"], f["severity"], f["techniques"]) for f in gone] == [
            ("WEB_SCRIPT_DROPPED_AND_REMOVED", "HIGH", ["T1505.003", "T1070.004"])]
        assert "deleted 90 s later" in gone[0]["detail"] and gone[0]["sha256"] == found[0]["sha256"]
        assert not ww.check(tmp_path / "webroot.json")["findings"], "the check that runs later sees nothing"
    finally:
        watcher.close()


@linux
def test_changes_hidden_code_renames_and_folders_moved_in(site, tmp_path):  # noqa: F811
    clock = Clock()
    watcher, _found, _ = watching(site, tmp_path, clock)
    try:
        (site / "html/index.php").write_text("<?php require 'wp-blog-header.php'; // patched\n")
        (site / "html/wp-content/uploads/2026/photo.jpg").write_bytes(b"\xff\xd8\xff\xe0" + OBFUSCATED.encode())
        (site / "html/style.css").write_text("body { color: #000; }\n")            # not code
        (site / "html/node_modules/x/new.php").write_text(SHELL_CALL)              # a folder the check skips
        assert rules(settle(watcher)) == [("CODE_IN_NON_SCRIPT_FILE", "photo.jpg"), ("WEB_SCRIPT_CHANGED", "index.php"),
                                          ("WEB_SHELL_PATTERN", "photo.jpg")]
        staging = tmp_path / "staging"
        (staging / "kit").mkdir(parents=True)
        (staging / "kit/up.php").write_text("<?php echo 1;\n")
        shutil.move(str(staging / "kit"), str(site / "html/kit"))                   # a whole folder moved in
        assert rules(settle(watcher)) == [("WEB_SCRIPT_ADDED", "up.php")]
        os.rename(site / "html/kit/up.php", site / "html/kit/down.php")            # renamed: not a removal
        assert rules(settle(watcher)) == [("WEB_SCRIPT_ADDED", "down.php")]
        (site / "html/kit/up.php").write_text("<?php echo 1;\n")                   # the old name, used again
        assert rules(settle(watcher)) == [("WEB_SCRIPT_ADDED", "up.php")]
        (site / "html/kit/down.php").unlink()
        assert rules(settle(watcher)) == [("WEB_SCRIPT_DROPPED_AND_REMOVED", "down.php")]
        (site / "html/index.php").unlink()                     # in the baseline, and changed while watching
        assert settle(watcher) == [], "only a script that newly appeared is dropped"
        os.symlink("/etc/passwd", site / "html/robots.php")
        assert rules(settle(watcher)) == [("WEB_LINK_ADDED", "robots.php")]
    finally:
        watcher.close()


@linux
def test_a_script_deleted_long_after_it_appeared_is_not_called_dropped(site, tmp_path):  # noqa: F811
    clock = Clock()
    watcher, _found, _ = watching(site, tmp_path, clock)
    try:
        (site / "html/new.php").write_text("<?php echo 2;\n")
        assert rules(settle(watcher)) == [("WEB_SCRIPT_ADDED", "new.php")]
        clock.now += ww.DROP_WINDOW + 1
        (site / "html/new.php").unlink()
        assert settle(watcher) == []
    finally:
        watcher.close()


@linux
def test_a_rename_keeps_when_the_script_first_appeared(site, tmp_path):  # noqa: F811
    clock = Clock()
    watcher, _found, _ = watching(site, tmp_path, clock)
    try:
        (site / "html/a.php").write_text("<?php echo 6;\n")
        settle(watcher)
        clock.now += ww.DROP_WINDOW - 10
        os.rename(site / "html/a.php", site / "html/b.php")
        settle(watcher)
        clock.now += 20
        (site / "html/b.php").unlink()
        assert settle(watcher) == [], "it appeared more than the window ago, under its first name"
    finally:
        watcher.close()


@linux
def test_moved_out_of_the_web_root_counts_as_deleted(site, tmp_path):  # noqa: F811
    watcher, _found, _ = watching(site, tmp_path)
    try:
        (site / "html/drop.php").write_text("<?php echo 3;\n")
        settle(watcher)
        os.rename(site / "html/drop.php", tmp_path / "drop.php")
        assert rules(settle(watcher)) == [("WEB_SCRIPT_DROPPED_AND_REMOVED", "drop.php")]
    finally:
        watcher.close()


def test_dropped_events_lead_to_a_full_look_once(site, tmp_path):  # noqa: F811
    from megalodon.ransomware_watch import IN_Q_OVERFLOW

    class Quiet:
        def add(self, path):
            return True

        def events(self, timeout):
            return []

        def close(self):
            pass
    manifest = tmp_path / "webroot.json"
    ww.baseline(manifest, web_roots=[str(site)])
    found, warned = [], []
    watcher = ww.Watcher(manifest, found.append, warn=warned.append, notify=Quiet())
    (site / "html/missed.php").write_text("<?php echo 4;\n")           # written while events were being lost
    assert rules(watcher.handle([(IN_Q_OVERFLOW, 0, None, "")])) == [("WEB_SCRIPT_ADDED", "missed.php")]
    assert len(warned) == 1 and "looked at again" in warned[0]
    assert watcher.handle([(IN_Q_OVERFLOW, 0, None, "")]) == [], "reported once"


def test_accept_while_watching_is_picked_up(site, tmp_path):  # noqa: F811
    class Quiet:
        def add(self, path):
            return True

        def events(self, timeout):
            return []

        def close(self):
            pass
    manifest = tmp_path / "webroot.json"
    ww.baseline(manifest, web_roots=[str(site)])
    (site / "html/plugin.php").write_text("<?php echo 5;\n")
    watcher = ww.Watcher(manifest, lambda f: None, notify=Quiet())
    assert rules(watcher.rescan()) == [("WEB_SCRIPT_ADDED", "plugin.php")]
    ww.accept(manifest)
    stopped = []

    class Once:
        def is_set(self):
            stopped.append(1)
            return len(stopped) > 1
    watcher.notify = Quiet()
    watcher.run(Once())                                    # one turn: the changed baseline is read again
    assert str(site / "html/plugin.php") in watcher.baseline["files"]
    assert watcher.rescan() == [], "accepted while watching"


def test_the_watch_command_needs_a_baseline(tmp_path, capsys):
    with pytest.raises(SystemExit) as stopped:
        cli.main(["webroot", "watch", "--manifest", str(tmp_path / "none.json")])
    assert stopped.value.code == 2 and "webroot baseline" in capsys.readouterr().err


@linux
def test_a_folder_moved_out_or_renamed_takes_its_new_scripts_with_it(site, tmp_path):  # noqa: F811
    watcher, _found, _ = watching(site, tmp_path)
    try:
        (site / "html/kit").mkdir()
        settle(watcher)
        (site / "html/kit/a.php").write_text("<?php echo 7;\n")
        assert rules(settle(watcher)) == [("WEB_SCRIPT_ADDED", "a.php")]
        os.rename(site / "html/kit", site / "html/tools")          # renamed within the root: nothing new
        assert settle(watcher) == []
        os.rename(site / "html/tools", tmp_path / "away")          # moved out: one event for the folder
        assert rules(settle(watcher)) == [("WEB_SCRIPT_DROPPED_AND_REMOVED", "a.php")]
    finally:
        watcher.close()


@linux
def test_folders_made_while_events_were_lost_are_watched_again(site, tmp_path):  # noqa: F811
    from megalodon.ransomware_watch import IN_Q_OVERFLOW
    watcher, _found, warned = watching(site, tmp_path)
    try:
        (site / "html/late").mkdir()
        watcher.notify.events(0.5)                                   # its creation, lost
        watcher.handle([(IN_Q_OVERFLOW, 0, None, "")])
        (site / "html/late/x.php").write_text("<?php echo 8;\n")
        assert rules(settle(watcher)) == [("WEB_SCRIPT_ADDED", "x.php")]
    finally:
        watcher.close()


@linux
def test_a_script_replaced_by_a_link_to_the_same_contents_is_reported(site, tmp_path):  # noqa: F811
    watcher, _found, _ = watching(site, tmp_path)
    try:
        watcher.rescan()                                           # remembers index.php as it is
        page = site / "html/index.php"
        same = tmp_path / "same.php"
        same.write_bytes(page.read_bytes())
        os.symlink(same, site / "html/.swap")
        os.replace(site / "html/.swap", page)                      # moved over the page in one step
        assert rules(settle(watcher)) == [("WEB_SCRIPT_REPLACED_BY_LINK", "index.php")]
        other = tmp_path / "other.php"
        other.write_bytes(page.read_bytes())                       # identical contents, another file
        os.symlink(other, site / "html/.swap")
        os.replace(site / "html/.swap", page)
        assert rules(settle(watcher)) == [("WEB_SCRIPT_REPLACED_BY_LINK", "index.php")], \
            "the link now leads elsewhere"
    finally:
        watcher.close()


@linux
def test_a_folder_renamed_and_its_script_deleted_at_once(site, tmp_path):  # noqa: F811
    watcher, _found, _ = watching(site, tmp_path)
    try:
        (site / "html/kit").mkdir()
        settle(watcher)
        (site / "html/kit/a.php").write_text("<?php echo 9;\n")
        settle(watcher)
        os.rename(site / "html/kit", site / "html/tools")
        (site / "html/tools/a.php").unlink()       # in the same batch: the kernel names the folder's old path
        gone = settle(watcher)
        assert [(f["rule_id"], f["path"]) for f in gone] == [
            ("WEB_SCRIPT_DROPPED_AND_REMOVED", str(site / "html/tools/a.php"))]
    finally:
        watcher.close()


def test_a_full_look_every_so_often_catches_what_no_event_shows(site, tmp_path):  # noqa: F811
    # A page that is a link to a file outside the web roots: a change to that file makes no event here.
    outside = tmp_path / "shared/header.php"
    outside.parent.mkdir()
    outside.write_text("<?php echo 'header';\n")
    os.symlink(outside, site / "html/header.php")
    manifest = tmp_path / "webroot.json"
    ww.baseline(manifest, web_roots=[str(site)])
    clock, found, seen = Clock(), [], []

    class Script:
        """No file events at all; each read moves time on, and the first one changes the outside file."""
        def __init__(self):
            self.reads = 0

        def add(self, path):
            return True

        def events(self, timeout):
            self.reads += 1
            seen.append(len(found))
            if self.reads == 1:
                outside.write_text(SHELL_CALL)
                clock.now += ww.RESCAN_SECONDS - 1           # not yet time for a full look
            else:
                clock.now += 2
            return []

        def close(self):
            pass

    class Turns:
        def __init__(self, turns):
            self.turns = turns

        def is_set(self):
            self.turns -= 1
            return self.turns < 0
    watcher = ww.Watcher(manifest, found.append, notify=Script(), clock=clock)
    watcher.run(Turns(3))
    assert seen[:2] == [0, 0], "no event, and not yet time for a full look"
    assert rules(found) == [("WEB_LINK_CHANGED", "header.php"), ("WEB_SHELL_PATTERN", "header.php")]
