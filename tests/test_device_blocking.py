"""Live device blocking: kernel events, one plug-in of one device as the target, block_device and its undo."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import threading
import time

import pytest

from megalodon import device_watch as dw
from megalodon import enforcement as en
from megalodon import response_engine as re_
from megalodon.respond_now import Responder
from test_device_watch import sysfs, usb  # noqa: F401
from test_enforcement import enable, p  # noqa: F401

LETTERS = "120000000000000 0 0 0 7fffffffffffffff ffffffffffffffff fffffffffffffffe"    # a full keyboard's keys
MOUSE = "1f0000 0 0 0 0"                                                                # buttons only


def plugged(sysfs, port, number, *, keys=None, vendor="1234", product="5678", name="Gadget",
            interfaces=("03/01/01",)):
    usb(sysfs, port, vendor, product, name, list(interfaces))
    folder = sysfs / "bus/usb/devices" / port
    (folder / "devnum").write_text(f"{number}\n")
    (folder / "authorized").write_text("1\n")
    if keys:
        input_device(sysfs, f"input{number}", folder / f"{port}:1.0/input", keys)
    return f"{port}#{number}@usb:{vendor}:{product}:{name}"


def input_device(sysfs, name, parent, keys):
    real = Path(parent) / name
    (real / "capabilities").mkdir(parents=True)
    (real / "capabilities/key").write_text(keys + "\n")
    (real / "name").write_text(name + "\n")
    (sysfs / "class/input").mkdir(parents=True, exist_ok=True)
    os.symlink(real, sysfs / "class/input" / name)


def authorized(sysfs, port):
    return (sysfs / "bus/usb/devices" / port / "authorized").read_text()[0]


@pytest.fixture
def laptop(sysfs):
    """The fixture's machine, with a built-in keyboard that is not on USB."""
    input_device(sysfs, "input0", sysfs / "devices/platform/i8042/serio0/input", LETTERS)
    return sysfs


def test_a_finding_names_each_plug_in(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    target = plugged(sysfs, "1-7", 5)
    [found] = dw.check(manifest, sysfs=str(sysfs))["findings"]
    assert (found["rule_id"], found["targets"]) == ("NEW_USB_KEYBOARD", [target])
    (sysfs / "bus/usb/devices/1-7/devnum").write_text("6\n")      # unplugged and plugged in again
    assert dw.check(manifest, sysfs=str(sysfs))["findings"][0]["targets"] == ["1-7#6@usb:1234:5678:Gadget"]


def test_the_watch_checks_as_soon_as_the_kernel_says_a_device_arrived(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    kernel, events = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    events.setblocking(False)
    found, stop = [], threading.Event()
    thread = threading.Thread(target=dw.watch, args=(manifest, found.append), daemon=True,
                              kwargs=dict(interval=60, stop=stop, events=events, sysfs=str(sysfs)))
    thread.start()
    try:
        time.sleep(0.2)
        plugged(sysfs, "1-7", 5)
        kernel.send(b"add@/devices/pci0/power\0ACTION=add\0SUBSYSTEM=power_supply\0")
        time.sleep(0.4)
        assert found == [], "an event about something else does not start a check"
        started = time.monotonic()
        kernel.send(b"add@/devices/pci0/usb1/1-7\0ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0")
        while not found and time.monotonic() - started < 5:
            time.sleep(0.01)
        assert [f["rule_id"] for f in found] == ["NEW_USB_KEYBOARD"]
        assert time.monotonic() - started < 1, "within moments, not at the next 60 s check"
        (sysfs / "bus/usb/devices/1-7/devnum").write_text("6\n")
        kernel.send(b"add@/devices/pci0/usb1/1-7\0ACTION=add\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0")
        deadline = time.monotonic() + 5
        while len(found) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert [f["targets"] for f in found] == [["1-7#5@usb:1234:5678:Gadget"], ["1-7#6@usb:1234:5678:Gadget"]], \
            "plugged in again, it is reported again"
    finally:
        stop.set()
        thread.join(5)
        kernel.close()
        events.close()


def test_keyboards_are_told_from_mice_and_from_the_device_itself(laptop):
    plugged(laptop, "1-7", 5, keys=LETTERS)
    plugged(laptop, "1-8", 6, keys=MOUSE, name="Mouse", interfaces=("03/01/02",))
    assert dw.keyboards(str(laptop)) == ["input0", "input5"]
    assert dw.keyboards(str(laptop), besides="1-7") == ["input0"], "the device's own keyboard does not count"


def test_a_new_keyboard_is_cut_off_and_let_back(laptop, tmp_path):
    target = plugged(laptop, "1-7", 5, keys=LETTERS)
    executor = en.Executor(sysfs=str(laptop), quarantine=tmp_path / "q")
    undo = executor.block_device(target, {})
    assert undo == dict(port="1-7", interfaces=["03/01/01"]) and authorized(laptop, "1-7") == "0"
    executor.undo_block_device(dict(target=target, undo=undo))
    assert authorized(laptop, "1-7") == "1"


def test_only_that_plug_in_of_that_device_is_ever_cut_off(laptop, tmp_path):
    target = plugged(laptop, "1-7", 5, keys=LETTERS)
    executor = en.Executor(sysfs=str(laptop), quarantine=tmp_path / "q")
    (laptop / "bus/usb/devices/1-7/devnum").write_text("6\n")
    with pytest.raises(en.DeviceGone, match="no longer the one decided on"):
        executor.block_device(target, {})
    with pytest.raises(en.DeviceGone, match="no USB device is on port 1-9"):
        executor.block_device("1-9#5@usb:1234:5678:Gadget", {})
    with pytest.raises(en.EnforcementError, match="only one plug-in"):
        executor.block_device("usb:1234:5678:Gadget", {})
    assert authorized(laptop, "1-7") == "1"
    # Unplugged after it was cut off: there is nothing to let back, and undo says done.
    executor.undo_block_device(dict(target=target, undo={}))
    assert authorized(laptop, "1-7") == "1"


def test_the_only_keyboard_is_never_cut_off(sysfs, tmp_path):
    executor = en.Executor(sysfs=str(sysfs), quarantine=tmp_path / "q")
    # On a machine with no keyboard at all, a network adapter is still cut off: it is not a keyboard.
    adapter = plugged(sysfs, "1-6", 4, name="Adapter", interfaces=("02/06/00", "0a/00/00"))
    assert dw.keyboards(str(sysfs)) == []
    executor.block_device(adapter, {})
    assert authorized(sysfs, "1-6") == "0"
    target = plugged(sysfs, "1-7", 5, keys=LETTERS)
    with pytest.raises(en.EnforcementError, match="only keyboard"):
        executor.block_device(target, {})
    assert authorized(sysfs, "1-7") == "1"


def test_the_engine_plans_exact_targets_only(tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    guards = re_.Guards(re_.load_policy(policy), {}, re_._now(), protected=set())
    assert guards.check("block_device", "1-7#5@usb:1234:5678:Gadget") is None
    assert "one plug-in" in guards.check("block_device", "usb:1234:5678:Gadget")
    assert "one plug-in" in guards.check("block_device", "../../x#5@usb:1234:5678:Gadget")


def test_a_device_plugged_in_is_cut_off_at_once(laptop, tmp_path, p):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(laptop))
    enable(p, ["block_device"], ["new-hardware"])
    responder = Responder(policy=p["policy"], ledger=p["ledger"], state=p["state"], enforcement_policy=p["enforce"],
                          journal=p["journal"], enforcement_state=p["enforce_state"],
                          executor=en.Executor(sysfs=str(laptop), quarantine=p["quarantine"]))
    target = plugged(laptop, "1-7", 5, keys=LETTERS)
    [found] = dw.check(manifest, sysfs=str(laptop))["findings"]
    answer = dw.respond(found, responder)
    [applied] = answer["enforcement"]["applied"]
    assert (applied["action"], applied["target"]) == ("block_device", target) and authorized(laptop, "1-7") == "0"
    en.undo(applied["id"], journal=p["journal"], executor=en.Executor(sysfs=str(laptop), quarantine=p["quarantine"]))
    assert authorized(laptop, "1-7") == "1"
    # The same device plugged in again is a new plug-in, and is decided again.
    (laptop / "bus/usb/devices/1-7/devnum").write_text("6\n")
    [again] = dw.check(manifest, sysfs=str(laptop))["findings"]
    assert dw.respond(again, responder)["enforcement"]["applied"][0]["target"] == "1-7#6@usb:1234:5678:Gadget"
    assert authorized(laptop, "1-7") == "0"


def test_the_scheduled_watch_listens_and_answers_at_once(tmp_path, monkeypatch):
    from megalodon import schedule as sc
    job = next(j for j in sc.JOBS if j.name == "devices")
    assert job.calendar is None and job.command == ("devices", "watch", "--alert", "--respond")
    folder = tmp_path / "units"
    folder.mkdir()
    (folder / "megalodon-devices.timer").write_text(sc.MARKER + "\n[Timer]\nOnCalendar=*:0/5\n")
    calls = []

    class Done:
        returncode, stdout, stderr = 0, "", ""
    home = tmp_path / "home"
    (home / ".config/megalodon").mkdir(parents=True)
    (home / ".config/megalodon/devices.json").write_text("{}")
    monkeypatch.setenv("HOME", str(home))
    result = sc.install(system=False, only=["devices"], directory=folder, launcher=["m"],
                        runner=lambda system, *args: calls.append(args) or Done())
    assert result["retired"] == [str(folder / "megalodon-devices.timer")]
    assert ("disable", "--now", "megalodon-devices.timer") in calls and not (folder / "megalodon-devices.timer").exists()
    assert result["enabled"] == ["megalodon-devices.service"]
