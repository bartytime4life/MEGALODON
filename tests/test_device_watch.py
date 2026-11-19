"""Device watch: new keyboards, network adapters, storage and Thunderbolt devices, over constructed /sys trees."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading

import pytest

from megalodon import device_watch as dw
from megalodon import response_engine as re_


def usb(sysfs, port, vendor, product, name, interfaces, serial=""):
    base = sysfs / "bus/usb/devices"
    folder = base / port
    folder.mkdir(parents=True)
    for field, value in (("idVendor", vendor), ("idProduct", product), ("product", name), ("serial", serial),
                         ("bDeviceClass", "00")):
        if value:
            (folder / field).write_text(value + "\n")
    for number, triple in enumerate(interfaces):
        interface = base / f"{port}:1.{number}"
        interface.mkdir()
        for field, value in zip(("bInterfaceClass", "bInterfaceSubClass", "bInterfaceProtocol"), triple.split("/")):
            (interface / field).write_text(value + "\n")


def netdev(sysfs, name, address, device_path):
    device = sysfs / device_path
    device.mkdir(parents=True)
    folder = sysfs / "class/net" / name
    folder.mkdir(parents=True)
    os.symlink(device, folder / "device")
    (folder / "address").write_text(address + "\n")


def disk(sysfs, name, model, removable, under_usb):
    real = sysfs / ("devices/pci0/usb1/1-4/host0/block" if under_usb else "devices/pci0/ata1/block") / name
    (real / "device").mkdir(parents=True)
    (real / "removable").write_text("1\n" if removable else "0\n")
    (real / "device/model").write_text(model + "\n")
    (sysfs / "block").mkdir(exist_ok=True)
    os.symlink(real, sysfs / "block" / name)


@pytest.fixture
def sysfs(tmp_path):
    root = tmp_path / "sys"
    usb(root, "1-1", "046d", "c31c", "Logitech Keyboard", ["03/01/01"], serial="K1")
    usb(root, "1-2", "046d", "c077", "Logitech Mouse", ["03/01/02"])
    usb(root, "1-3", "0781", "5583", "SanDisk Ultra", ["08/06/50"], serial="S1")
    netdev(root, "eth0", "02:00:00:00:00:01", "devices/pci0/0000:00:03.0")
    netdev(root, "docker0", "02:42:00:00:00:01", "devices/virtual/net/docker0")
    disk(root, "sda", "Samsung SSD", False, False)
    return root


def rules(report):
    return sorted((f["rule_id"], f["device"]) for f in report["findings"])


def test_new_attack_shaped_devices_are_reported(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    result = dw.baseline(manifest, sysfs=str(sysfs))
    assert result["devices"] == 4 and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert dw.check(manifest, sysfs=str(sysfs))["findings"] == []
    # A keystroke-injection stick that also offers storage, a USB network implant, a plain stick and a disk.
    usb(sysfs, "1-4", "05ac", "0220", "Apple Keyboard", ["03/00/00", "08/06/50"])
    usb(sysfs, "1-5", "0b95", "1790", "USB Ethernet", ["02/06/00", "0a/00/00"], serial="N1")
    usb(sysfs, "1-6", "0951", "1666", "DataTraveler", ["08/06/50"], serial="D1")
    netdev(sysfs, "usb0", "8a:00:00:00:00:09", "devices/pci0/usb1/1-5/1-5:1.0")
    disk(sysfs, "sdb", "DataTraveler", True, True)
    netdev(sysfs, "veth12", "aa:00:00:00:00:01", "devices/virtual/net/veth12")
    report = dw.check(manifest, sysfs=str(sysfs))
    assert rules(report) == [
        ("NEW_NETWORK_ADAPTER", "net:8a:00:00:00:00:09"), ("NEW_NETWORK_ADAPTER", "usb:0b95:1790:N1"),
        ("NEW_REMOVABLE_DISK", "disk:DataTraveler:-"), ("NEW_USB_KEYBOARD", "usb:05ac:0220:Apple Keyboard"),
        ("NEW_USB_STORAGE", "usb:0951:1666:D1")]
    assert [f["severity"] for f in report["findings"]][:3] == ["HIGH", "HIGH", "HIGH"]
    assert report["findings"][0]["techniques"]


def test_a_known_device_that_gains_a_keyboard_is_reported(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    interface = sysfs / "bus/usb/devices/1-3:1.1"
    interface.mkdir()
    for field, value in (("bInterfaceClass", "03"), ("bInterfaceSubClass", "01"), ("bInterfaceProtocol", "01")):
        (interface / field).write_text(value)
    found = dw.check(manifest, sysfs=str(sysfs))["findings"]
    assert [(f["rule_id"], f["severity"]) for f in found] == [("DEVICE_GAINED_FUNCTIONS", "HIGH")]
    assert "03/01/01" in found[0]["detail"]


def test_moving_a_device_to_another_port_is_not_new(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    os.rename(sysfs / "bus/usb/devices/1-3", sysfs / "bus/usb/devices/2-1")
    os.rename(sysfs / "bus/usb/devices/1-3:1.0", sysfs / "bus/usb/devices/2-1:1.0")
    assert dw.check(manifest, sysfs=str(sysfs))["findings"] == []


def test_thunderbolt_and_accept(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    folder = sysfs / "bus/thunderbolt/devices/0-1"
    folder.mkdir(parents=True)
    (folder / "unique_id").write_text("d1e2\n")
    (folder / "device_name").write_text("Dock\n")
    assert rules(dw.check(manifest, sysfs=str(sysfs))) == [("NEW_THUNDERBOLT_DEVICE", "thunderbolt:d1e2")]
    dw.accept(manifest, sysfs=str(sysfs))
    assert dw.check(manifest, sysfs=str(sysfs))["findings"] == []
    with pytest.raises(dw.DeviceError, match="use accept"):
        dw.baseline(manifest, sysfs=str(sysfs))
    os.chmod(manifest, 0o644)
    with pytest.raises(dw.DeviceError, match="mode-600"):
        dw.check(manifest, sysfs=str(sysfs))


def test_watch_reports_each_device_once(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    usb(sysfs, "1-7", "1234", "5678", "Gadget", ["03/01/01"])
    found, stop = [], threading.Event()

    def emit(item):
        found.append(item)
        if len(found) >= 1:
            threading.Timer(0.2, stop.set).start()
    dw.watch(manifest, emit, interval=0.05, stop=stop, sysfs=str(sysfs))
    assert [f["rule_id"] for f in found] == ["NEW_USB_KEYBOARD"]


def test_findings_reach_the_response_engine(sysfs, tmp_path):
    manifest = tmp_path / "devices.json"
    dw.baseline(manifest, sysfs=str(sysfs))
    usb(sysfs, "1-8", "05ac", "0220", "Injector", ["03/01/01"])
    signals = re_.path_signals(dw.check(manifest, sysfs=str(sysfs)), "devices", "device")
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decision = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    assert decision["playbook"] == "new-hardware" and [a["action"] for a in decision["actions"]] == ["notify"]


def test_cli(sysfs, tmp_path, capsys, monkeypatch):
    from megalodon.cli import main
    real = dw.snapshot
    monkeypatch.setattr(dw, "snapshot", lambda **kw: real(sysfs=str(sysfs)))
    manifest = tmp_path / "devices.json"

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("devices", "baseline", "--manifest", str(manifest)) == 0
    assert code("devices", "check", "--manifest", str(manifest)) == 0
    usb(sysfs, "1-9", "dead", "beef", "Stick", ["08/06/50"])
    capsys.readouterr()
    assert code("devices", "check", "--manifest", str(manifest)) == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "NEW_USB_STORAGE"
    assert code("devices", "check", "--manifest", str(tmp_path / "none.json")) == 2
