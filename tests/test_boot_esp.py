"""The EFI system partition, found wherever it is mounted, and a gap when a UEFI machine has it unmounted."""
from __future__ import annotations

import os
import shutil

from megalodon import boot_integrity as bi
from test_boot_integrity import root  # noqa: F401


def mount(base, where, fstype="vfat", esp=True):
    """A FAT mount at `where`, recorded in the mount table and, with `esp`, by udev as the EFI system partition."""
    folder = base / where.lstrip("/")
    folder.mkdir(parents=True, exist_ok=True)
    escaped = where.replace(" ", "\\040")
    with open(base / "proc/self/mounts", "a") as table:
        table.write(f"/dev/sda1 {escaped} {fstype} rw,relatime,fmask=0077 0 0\n")
    device = os.stat(folder).st_dev
    record = base / f"run/udev/data/b{os.major(device)}:{os.minor(device)}"
    record.parent.mkdir(parents=True, exist_ok=True)
    kind = bi.ESP_TYPE if esp else "0fc63daf-8483-4772-8e79-3d69d8477de4"      # a Linux data partition
    record.write_text(f"S:disk/by-partlabel/EFI\nE:ID_FS_TYPE=vfat\nE:ID_PART_ENTRY_TYPE={kind.upper()}\n")
    return folder


def test_the_partition_is_read_wherever_it_is_mounted(root, tmp_path):  # noqa: F811
    shutil.rmtree(root / "boot/efi")
    (root / "proc/self").mkdir(parents=True)
    esp = mount(root, "/boot loader")                    # a mount point with a space, escaped in the table
    (esp / "EFI/BOOT").mkdir(parents=True)
    (esp / "EFI/BOOT/BOOTX64.EFI").write_bytes(b"shim")
    snapshot = bi.snapshot(root=str(root))
    assert snapshot["esp"] == ["/boot loader"]
    assert "/boot loader/EFI/BOOT/BOOTX64.EFI" in snapshot["files"]


def test_a_fat_stick_is_not_the_boot_partition(root):  # noqa: F811
    # Each test stands one partition up: the stand-in mounts share the test folder's device number.
    (root / "proc/self").mkdir(parents=True)
    stick = mount(root, "/media/usb", esp=False)
    (stick / "notes.txt").write_text("x")
    snapshot = bi.snapshot(root=str(root))
    assert snapshot["esp"] == [] and not [f for f in snapshot["files"] if f.startswith("/media/")]


def test_only_fat_mounts_are_looked_up(root):  # noqa: F811
    (root / "proc/self").mkdir(parents=True)
    mount(root, "/data", fstype="ext4")                     # recorded with the partition type, but not FAT
    assert bi.snapshot(root=str(root))["esp"] == []


def test_a_bootloader_changed_on_the_partition_is_reported(root, tmp_path):  # noqa: F811
    manifest = tmp_path / "boot.json"
    (root / "proc/self").mkdir(parents=True)
    esp = mount(root, "/esp")
    (esp / "EFI/systemd").mkdir(parents=True)
    (esp / "EFI/systemd/systemd-bootx64.efi").write_bytes(b"systemd-boot")
    bi.baseline(manifest, root=str(root))
    (esp / "EFI/systemd/systemd-bootx64.efi").write_bytes(b"a different loader")
    (esp / "EFI/Microsoft/Boot").mkdir(parents=True)
    (esp / "EFI/Microsoft/Boot/bootmgfw.efi").write_bytes(b"planted")
    report = bi.check(manifest)
    assert sorted((f["rule_id"], f["subject"]) for f in report["findings"]) == [
        ("BOOT_FILE_ADDED", "/esp/EFI/Microsoft/Boot/bootmgfw.efi"),
        ("BOOT_FILE_CHANGED", "/esp/EFI/systemd/systemd-bootx64.efi")]


def test_efi_is_read_by_name_and_a_partition_under_boot_once(root):  # noqa: F811
    (root / "efi/loader/entries").mkdir(parents=True)
    (root / "efi/loader/entries/arch.conf").write_text("linux /vmlinuz-linux\noptions root=/dev/sda2 rw\n")
    (root / "proc/self").mkdir(parents=True)
    mount(root, "/boot/efi")
    snapshot = bi.snapshot(root=str(root))
    assert "/efi/loader/entries/arch.conf" in snapshot["files"]
    assert snapshot["esp"] == ["/boot/efi"] and "/boot/efi/EFI/debian/grubx64.efi" in snapshot["files"]


def test_a_uefi_machine_with_its_partition_unmounted_is_a_gap(root):  # noqa: F811
    assert not [g for g in bi.snapshot(root=str(root))["gaps"] if "EFI system partition" in g], \
        "its loaders are already under /boot/efi"
    shutil.rmtree(root / "boot/efi")
    gap = [g for g in bi.snapshot(root=str(root))["gaps"] if "EFI system partition is not mounted" in g]
    assert len(gap) == 1
    shutil.rmtree(root / "sys/firmware/efi")                # a machine booted by BIOS has no such partition
    assert not [g for g in bi.snapshot(root=str(root))["gaps"] if "EFI system partition" in g]


def test_a_folder_on_the_root_file_system_is_not_a_mounted_partition(root):  # noqa: F811
    # The partition unmounted: what is left at /boot/efi is the root file system's own folder, empty or stale.
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw,relatime 0 0\n")
    unmounted = "EFI system partition is not mounted"
    assert [g for g in bi.snapshot(root=str(root))["gaps"] if unmounted in g], "stale loaders under /boot/efi"
    shutil.rmtree(root / "boot/efi/EFI")
    (root / "boot/efi/EFI").mkdir()
    (root / "efi/EFI").mkdir(parents=True)
    assert [g for g in bi.snapshot(root=str(root))["gaps"] if unmounted in g], "empty folders"


def test_a_fat_mount_where_the_partition_goes_is_enough_without_udev(root):  # noqa: F811
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/self/mounts").write_text("/dev/sda2 / ext4 rw 0 0\n/dev/sda1 /boot/efi vfat rw,fmask=0077 0 0\n")
    snapshot = bi.snapshot(root=str(root))                 # no /run/udev here, as in many containers
    assert snapshot["esp"] == [] and not [g for g in snapshot["gaps"] if "EFI system partition" in g]
    assert "/boot/efi/EFI/debian/grubx64.efi" in snapshot["files"]
