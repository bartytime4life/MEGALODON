"""Boot integrity: kernels against their packages, changes against package activity, boot-time protections."""
from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path

import pytest

from megalodon import boot_integrity as bi
from megalodon import response_engine as re_

CMDLINE = "BOOT_IMAGE=/vmlinuz-6.1.0-9 root=UUID=abcd ro quiet\n"


@pytest.fixture
def root(tmp_path):
    base = tmp_path / "root"
    files = {
        "boot/vmlinuz-6.1.0-9": b"kernel image 6.1.0-9",
        "boot/initrd.img-6.1.0-9": b"initramfs 6.1.0-9",
        "boot/grub/grub.cfg": b"menuentry 'Debian' {\n  linux /vmlinuz-6.1.0-9 root=UUID=abcd ro quiet\n}\n",
        "boot/efi/EFI/debian/grubx64.efi": b"bootloader",
        "etc/default/grub": b'GRUB_CMDLINE_LINUX_DEFAULT="quiet"\n',
        "proc/cmdline": CMDLINE.encode(),
        "sys/kernel/security/lockdown": b"none [integrity] confidentiality\n",
        "sys/module/module/parameters/sig_enforce": b"Y\n",
        "var/log/dpkg.log": b"2026-01-01 10:00:00 status installed base-files:amd64 13\n",
    }
    for path, data in files.items():
        (base / path).parent.mkdir(parents=True, exist_ok=True)
        (base / path).write_bytes(data)
    (base / "sys/firmware/efi/efivars").mkdir(parents=True)
    (base / f"{bi.SECURE_BOOT_VAR}").write_bytes(b"\x06\x00\x00\x00\x01")
    (base / "var/lib/dpkg/info").mkdir(parents=True)
    (base / "var/lib/dpkg/info/linux-image-6.1.0-9-amd64.md5sums").write_text(
        f"{hashlib.md5(files['boot/vmlinuz-6.1.0-9']).hexdigest()}  boot/vmlinuz-6.1.0-9\n")
    return base


def rules(report):
    return sorted((f["rule_id"], f["subject"]) for f in report["findings"])


def package_activity_now(root):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(root / "var/log/dpkg.log", "a") as log:
        log.write(f"{stamp} trigproc initramfs-tools:all 0.142 <none>\n")


def test_a_clean_machine_and_its_protections_are_recorded(root, tmp_path):
    manifest = tmp_path / "boot.json"
    result = bi.baseline(manifest, root=str(root))
    assert result["files"] == 5 and result["findings"] == [] and oct(manifest.stat().st_mode & 0o777) == "0o600"
    assert result["kernel"]["secure_boot"] is True and result["kernel"]["lockdown"] == "integrity"
    assert result["kernel"]["sig_enforce"] == "Y"
    report = bi.check(manifest)
    assert report["findings"] == [] and report["explained"] == []


def test_tampered_kernel_initramfs_and_bootloader(root, tmp_path):
    manifest = tmp_path / "boot.json"
    bi.baseline(manifest, root=str(root))
    (root / "boot/vmlinuz-6.1.0-9").write_bytes(b"kernel image 6.1.0-9, patched")      # no update made this
    (root / "boot/initrd.img-6.1.0-9").write_bytes(b"initramfs with an extra hook")
    (root / "boot/efi/EFI/debian/shimx64.efi").write_bytes(b"another bootloader")
    with open(root / "boot/grub/grub.cfg", "a") as cfg:
        cfg.write("menuentry 'x' {\n  linux /vmlinuz-6.1.0-9 ro init=/bin/sh\n}\n")
    report = bi.check(manifest)
    assert rules(report) == [
        ("BOOT_CONFIG_CHANGED", "/boot/grub/grub.cfg"), ("BOOT_FILE_ADDED", "/boot/efi/EFI/debian/shimx64.efi"),
        ("BOOT_FILE_CHANGED", "/boot/initrd.img-6.1.0-9"), ("BOOT_PACKAGE_MISMATCH", "/boot/vmlinuz-6.1.0-9"),
        ("CMDLINE_WEAKENED", "/boot/grub/grub.cfg")]
    assert report["findings"][0]["rule_id"] == "BOOT_PACKAGE_MISMATCH"
    assert report["findings"][0]["severity"] == "CRITICAL"
    weakened = next(f for f in report["findings"] if f["rule_id"] == "CMDLINE_WEAKENED")
    assert weakened["parameters"] == ["init=/bin/sh"]


def test_an_initramfs_rebuilt_during_an_update_is_explained(root, tmp_path):
    manifest = tmp_path / "boot.json"
    bi.baseline(manifest, root=str(root))
    package_activity_now(root)
    (root / "boot/initrd.img-6.1.0-9").write_bytes(b"initramfs rebuilt by update-initramfs")
    (root / "boot/vmlinuz-6.1.0-10").write_bytes(b"new kernel")
    report = bi.check(manifest)
    assert report["findings"] == []
    assert sorted(e["subject"] for e in report["explained"]) == ["/boot/initrd.img-6.1.0-9", "/boot/vmlinuz-6.1.0-10"]
    assert "package activity" in report["explained"][0]["detail"]
    bi.accept(manifest)
    assert bi.check(manifest)["explained"] == []


def test_weakened_boot_time_protections(root, tmp_path):
    manifest = tmp_path / "boot.json"
    bi.baseline(manifest, root=str(root))
    (root / "proc/cmdline").write_text(CMDLINE.strip() + " module.sig_enforce=0 lockdown=none\n")
    (root / bi.SECURE_BOOT_VAR).write_bytes(b"\x06\x00\x00\x00\x00")
    (root / "sys/kernel/security/lockdown").write_text("[none] integrity confidentiality\n")
    (root / "sys/module/module/parameters/sig_enforce").write_text("N\n")
    report = bi.check(manifest)
    assert rules(report) == [("CMDLINE_WEAKENED", "kernel:cmdline"), ("LOCKDOWN_WEAKENED", "kernel:lockdown"),
                             ("MODULE_SIGNATURES_OFF", "kernel:sig_enforce"),
                             ("SECURE_BOOT_DISABLED", "kernel:secure_boot")]
    assert next(f for f in report["findings"] if f["subject"] == "kernel:cmdline")["parameters"] == [
        "lockdown=none", "module.sig_enforce=0"]
    # A harmless change to the command line is reported, at a lower level.
    (root / "proc/cmdline").write_text(CMDLINE.strip() + " splash\n")
    assert ("CMDLINE_CHANGED", "kernel:cmdline") in rules(bi.check(manifest))


def test_a_mismatched_packaged_kernel_is_reported_at_baseline(root, tmp_path):
    (root / "boot/vmlinuz-6.1.0-9").write_bytes(b"already patched")
    result = bi.baseline(tmp_path / "boot.json", root=str(root))
    assert [(f["rule_id"], f["subject"]) for f in result["findings"]] == [
        ("BOOT_PACKAGE_MISMATCH", "/boot/vmlinuz-6.1.0-9")]


def test_findings_reach_the_response_engine_and_the_cli(root, tmp_path, capsys):
    manifest = tmp_path / "boot.json"
    bi.baseline(manifest, root=str(root))
    (root / "sys/module/module/parameters/sig_enforce").write_text("N\n")
    signals = re_.path_signals(bi.check(manifest), "boot", "subject")
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    re_.run(policy_path=policy, ledger=tmp_path / "ledger.jsonl", state_path=tmp_path / "state.json",
            signals=signals, protected=set())
    decision = json.loads((tmp_path / "ledger.jsonl").read_text().splitlines()[0])
    assert decision["playbook"] == "boot-tampering"
    assert [a["action"] for a in decision["actions"]] == ["collect_evidence", "notify"]
    from megalodon.cli import main
    with pytest.raises(SystemExit) as exit_:
        main(["boot", "check", "--manifest", str(manifest)])
    assert exit_.value.code == 1
    assert json.loads(capsys.readouterr().out)["findings"][0]["rule_id"] == "MODULE_SIGNATURES_OFF"
    os.chmod(manifest, 0o644)
    with pytest.raises(SystemExit) as exit_:
        main(["boot", "check", "--manifest", str(manifest)])
    assert exit_.value.code == 2
