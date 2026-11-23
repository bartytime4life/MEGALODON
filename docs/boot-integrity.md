# Boot integrity

Whatever runs before the operating system runs before every defense. The
[program integrity check](binary-integrity.md) trusts the package database,
but much of what boots the machine is built on it: the initramfs, the GRUB
configuration, the EFI bootloader copies. Backdoored initramfs images and
bootloaders are a known way to survive reinstalls of everything else (ATT&CK
T1542, T1547.006). `megalodon boot` records the boot files and the kernel's
boot-time protections, and reports what changes.

```bash
sudo megalodon boot baseline
```

```bash
sudo megalodon boot check
```

```bash
sudo megalodon boot accept
```

* **`baseline`** records the following in `~/.config/megalodon/boot.json`
  (mode 600):
  - the SHA-256 of every file under `/boot`: kernels, initramfs images,
    GRUB and its configuration, and the EFI system partition when it is
    mounted at `/boot/efi`;
  - the EFI system partition wherever else it is mounted. That includes
    `/efi`, where systemd-boot mounts it, read by name. It also includes any
    other FAT mount whose partition udev records with the EFI system
    partition's type (`ID_PART_ENTRY_TYPE`
    `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`). A FAT USB stick is not that
    partition, and is not read. Bootkits plant their loaders here;
  - `/etc/default/grub`, `/etc/grub.d`, `/etc/kernel` and the initramfs-tools,
    dracut and mkinitcpio configuration;
  - the running kernel's command line, Secure Boot, kernel lockdown,
    module-signature enforcement and whether module loading is disabled.

  A packaged boot file that already does not match its package is reported
  at once.
* **`check`** reports what changed, most severe first. It exits 1 on
  findings and 2 on an error. Changes that package updates explain are
  listed under `explained` and are not findings. A protection the baseline
  could read but this check cannot, for example after securityfs is
  unmounted, is listed under `gaps` rather than skipped.
* **`accept`** records the current state after a kernel or bootloader update
  you reviewed.

Run it as root, since `/boot` and EFI variables are often readable only by
root. With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The
[scheduler](scheduling.md) runs the check hourly, and the
[response engine](response-engine.md) reads it on every pass.

## Changes and updates

Kernel and bootloader updates change boot files all the time. Each change is
matched against the package manager's own log (`/var/log/dpkg.log`,
`dnf.rpm.log`, `yum.log` or `pacman.log`). A change whose time falls within
30 minutes before, or 5 minutes after, package activity counts as explained.
A packaged file that matches its package is also explained.

The change time used is the file's *change* time (ctime), not its
modification time. Anyone who can edit a file can set its modification time
to match an update, but not its change time.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `BOOT_PACKAGE_MISMATCH` | CRITICAL | A packaged boot file, such as a kernel, does not match the package database |
| `SECURE_BOOT_DISABLED` | HIGH | Secure Boot was on and is now off |
| `LOCKDOWN_WEAKENED` | HIGH | Kernel lockdown is weaker than before (confidentiality → integrity → none) |
| `MODULE_SIGNATURES_OFF` | HIGH | The kernel enforced module signatures and no longer does |
| `CMDLINE_WEAKENED` | HIGH | The running kernel, a GRUB or loader entry, or a quoted `GRUB_CMDLINE_LINUX` value in `/etc/default/grub` gained a parameter that switches a protection off or replaces the first program: `init=`, `rd.break`, `single`, `module.sig_enforce=0`, `lockdown=none`, `apparmor=0`, `selinux=0`, `enforcing=0`, `security=none`, `audit=0`, `ima_appraise=off`, `nokaslr`, `mitigations=off`, `lsm=`. Reported even when an update explains the file change |
| `BOOT_FILE_CHANGED`, `BOOT_FILE_ADDED` | HIGH | A kernel, initramfs or bootloader file changed or appeared with no package update near that time |
| `BOOT_CONFIG_CHANGED` | MEDIUM | Bootloader or initramfs configuration changed with no package update near that time |
| `CMDLINE_CHANGED` | MEDIUM | The running kernel's command line changed in another way |
| `BOOT_FILE_REMOVED` | MEDIUM | A recorded boot file was removed |

The **boot-tampering** response playbook covers the HIGH and CRITICAL rules.
It collects evidence and notifies you: what runs before every defense cannot
be repaired from inside it.

## Limits

* **It checks the files, not what the firmware loaded.** A bootloader that
  was replaced and then put back before the check, or firmware-level
  implants, are not seen. Measured boot (TPM event logs) would go further.
* **Package activity explains changes broadly.** A change made during the
  same half hour as an update is counted as explained. Review `explained`
  after updates, and run `accept` when the update is complete.
* **The EFI system partition must be mounted.** It is read wherever it is
  mounted. On a machine booted with UEFI where it is not mounted at all, the
  report lists a gap: MEGALODON does not mount it, since that would change
  the machine. A `/boot/efi` or `/efi` folder left on the root file system
  does not count: the gap is lifted only by a FAT file system mounted there.
  Without udev's records, as in some containers, only `/boot/efi` and `/efi`
  are read.
* **Containers and virtual machines booted directly** have no `/boot`. The
  report says so, and checks only the kernel's state.
