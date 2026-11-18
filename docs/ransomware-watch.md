# Ransomware watch

`megalodon ransomware watch` watches folders you choose and raises an alarm
while files are being encrypted. It doesn't wait for the ransom note. It runs
on Linux, uses inotify and needs no extra package.

```bash
megalodon ransomware selftest
```

```bash
megalodon ransomware watch --dir ~/Documents --dir ~/Pictures --dir /srv/share
```

`selftest` encrypts throwaway files in a temporary folder and confirms both
alarms fire. Run it after installing and after changes. `watch` runs until you
stop it. It prints each finding as one JSON line, and sends it to your
[off-machine alerts](off-machine-alerts.md) when `[alerts]` is configured in
`~/.config/megalodon/settings.toml` (or the file given with `--config`), so a
phone push or SIEM still gets it if the machine is lost.

## What raises the alarm

| Finding | Severity | When |
| --- | --- | --- |
| `RANSOMWARE_ENCRYPTION` | CRITICAL | At least `--min-files` (default 10) files turned from a recognized format into encrypted-looking data within `--window` seconds (default 60) |
| `RANSOMWARE_MASS_WRITE` | HIGH | Three times that many new encrypted-looking files with no recognized predecessor in one window |
| `RANSOM_NOTE` | HIGH | A file named like a ransom note was created (`_readme.txt`, `HOW_TO_DECRYPT.txt`, `!!!READ_ME_TO_DECRYPT!!!.txt`, `RESTORE_FILES.html`, ...) |

All three map to ATT&CK T1486 (Data Encrypted for Impact).

* **How a file is judged.** The first 64 KiB of each written file is sampled.
  It counts as *recognized* when it starts with a known format signature
  (PDF, Office/ZIP, JPEG, PNG, GIF, audio and video, gzip, 7z, SQLite,
  executables and more) or is readable text. It counts as *encrypted-looking*
  when it has no signature, isn't text and its byte entropy is at least
  7.5 bits per byte. Files under 1 KiB are not judged.
* **What counts toward the alarm.** An encrypted-looking write counts when:
  * the same file was recognized before, which is in-place encryption;
  * it replaces a file just deleted or renamed in the same folder: the same
    name, the old name plus an extension (`report.docx.locked`) or the same
    stem with a new extension; or
  * it carries a ransomware extension (`.locked`, `.crypt`, `.encrypted`, ...).

  The watch records what existing files look like when it starts, so
  in-place rewrites can be compared.
* **Who is doing it.** Each finding lists, best effort, the processes that
  have files open under the watched folders, with process ID, name and program
  path, read from `/proc`. Run as an ordinary user, the watch sees that
  user's processes. Run it as root to see everyone's.
* **Never acts.** Nothing is blocked, killed or restored. On an alarm, take
  the machine off the network, stop the listed process and restore from an
  offline backup.

Everyday activity does not count: new or copied photos, archives and Office
files all carry signatures, text edits stay text, and an ordinary
`README.txt` is not a ransom note. The tests check this with a mixed burst.

## Run it all the time

A systemd user service keeps the watch running. Create
`~/.config/systemd/user/megalodon-ransomware.service`:

```ini
[Unit]
Description=MEGALODON ransomware watch

[Service]
ExecStart=%h/.local/share/megalodon/current/venv/bin/python -I -m megalodon ransomware watch --dir %h/Documents --dir %h/Pictures
Restart=on-failure

[Install]
WantedBy=default.target
```

Then enable it:

```bash
systemctl --user enable --now megalodon-ransomware.service
```

Findings then appear in `journalctl --user -u megalodon-ransomware`, and in
your configured alerts.

## Limits

* **It's an alarm, not prevention.** Some files are encrypted before the
  threshold is reached: about `--min-files`, plus whatever is written while
  you respond. Keep offline or versioned backups.
* **Coverage is what inotify sees.** Hidden folders (starting with `.`) are
  skipped. At most 8,192 folders are watched; the start message says when that
  limit cut coverage, and the kernel's `fs.inotify.max_user_watches` may need
  raising. Network shares only report changes made from this machine. Changes
  made while the watch is not running are not seen.
* **Partial or format-preserving encryption.** Ransomware that leaves the
  first 64 KiB intact, or wraps its output in a recognized container, is not
  judged encrypted. A ransom note or `MASS_WRITE` may still fire.
* **Look-alikes.** Encrypting many of your own files (GnuPG, `age`, VeraCrypt
  containers, encrypted backups written into a watched folder) looks exactly
  like this. Point the watch at the folders you care about, not at backup
  destinations.
* **Process list.** The list is best effort. A process that has already
  closed its files is not listed, and the list never proves which process
  wrote what.
