# Credential access watch

Info-stealers are the most common malware on desktops and developer
machines. They read:
- SSH keys;
- browser password and cookie stores;
- cloud and developer tokens;
- keyrings and cryptocurrency wallets.

Then they ship it all out within seconds (ATT&CK T1552, T1555, T1539).
[Canaries](host-tripwires.md) catch reads of decoys. `megalodon credentials`
watches the real files and reports which program opened them.

```bash
sudo megalodon credentials watch
```

```bash
megalodon credentials check
```

* **`watch`** reports each unexpected open as a JSON line, as it happens.
  Pipe it into the [response engine](response-engine.md):

  ```bash
  sudo megalodon credentials watch | megalodon respond ingest
  ```

  As root it uses the kernel's file-access notifications (fanotify), which
  name the process behind every open. It also follows the kernel's process
  events, so a reader that exits at once can still be named. Without root
  it uses inotify, which sees the open but not the process. A program is
  named only if it still holds the file open when the open is handled.
* **`check`** reports programs holding credential files open right now, and
  exits 1 on findings. The response engine runs it on every pass.
* **`allow PROGRAM [--category ssh|browser|cloud|keyring|wallet|system|any]`**
  records, after review, a program that may read credentials, such as a
  backup tool. The allow list is
  `~/.config/megalodon/credential-allow.json` (mode 600), and the
  [tamper check](tamper-detection.md) watches it.

As root, every user's home is watched (UID 0 and 1000 and up). Otherwise,
only your own is. With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The contents of the files are
never read.

## What is watched, and who may read it

| Kind | Files | Expected readers |
| --- | --- | --- |
| ssh | `~/.ssh/id_*` and other private keys (not `.pub`) | `ssh`, `ssh-add`, `ssh-agent`, `ssh-keygen`, `scp`, `sftp`, `sshd`, key agents |
| browser | Firefox `logins.json`, `key4.db`, `cookies.sqlite`; Chrome, Chromium, Brave, Edge, Vivaldi and Opera `Login Data`, `Cookies`, `Web Data`, `Local State` | the browsers themselves |
| cloud | `~/.aws`, gcloud and Azure tokens, `~/.kube/config`, `~/.docker/config.json`, `~/.git-credentials`, `~/.netrc`, `~/.npmrc`, `~/.pypirc`, `gh` and Terraform tokens | `aws`, `gcloud`, `az`, `kubectl`, `helm`, `docker`, `terraform`, `gh`, `git`, `npm`, `pip`, `twine`, `curl` and similar |
| keyring | GNOME keyrings, GnuPG private keys, KWallet | the keyring daemons, `gpg`, `pass`, KeePassXC |
| wallet | Bitcoin, Electrum, Ethereum keystores, Exodus, Atomic | the wallets themselves |
| system | `/etc/shadow`, `/etc/gshadow`, their backups, `/etc/security/opasswd`, SSH host keys | `sshd`, `login`, `passwd`, `su`, `sudo`, PAM helpers, account tools, `cron`, display managers, `dpkg` |

An expected reader counts only when the program (and its script, for an
interpreter) is installed where packages put programs: `/usr`, `/bin`,
`/sbin`, `/lib`, `/opt` or `/snap`. A program called `ssh` in a home folder
or `/tmp` is not `ssh`.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `CREDENTIAL_SWEEP` | CRITICAL | One process opened credentials of two or more kinds within 2 minutes, as an info-stealer does |
| `CREDENTIAL_READ_BY_DROPPED_TOOL` | CRITICAL | A program run from a temporary folder, a deleted file or memory, or a script in a temporary folder, opened a credential file |
| `CREDENTIAL_READ` | HIGH | Any other program that is not an expected reader opened a credential file |

The same program and file are reported once an hour. Each finding names the
program, its process ID with start time, its command line and the file.

## Response

* **credential-theft** covers `CREDENTIAL_SWEEP` and
  `CREDENTIAL_READ_BY_DROPPED_TOOL`. It plans to collect evidence, suspend
  that process and notify you.
* **credential-read** covers `CREDENTIAL_READ`. It plans to collect evidence
  and notify you, because backups and migrations also read credentials.

## Limits

* **Root sees everything.** Without root, only your own home is watched,
  and a reader that closes the file before it is noticed goes unnamed. The
  watch counts these as `unattributed` in the statistics it prints when it
  stops.
* **Very short readers.** Even as root, a program that opens a file and
  exits within microseconds can occasionally finish before it is
  identified, and is counted as `unattributed`.
* **A known program loading hostile code**, such as a browser extension or a
  malicious package run by `npm`, reads as that program and is not
  reported.
* **Copies made earlier.** Credentials copied elsewhere before the watch
  started, or read through a backup, are not covered.
* **MEGALODON's own evidence collection and your backup tools** appear as
  readers. Allow them after review.
