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
  With `--respond`, it decides each finding itself, at once, and runs
  [enforcement](enforcement.md) before it reads the next event, so the
  process it names can be paused while it still runs. What was decided and
  done is written to standard error as one `megalodon: response {...}`
  line. The scheduled `megalodon-credentials` job runs it this way, with the
  exec trace below:

  ```bash
  sudo megalodon credentials watch --respond --trace-execs
  ```

  The five-minute response pass still reads `check`. The same process is
  decided only once, whichever sees it first. Enforcement acts only when its
  policy is on and lists the action and the playbook.

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
only your own is. A credential that is a symbolic link, such as a key linked
from a secrets folder, is reported under its own name. Credential folders and
files created after the watch started, such as a first `aws configure` or a
new browser profile, are picked up within 30 seconds. With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The contents of the files are
never read.

### Naming readers gone at once: `watch --trace-execs`

```bash
sudo megalodon credentials watch --trace-execs
```

File-access notifications give the process ID of every open, but the watch
reads the program from `/proc` only when it handles the open. A reader that
starts, opens a key and exits within microseconds is gone by then, and so
is a burst of quick readers that outruns the watch. With `--trace-execs`,
the watch loads two small eBPF programs that remember every program as the
kernel starts it, so these are named too. On this machine, 300 copies of a
small reader started at once from a hidden temporary folder were all
`unattributed` without it, and all named with it.

* **How.** One program is attached to the kernel's `sched_process_exec`
  tracepoint, and runs in each new program as its exec completes. It records
  the process and parent IDs, the user and group, the command name, the
  start time and the start of the command line (512 bytes), and the paths
  of the executable and the working folder, up to nine names each, with the
  mount each is on. It also records the account that logged in and the login
  session, used by [`commands record --trace-execs`](command-log.md#programs-gone-at-once-record---trace-execs),
  and the mount namespace, the executable's inode and the control groups, which
  [`containers watch`](container-watch.md#escapes-as-they-start-containers-watch)
  uses. The other, on `sched_process_fork`, records each new
  process and its parent, so a worker that forks without exec is named as
  its parent's program. New threads are skipped in the kernel.
* **Which record.** A process still running when its open is handled is
  read from `/proc`, as before. Once it is gone, the kernel's record of its
  exec is used as it is. By the time the trace is read, the process may run
  another program: a parent that forked a reader can run an expected reader
  such as `curl` straight after. So `/proc` adds only whether the same file
  was deleted since. A reused process ID is told apart by its start time,
  and a parent from before the watch is read from `/proc` once, unless it
  runs another program later in the same batch of records. A finding named
  this way has
  `evidence.traced` (the parent's process ID, the user ID and the command
  name, or `forked` and the parent for a forked worker). The statistics the
  watch prints when it stops count these as `named_after_exit`.
* **Paths.** A path is rebuilt from its names and its mount, as
  [`egress watch --trace-connects`](egress-watch.md) does. A path seen only
  in part (`…/.x/agent`: more than nine names, a name of 63 bytes or more
  that may have been cut short, or on a mount of another mount namespace,
  such as a container's) is reported as it is, as a
  program that is not an expected reader. A program run from memory is
  named `/memfd:NAME`, as `/proc` names it. A script run by a relative name
  (`python3 steal.py`) is found through the traced working folder.
* **What it changes.** Like `--trace-connects`, this changes the running
  kernel: the programs only read, nothing on disk is changed, and they are
  removed when the watch stops, however it stops. It needs root and
  file-access notifications, a kernel built with BTF and BPF ring buffers
  (Linux 5.8 or later), on x86-64 or arm64. Where it cannot be loaded, the
  watch says why on standard error and goes on without it. The programs are
  generated by MEGALODON at start, with field offsets from the running
  kernel's own type information, and declare the license "Dual BSD/GPL".
* **Cost.** The kernel runs one program on every exec and one on every fork
  on the machine. Each exec writes a record of about 3.3 KiB and each fork
  one of 24 bytes into an 8 MiB ring buffer, which the watch empties as they
  arrive and reads each new program's `/proc` entry once. If programs start
  faster than that, the kernel drops records, and those readers are named as
  they were without the trace. The programs count the records dropped, and
  the statistics printed when the watch stops show them as `trace_dropped`.

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
  exits within microseconds can finish before it is identified, and is
  counted as `unattributed`, unless the watch runs with `--trace-execs`.
  With it, a reader is unnamed only if its records were dropped, or it
  started before the watch did.
* **A known program loading hostile code**, such as a browser extension or a
  malicious package run by `npm`, reads as that program and is not
  reported.
* **Copies made earlier.** Credentials copied elsewhere before the watch
  started, or read through a backup, are not covered.
* **MEGALODON's own evidence collection and your backup tools** appear as
  readers. Allow them after review.
