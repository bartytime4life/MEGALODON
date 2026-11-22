# Hardening drift

The [hardening review](../megalodon/hardening_review.py) reads the machine's
protections once. Attackers who get in lower them so they can stay. They:
- turn process tracing back on;
- allow root over SSH;
- leave a way back to root that no account, service or setuid program shows.

These are ATT&CK T1562, T1548 and T1574. `megalodon hardening` records the
protections and reports what gets weaker.

```bash
sudo megalodon hardening baseline
```

```bash
sudo megalodon hardening check
```

```bash
sudo megalodon hardening accept
```

* **`baseline`** records three things in `~/.config/megalodon/hardening.json`
  (mode 600):
  - every hardening review check;
  - every file with a file capability;
  - the folders and programs on root's command search path that other
    accounts can write to.

  A file capability that is already a back door is reported at once. What is
  already exposed is listed under `exposures`, so you can fix it before
  accepting it as normal.
* **`check`** reports what got weaker, most severe first. It exits 1 on
  findings and 2 on an error.
* **`accept`** records the current state after review.

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The [scheduler](scheduling.md)
runs the check hourly, and the [response engine](response-engine.md) reads it
on every pass.

## What is checked

* **The hardening review checks:**
  - kernel parameters such as `ptrace_scope`, `kptr_restrict`, ASLR, protected
    links and `suid_dumpable`;
  - the SSH daemon's root login, password and empty-password settings;
  - automatic updates, IP forwarding and listeners exposed beyond this machine.

  A check that goes from pass to review or fail, or from review to fail, is
  reported.
* **File capabilities.** A file capability lets anyone who runs a program use a
  privilege. `cap_setuid` on a copy of Python, Perl or a shell gives root to
  whoever runs it, and setuid searches do not see it.

  Every local file system is searched for files that carry the
  `security.capability` attribute. The root file system is always searched,
  including an overlay root as in containers. The search skips kernel views,
  container image layers, and network and FUSE mounts; skipped mounts are
  listed as a gap. It stops after two million files or
  two minutes and reports a gap if it did.
* **Root's command search path:**
  - **The search path.** It is read wherever something that runs as root
    gets one, and each finding says where:
    - **Logins and sudo:** the system default, `/etc/environment`,
      `ENV_SUPATH` in `/etc/login.defs`, and sudo's `secure_path`.
    - **Root's own shell files:** `~/.profile`, `~/.bash_profile`,
      `~/.bash_login`, `~/.bashrc`, `~/.zshenv`, `~/.zprofile` and `~/.zshrc`.
      `$HOME` and `~` are `/root`, and `$PATH` is the path already read. A
      part built from any other variable or a command is not known, and is
      left out.
    - **cron:** `PATH=` in `/etc/crontab`, `/etc/cron.d` and root's own
      crontab.
    - **Services:**
      - systemd's `DefaultEnvironment`, which every service gets.
      - The `PATH` each service that runs as root sets itself in
        `Environment=`, or in a file its `EnvironmentFile=` names. Unit files
        are read where systemd reads them, `/etc` first, and their drop-ins
        in order. A service with `User=` another account, or `DynamicUser=`,
        does not run as root and is skipped.
      - In a unit file, `%h` is `/root`. A part with any other specifier, or
        with one in an environment file, is left out.
  - **Folders.** Each folder on the path, and every folder above it, is checked
    for whether an account other than root can write to it. A folder that is a
    symlink is checked both ways: up from its own path, and up from where it
    leads. Whatever lands
    there, root runs.
  - **Programs.** So is each program in those folders.
  - **Relative entries.** An empty or relative entry (`.`) makes root run
    programs from whatever folder it is in.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `FILE_CAPABILITY_BACKDOOR` | CRITICAL | A shell, script interpreter, or program in a temporary or home folder holds a capability that leads to root: `cap_setuid`, `cap_setgid`, `cap_dac_override`, `cap_dac_read_search`, `cap_chown`, `cap_fowner`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_sys_module`, `cap_sys_rawio`, `cap_setfcap` or `cap_bpf`. Reported at baseline time too. |
| `PATH_FOLDER_WRITABLE` | CRITICAL when everyone can write, HIGH otherwise | A folder on root's search path, or one above it, became writable by another account |
| `PROGRAM_WRITABLE` | CRITICAL when everyone can write, HIGH otherwise | A program on root's search path became changeable by another account |
| `PATH_HAS_RELATIVE_ENTRY` | HIGH | Root's search path gained an empty or relative entry |
| `FILE_CAPABILITY_ADDED` | HIGH | Another program gained a capability that leads to root |
| `HARDENING_WEAKENED` | HIGH for kernel and SSH protections, MEDIUM for updates and network settings | A hardening review check got worse |
| `FILE_CAPABILITY_CHANGED` | MEDIUM | A program gained another capability, such as `cap_net_raw`, or a permitted one was switched on (`+p` to `+ep`) |

The **hardening-drift** response playbook covers the HIGH and CRITICAL rules.
It collects evidence and notifies you. Settings and permissions are the
administrator's to put back.

## Limits

* **Live values only.** Settings changed at runtime and changed back between
  checks are not seen.
* **Root's search paths only.** Other accounts' paths, and those of
  services that run as another account, are not read: a folder an account
  can write to on its own path gives it nothing it does not have. A path set
  at run time, by a script that a service or job starts, is not seen
  either.
* **One search per run.** The capability search runs every check, at the
  scheduler's low CPU and I/O priority. A machine with many millions of files
  is searched only in part, and the report says so.
* **Root is needed** to read every folder. Without it, folders it cannot open
  are skipped.
