# Login watch

The [auth review](host-tripwires.md) counts failed logins: someone guessing.
The breach itself is usually a login that *succeeds* (ATT&CK T1078):
- from a network the account never used;
- with an SSH key that was never seen before;
- at an hour the account never logs in;
- as a service account that should never log in at all;
- or followed by `sudo` from someone who never used it.

Stolen passwords and keys look like this. No file or process watch sees
them, because nothing unusual runs. `megalodon logins` learns how each
account normally logs in and reports logins that do not fit.

```bash
sudo megalodon logins learn
```

```bash
sudo megalodon logins check
```

* **`learn`** builds the baseline from past logs, in
  `~/.config/megalodon/logins.json` (mode 600). For each account it records:
  - the networks it logs in from (/24 for IPv4, /48 for IPv6);
  - how it logs in (key or password);
  - its SSH key fingerprints;
  - the hours of the day it logs in.

  It also records who uses `sudo` and `su`, and as whom. Run it over logs
  from a period you trust; logs are usually kept for a few weeks. Run it
  again over a log to accept logins in it that you have reviewed.
* **`check`** reports logins, `sudo` and `su` that do not fit the baseline,
  most severe first. It exits 1 on findings and 2 on an error. Each run
  judges only events after the previous run (`--all` judges every one).
  With `--alert`, findings also go to the
  [off-machine alerts](off-machine-alerts.md).

Logs are read from `/var/log/auth.log` (Debian, Ubuntu), `/var/log/secure`
(RHEL family), or `/var/log/wtmp` when there is no text log. Without root,
reading them usually needs membership in the `adm` group. On systems that
keep logs only in the journal, pipe it in:

```bash
journalctl -o short-iso -t sshd -t sudo -t su --since -30d | megalodon logins learn --log -
```

`wtmp` records logins without the method or key, so key and method rules
need a text log.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `LOGIN_SERVICE_ACCOUNT` | CRITICAL | A system account (UID below the system's `UID_MIN`, normally 1000, other than root) or an account with no login shell logged in |
| `LOGIN_NEW_KEY` | HIGH | An account logged in with an SSH key fingerprint it never used: a key someone added, or a stolen one |
| `LOGIN_NEW_SOURCE` | HIGH (MEDIUM inside the LAN) | An account logged in from a network it never logged in from |
| `LOGIN_ROOT_REMOTE` | HIGH | root logged in over the network, which it never did before |
| `LOGIN_NEW_ACCOUNT` | HIGH | An account that never logged in did |
| `SUDO_FIRST_USE` | HIGH | An account that never used `sudo` ran a command as another user |
| `LOGIN_NEW_METHOD` | MEDIUM | An account logged in a way it never has, such as by password when it always used a key |
| `LOGIN_UNUSUAL_HOUR` | MEDIUM | An account with at least 20 recorded logins logged in at an hour it never logs in |
| `SUDO_NEW_TARGET` | MEDIUM | An account used `sudo` as a user it never did before |
| `SU_NEW` | MEDIUM | An account switched to another user with `su` for the first time |

Failed `sudo` attempts are not uses of `sudo`; the auth review reports
those.

## Response

The [response engine](response-engine.md) reads the check on every pass,
keeping its own position in the log.

* **service-account-login** covers `LOGIN_SERVICE_ACCOUNT`. It plans to
  collect evidence, lock that account, block the source address for 60
  minutes and notify you.
* **unusual-login** covers the HIGH rules above. It plans to collect evidence
  and notify you: it may be you, travelling.

The response guards never lock root or the account running MEGALODON.

## Limits

* **The baseline is only as good as the logs it learned from.** An intruder
  already present while it learned looks normal. Learn from a period you
  trust, and review what it recorded.
* **Keys are seen only where sshd logs them.** OpenSSH logs the key
  fingerprint on each public-key login at its default log level.
* **Networks, not places.** A new address in a network an account already
  uses is not new; a mobile or home connection that changes networks often
  will be reported until it is learned.
* **One machine's logs.** Logins to other machines are not seen here.
