# Host tripwires: canary files and login review

Two host-side checks complement the network detectors. Both are explicit
operator commands that read local state, write nothing outside the paths you
name, contact no network service and take no action.

## In the HUD

**Setup → Tripwires and login review** shows both checks without running any
command. The HUD refreshes them in the background at most every two minutes:

- **Canary files:** reads the manifest at the conventional path
  `~/.config/megalodon/canary.json` (plant there to see it in the HUD). It
  reports intact, tripped or not planted. Only file names are shown, never
  your directory layout.
- **Login review:** reviews the first readable of `/var/log/auth.log` or
  `/var/log/secure`. It shows the most severe findings (up to 16) and the
  addresses with the most failed logins. When the log is unreadable it says
  so, which usually means the account is not in the `adm` group.

The panel is read-only. Planting, rearming, writing watchlists and any
response stay explicit commands. Like the other Setup reviews, it needs the
HUD running as your ordinary (non-root) user.

## Canary files

Canaries are bait files placed where an intruder or ransomware would look.
Nobody legitimate opens them, so any contact is worth investigating.

```bash
megalodon canary plant --dir ~/Documents/Finance --manifest ~/.config/megalodon/canary.json
```

```bash
megalodon canary check --manifest ~/.config/megalodon/canary.json
```

```bash
megalodon canary rearm --manifest ~/.config/megalodon/canary.json
```

`plant` writes up to five believable files (`passwords.txt`,
`ssh-key-backup.txt`, `wallet-recovery.txt`, `vpn-client.ovpn`,
`cloud-credentials.bak`). Each contains its own random marker and **no real
credential**. It never overwrites an existing file, and it records each
file's identity in an owner-private (0600) manifest. Keep the manifest
outside the bait directory; `plant` refuses otherwise.

`check` reports:

| Finding | Severity | Meaning |
| --- | --- | --- |
| `CANARY_REMOVED` | CRITICAL | The file was deleted, moved or renamed, or another file replaced it. |
| `CANARY_MODIFIED` | CRITICAL | Content, size, timestamps or permissions changed. This is the typical trace of ransomware encryption or tampering. |
| `CANARY_READ` | HIGH | The file was opened and read. |

`check` exits **1** when anything tripped, 0 when clean and 2 on an error, so
it can run from cron or a systemd timer and alert on a non-zero exit.

### Agent lures: catching an AI agent at work

```bash
megalodon canary plant --dir /srv/decoy --manifest ~/.config/megalodon/canary.json --lure
```

`--lure` adds `OPERATIONS-NOTE.txt`. It is a note written as instructions to automated agents and AI assistants:
confirm your access by signing in over SSH as a verification account. The account is random (`svc-` and six
letters or digits), appears in no wordlist, and `plant` checks that this machine has no such account. The password
it gives is a random marker, never a real one.

For whoever reached the machine over the web instead, the note also names a page of this site: a random path
(`/ops-` and ten letters or digits) with a code. It is given as a path and a code in a sentence, not as a link, and
no page links to it, so a crawler that follows links never asks for it. Planted in a folder your web server
serves, the note is found by an agent browsing the site too:

```bash
megalodon canary plant --dir /var/www/site/old-admin --manifest ~/.config/megalodon/canary.json --lure --web-readable
```

Every bait file is the owner's alone (mode 600), so a web server running as its own user (`www-data`, `nginx`)
could not serve the note, and no browsing agent would learn its page. `--web-readable` makes the lure's note, and
only it, readable by others (mode 644); the folder must let the server in too. Its mode is recorded as planted, so
it is never reported as changed. A local user reading it then trips `CANARY_READ`, as for any bait.

To check web lures against a real nginx, run `MEGALODON_TEST_LIVE_NGINX=1 python -m pytest tests/test_live_nginx.py`
as root on a machine with nginx. It runs nginx from a temporary folder on a free loopback port, its workers as
`nobody`, and checks that only a `--web-readable` note is served, that nginx's own access log is read, and that
a request for the lure's page in it is `LURE_FOLLOWED`, decided by the response engine. nginx is stopped and the
folder removed after.

What it tells apart:

* **Scanners and password-guessing tools** do not read sentences, and never try the account.
* **A person** rarely acts on such a note, and not within seconds.
* **An AI agent driving an attack** reads files to decide what to do next, takes the note as a lead, and tries
  the account.

So a login tried as the lure's account, or a request for its page, is reported as `LURE_FOLLOWED` (CRITICAL):
something read a note written for automated agents and acted on it. A login is found in the auth log, by
`megalodon auth-review --lures MANIFEST` or by the response engine with both `canary_manifest` and `auth_log` set. A
request for the page is found in the web server's access log, by `megalodon web-review --input LOG --lures MANIFEST`
or by the response engine with both `canary_manifest` and `web_log` set, whatever the server answered. A refused attempt is enough; an accepted one also
means the account exists after all, so check it at once. An accepted one is reported even right after refused ones,
and the response engine's summary says it was accepted and links the account.

The response engine links the attempt to the lure's own `CANARY_READ` finding in one incident. When the read time
is known, it says how soon the account was tried or the page asked for. Within two minutes, the summary says so plainly: "an AI agent
reading text and acting on it, at machine speed". The `lure-followed` playbook would collect evidence, block the
address for an hour and notify you.

To check the SSH lure against a real sshd, run `MEGALODON_TEST_LIVE_SSHD=1 python -m pytest tests/test_live_sshd.py` as
root on a machine where journald runs and sshd, ssh and sshpass are installed. It plants a lure, runs sshd from a
temporary folder on a free loopback port, tries one password login as the lure's account, and checks that sshd's own
lines, read back from the journal, are `LURE_FOLLOWED`, decided by the response engine. sshd's lines about that one
attempt stay in the journal; sshd is stopped and the folder removed after.

**Keep lures out of folders your own AI assistants work in.** A coding assistant or chat agent reading your files
would follow the note too. Plant lures in decoy folders that only an intruder has reason to read: a fake backup
share, a web root's old admin folder, a home directory no one uses.

Lures planted before pages were named have none; plant a lure again for the web log to watch one. The access log
is read in nginx's and Apache's default formats (`combined` and `common`), and only for a lure's page: this is not a
general web attack detector. Behind a reverse proxy, the address the server logged is the proxy's. One on this
machine logs one of its own addresses, which is never blocked; one on another machine would be, so with such a
proxy leave `lure-followed` out of [enforcement](enforcement.md)'s policy and act on the decision yourself.

### How read detection works and where it is blind

After planting, each file's access time is set two days before its
modification time. Under Linux's default `relatime` mount option, the next
read updates the access time, and `check` sees that.

`check` itself never disturbs it. It uses `stat` and hashes content with
`O_NOATIME`, which the file's owner may use.

`plant` tests the target filesystem and reports `read_detection`. On
`noatime` mounts reads cannot be detected, but removal and change still are.
After you review a read, run `rearm` so the next read is detected again.

Backup, file indexing and antivirus tools also read files. Exclude the bait
directory from them, or expect benign `CANARY_READ` trips. A trip shows that
something touched the file, not who or why.

## Login review (`auth-review`)

```bash
megalodon auth-review --input /var/log/auth.log
```

```bash
megalodon auth-review --journal --hours 24
```

Use `/var/log/secure` on RHEL-family systems, and `--journal` on systems that keep logins only in the systemd
journal. `--journal` reads its auth and authpriv messages, which `auth.log` holds where kept, with `journalctl`.
It says so in `gaps` when the journal holds no files, or shows only your own messages. Reading auth logs
usually requires membership in the `adm` group; the journal, `adm` or `systemd-journal`.

To check `--journal` against this machine's own journal, run
`MEGALODON_TEST_LIVE_JOURNAL=1 python -m pytest tests/test_live_journal.py`. It writes three neutral messages tagged
with a random marker (under the auth, authpriv and daemon facilities), which stay in the journal like any logged
line, and checks that the first two are read, in this format and in UTC, and the third is not.

| Finding | Severity | Default trigger |
| --- | --- | --- |
| `AUTH_SUCCESS_AFTER_FAILURES` | CRITICAL | A login succeeded from an address with ≥ 5 failures in the previous hour |
| `AUTH_FAILURE_BURST` | HIGH | ≥ 6 failed logins from one address within 10 minutes |
| `PASSWORD_SPRAY` | HIGH | One address tried ≥ 4 different usernames within an hour |
| `SUDO_DENIED` | HIGH | A user who is not in sudoers tried sudo |
| `PRIVILEGE_GRANT` | HIGH | An account joined `sudo`, `wheel`, `admin`, `root`, `adm`, `docker`, `lxd`, `libvirt`, `disk` or `shadow` |
| `SUDO_FAILURES` | MEDIUM | ≥ 3 wrong sudo passwords by one user within 10 minutes |
| `ACCOUNT_CREATED` | MEDIUM | A new local account appeared |

`AUTH_SUCCESS_AFTER_FAILURES` is the signal to act on first: a guessed
password that worked.

Each finding repeats at most once per hour for the same subject. The command
exits **1** when any HIGH or CRITICAL finding exists, so it can drive
alerting.

### The response engine reads it too

With `auth_log` set in the response policy (`megalodon respond init` sets it to the log this system keeps, or to
`"journal"` where there is none and journald runs), every response pass reviews the log and decides the findings
newer than the last it read. Failed-login bursts and password
spraying go to the `attacker-at-the-door` playbook, a login after many failures to `guessed-login`, and all of them
count toward an [automated campaign](automated-campaigns.md) from the same address. See the
[response engine](response-engine.md).

### Feed attackers into the network watchlist

```bash
megalodon auth-review --input /var/log/auth.log --emit-watchlist ~/.config/megalodon/attackers.txt --replace
```

This writes the addresses behind brute-force, spraying and
success-after-failure findings (loopback excluded) to an owner-private
watchlist. Point `threat_detection.watchlist_path` at it, and every later
connection to or from those addresses raises `IOC_MATCH` in the network view.

### Parsing details and limits

- **Input formats:** classic syslog (`Nov 17 22:01:02 host sshd[1]: …`), high-precision ISO-8601 and `journalctl -o short-iso` (and `short-iso-precise`, which `--journal` reads).
- **Classic timestamps:** these carry no year or zone, so this computer's local time and the current year are assumed (a December line read in January rolls back a year). Pass `--utc` when the log was written in UTC.
- **Counting:** one connection that logs both `Invalid user X` and `Failed password for invalid user X` counts once. Repeated password guesses on one connection each count.
- **Untrusted usernames:** attackers choose them, so they are bounded to 64 printable characters and only reported as data.
- **Size and state limits:** input up to 64 MiB, lines up to 4 KiB (longer lines are counted and skipped), at most 50 000 tracked addresses, and at most 500 findings (`truncated` is set when the limit is hit).
- **Blind spots:** logins outside the supplied log (rotated files, other hosts, services that do not log through syslog) are invisible. A quiet log does not establish that a host is safe.
