# Process ancestry watch

A web server, database or mail server answers requests. It has no reason to
run `sh`, `python`, `nc` or `id`. When one does, the usual cause is a web shell
or an exploited service: the attacker's first commands run as children of
the service they broke into (ATT&CK T1505.003, T1059). `megalodon ancestry`
reports those children.

```bash
sudo megalodon ancestry watch
```

```bash
megalodon ancestry check
```

* **`watch`** reports each program a service starts, as it starts, as one
  JSON line per finding. Run as root, it uses the kernel's process events, so
  a command that ends within milliseconds (`id`, `uname -a`) is still seen.
  Without root it scans `/proc` every `--interval` seconds (default 0.25) and
  misses programs that end sooner. Pipe it into the
  [response engine](response-engine.md):

  ```bash
  sudo megalodon ancestry watch | megalodon respond ingest
  ```

* **`check`** reviews the processes running now and exits 1 on findings. The
  response engine runs it on every pass.
* **`allow SERVICE PROGRAM`** records, after review, that one service program
  may start one program, for example a PostgreSQL `archive_command`:

  ```bash
  megalodon ancestry allow /usr/lib/postgresql/16/bin/postgres /usr/bin/dash
  ```

  The allow list is `~/.config/megalodon/ancestry-allow.json` (mode 600).

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md).

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `SERVICE_SPAWNED_SHELL` | HIGH for web servers and databases, MEDIUM for mail and file-sharing servers | A service started a shell or script interpreter |
| `SERVICE_SPAWNED_TOOL` | as above | A service started a transfer, relay or reconnaissance tool: `curl`, `wget`, `nc`, `socat`, `ssh`, `openssl`, `base64`, `id`, `whoami`, `uname`, `netstat` and similar |

A service counts as the starter when it is anywhere among the program's
parents, so `nginx → sh → curl` is reported for both `sh` and `curl`. A
parent that has already exited is still followed: the watch remembers each
process from the moment it was forked, so `sh -c '(id &)'` leads back to the
service even after the shells are gone.

Services: `nginx`, `apache2`/`httpd`, `lighttpd`, `caddy`, `php-fpm`,
`uwsgi`, MySQL/MariaDB, PostgreSQL, MongoDB, Redis/Valkey, Memcached,
ClickHouse, InfluxDB, Exim, Postfix, Dovecot, OpenSMTPD, vsftpd, ProFTPD,
Pure-FTPd and Samba.

Each finding names the program, its process ID with start time, its command
line (up to 512 bytes), the service and the chain of parents.

## What stays quiet

* **`sh -c` running one mail or log helper** with no shell syntax at all:
  PHP's `mail()` (`sh -c "/usr/sbin/sendmail -t -i"`) and Apache's piped logs
  (`rotatelogs`, `cronolog`). Any `;`, `|`, `$(...)` or other shell syntax
  makes it a finding.
* **CGI scripts:** an interpreter that the web server starts directly on a
  script file under `/usr/lib/cgi-bin/` or another `cgi-bin` folder. Code
  given as text (`sh -c`, `perl -e`, `php -r`) never counts, even if it
  starts with a CGI path.
* **Pairs in the allow list.**
* **Your own shells.** A shell under `sshd` or a terminal is not under a
  service.

## Limits

* **Root sees everything.** Without root, the programs of other accounts'
  processes cannot be read, and the `/proc` scan misses short-lived commands.
  It also cannot follow a parent that already exited, because only the
  kernel's fork events prove which process a child came from.
* **Code that never starts a program is invisible.** A PHP web shell that
  reads files or opens sockets from inside PHP, without running a command,
  is not seen here. The [web-root watch](webroot-watch.md) looks at the
  files themselves.
* **Services are known by their program name.** A web application run by a
  general interpreter (`python3 app.py`, `node server.js`, `java -jar`) is
  not recognized as a service.
* **The kernel can drop events under heavy load.** The watch counts this as
  `lost` in the statistics it prints when it stops.
