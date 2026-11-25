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
  a command that ends within milliseconds (`id`, `uname -a`) is still seen
  while the watch keeps up; with `--trace-execs`, also when it falls behind.
  Without root it scans `/proc` every `--interval` seconds (default 0.25) and
  misses programs that end sooner.
  With `--respond`, it decides each finding itself, at once, and runs
  [enforcement](enforcement.md) before it reads the next event, so the
  process it names can be paused while it still runs. What was decided and
  done is written to standard error as one `megalodon: response {...}`
  line. The scheduled `megalodon-ancestry` job runs it this way:

  ```bash
  sudo megalodon ancestry watch --respond
  ```

  The five-minute response pass still reads `check`. The same process is
  decided only once, whichever sees it first. Enforcement acts only when its
  policy is on and lists the action and the playbook.

* **`check`** reviews the processes running now and exits 1 on findings. The
  response engine runs it on every pass.
* **`allow SERVICE PROGRAM`** records, after review, that one service program
  may start one program, for example a PostgreSQL `archive_command`:

  ```bash
  megalodon ancestry allow /usr/lib/postgresql/16/bin/postgres /usr/bin/dash
  ```

  The allow list is `~/.config/megalodon/ancestry-allow.json` (mode 600).
  An application service is named the way its finding's
  `service.allow_as` gives it: its runtime, what it runs and the folder it
  runs in. So allowing one Python application does not allow every one:

  ```bash
  megalodon ancestry allow "/usr/bin/python3.12 /srv/app/manage.py in /srv/app" /usr/bin/dash
  ```

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md).

### Commands gone before they are read: `watch --trace-execs`

```bash
sudo megalodon ancestry watch --trace-execs
```

The process events give only a process ID; the watch then reads the program
and its arguments from `/proc`. When commands come faster than the watch
reads them, as a script run through a web shell does, some are gone by then.
They are counted as `vanished` and not judged, and one read as it exits has
no program or arguments. On this machine, a program named `nginx` started 20
different quick commands at once: 2 of them were reported.
`--trace-execs` loads the [exec trace](credential-watch.md#naming-readers-gone-at-once-watch---trace-execs)
instead, and all 20 were reported, each with its arguments.

* **How.** Each started program is judged as the kernel recorded it at its
  exec: its program, arguments, working folder, account, parent and start
  time. That record is its identity, even when `/proc` shows something else
  by the time it is read. Each exec and fork is also remembered, so a parent
  that already exited, such as the `sh -c` between a service and the command,
  still leads back to the service. A parent the trace recorded is taken as
  its records left it, not as `/proc` shows it later: a startup script that
  ran `id` and then became `nginx` is not reported as `nginx` running `id`.
  A parent known only from `/proc`, such as one started before the watch, is
  read from `/proc` again each time.
* **Lost records.** If programs start faster than the watch reads, the
  kernel has no room for some records. The statistics printed when the watch
  stops count them as `trace_dropped`.
* **What it changes.** As with the other watches, the programs only read, and
  are removed when the watch stops. It needs root, a kernel with BTF and BPF
  ring buffers (Linux 5.8 or later), on x86-64 or arm64. Where they cannot be
  loaded, the watch says why and uses the process events. The scheduler runs
  `ancestry watch` without it.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `SERVICE_SPAWNED_SHELL` | HIGH for web servers and databases, MEDIUM for mail and file-sharing servers and applications | A service started a shell or script interpreter |
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

**Applications.** Many web applications are not a separate server program,
but an interpreter or the JVM running the application itself. Examples are
gunicorn and uvicorn under `python3`, `node server.js`, `java -jar app.jar`
and a Jupyter server. Such a process counts as an application service while
it holds a listening socket: TCP, or a Unix socket with a path, as gunicorn
and uvicorn use behind nginx (`--bind unix:/run/gunicorn.sock`). A gunicorn
worker counts too, because it inherits its master's socket. The socket is matched in the process's own
network namespace, through `/proc/PID/net`, so an application in a container
counts the same way.
- **Runtimes:** Python, Perl, Ruby, PHP, Lua, Tcl, PowerShell, Node, Deno,
  Bun and Java.
- **Severity:** MEDIUM. Development servers and notebooks start shells for
  their own work, so the response playbook, which acts on HIGH, records
  these without pausing anything.
- **Naming:** the finding names the application by runtime and script, such
  as `python3.12 /usr/local/bin/gunicorn` or `java -jar /opt/app/app.jar`.
  The application's working directory is part of the name (`... gunicorn
  in /srv/a`), so two applications run by one launcher, such as gunicorn
  in `/srv/a` and in `/srv/b`, are two applications, and a relative script
  or archive is resolved against it. When that directory cannot be read
  (another account's process, without root), the name has no folder and a
  relative script stays `./server.js`. The same command started
  by two applications is reported for each, once every five minutes.
- **Timing:** a process that is not listening yet is looked at again after
  30 seconds, so a server that opens its port after starting is still
  recognized.

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
  service. `sshd` listens, but it is not an interpreter, so it is never an
  application service.
* **A runtime starting itself again,** such as Python's multiprocessing or
  Node's cluster workers. An application service's child that runs the same
  interpreter or JVM is not reported. Its shells and tools are.
* **Interpreters that are not serving:** a script with no listening socket,
  or one whose namespace has a listener another process holds. Unix sockets
  that are not a service's do not count: abstract ones, those under
  `/run/user/` (a person's desktop session) and multiprocessing's own under
  `/tmp/pymp-*`.
* **Process managers and daemons whose job is starting programs:**
  supervisord, circusd, fail2ban-server (its ban actions), the Salt daemons
  and PM2's daemon. An application they run is still checked as itself.

## Limits

* **Root sees everything.** Without root, the programs of other accounts'
  processes cannot be read, and the `/proc` scan misses short-lived commands.
  It also cannot follow a parent that already exited, because only the
  kernel's fork events prove which process a child came from.
* **Code that never starts a program is invisible.** A PHP web shell that
  reads files or opens sockets from inside PHP, without running a command,
  is not seen here. The [web-root watch](webroot-watch.md) looks at the
  files themselves.
* **Applications are known by their listening socket.** An application run
  by an interpreter counts only while it holds a listening TCP socket or a
  Unix socket with a path. One that only listens on UDP or an abstract Unix
  socket, or that is handed connections by another process, is not
  recognized. Other interpreter-run daemons that start commands over a
  control socket, beyond the ones above, are reported until allowed. A shell it starts in the 30 seconds
  after it was last seen not listening is missed too, since that answer is
  kept for 30 seconds. The same interpreter started by an application, as in
  `python3 -c 'import pty; ...'`, is not reported, but the shell it then
  starts is.
* **The kernel can drop events under heavy load.** The watch counts this as
  `lost` in the statistics it prints when it stops (`trace_dropped` with
  `--trace-execs`). Without `--trace-execs`, a command gone before the watch
  reads it is counted as `vanished` and not judged.
