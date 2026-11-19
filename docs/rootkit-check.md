# Rootkit cross-checks

A rootkit hides a process, a module, a port or a file by changing one way
the system reports it: the listing of `/proc`, the kernel's module list, the
socket tables, a folder's directory reads. Hooking every way is harder, and
rootkits rarely manage it. `megalodon rootkit check` asks each question
twice, through different kernel paths, and reports where the answers
disagree (ATT&CK T1014, T1574.006). It needs no baseline.

```bash
sudo megalodon rootkit check
```

It exits 1 on findings and 2 on an error. With `--alert`, a summary also
goes to the [off-machine alerts](off-machine-alerts.md). The
[response engine](response-engine.md) runs it on every pass, without the
port test.

## What is compared

| Rule | Severity | Disagreement |
| --- | --- | --- |
| `HIDDEN_PROCESS` | CRITICAL | A process ID answers a signal probe, or opens directly as `/proc/<pid>`, but is missing from two listings of `/proc`. Threads, which `/proc` never lists, are recognized and left out. |
| `HIDDEN_MODULE` | CRITICAL | A loaded kernel module is in `/sys/module` but not in `/proc/modules`, or the reverse |
| `HIDDEN_PORT` | HIGH | A TCP or UDP port cannot be bound because it is in use, but no socket table lists it |
| `HIDDEN_DIRECTORY` | HIGH | A system folder's link count shows more subfolders than its listing returns. This is checked only on filesystems that keep that count: ext2/3/4, XFS, tmpfs, JFS, ReiserFS and F2FS. |
| `HIDDEN_FILE` | CRITICAL | A library named in `/etc/ld.so.preload` exists but is missing from its folder's listing |
| `PRELOAD_LIBRARY` | HIGH | `/etc/ld.so.preload` loads a library into every program, as userland rootkits do. Few systems need it. |
| `KERNEL_FORCED_MODULE` | MEDIUM | The kernel's taint flags record a module loaded or unloaded by force |

Each disagreement is checked again before it is reported, so a process
that started or a socket that opened between the two looks is not a
finding. The report also lists the kernel's other taint flags
(proprietary, out-of-tree and unsigned modules) under `kernel`, for
information.

* `--skip-ports` leaves out the port test.
* `--max-pid` limits how far process IDs are probed. The default is the
  kernel's `pid_max`; probing 4 million IDs takes about 12 seconds.

## The port test binds ports

To learn whether a port is in use, the test binds it for a moment and
closes it again: every TCP and UDP port, on IPv4 and IPv6, that no socket
table lists. A service that starts in that same instant could find its
port briefly taken and fail to start. This is why the response engine
leaves the port test out unless `rootkit_ports = true`. Run it yourself
when nothing is starting. Without root, ports below the unprivileged limit
(usually 1024) cannot be tested, and the report says so.

## Limits

* **A rootkit that hooks every view is not seen.** For example, a kernel
  rootkit that hides a process from the `/proc` listing, from direct
  lookups and from signals alike. This check makes hiding harder, and it
  catches the common rootkits. It cannot prove a machine is clean. Boot
  from trusted media and inspect the disk offline when it matters.
* **Root sees everything.** Without root, other accounts' processes are
  probed but not inspected, and protected folders are skipped.
* **One network namespace.** Ports are compared within the namespace the
  check runs in. A socket in a container's own namespace does not conflict,
  and it is not listed either.
* **Kernels without loadable modules** have nothing to compare for modules,
  and the report says so.
