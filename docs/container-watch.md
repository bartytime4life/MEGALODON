# Container watch

A container shares the host's kernel. Several settings make it root on the
machine in all but name:
- running privileged;
- having the container runtime's socket mounted;
- having the host's root folder mounted;
- sharing the host's process table;
- holding a capability such as `SYS_ADMIN`.

From there, leaving the container takes one command (ATT&CK T1611, T1610).
`megalodon containers` records the running containers and the host's container
exposures, and reports what gets riskier.

```bash
sudo megalodon containers baseline
```

```bash
sudo megalodon containers check
```

```bash
sudo megalodon containers accept
```

* **`baseline`** records the following in
  `~/.config/megalodon/containers.json` (mode 600):
  - every running container, with what it shares with the host;
  - the kernel hooks that escapes overwrite;
  - the members of root-equivalent groups: those listed in `/etc/group`,
    and the accounts whose own (primary) group in `/etc/passwd` is one of
    them, which have its access without being listed.

  An escape, an open runtime API or socket, or a hook that already runs a
  program from outside the system folders is reported at once.
* **`check`** reports what got riskier, most severe first. It exits 1 on
  findings and 2 on an error. New containers are listed under `added` and
  stopped ones under `removed`. A new container is a finding only when it
  shares something risky.
* **`accept`** records the current containers after review, for example after
  deploying a monitoring agent that is meant to see the host.

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The [scheduler](scheduling.md)
runs the check every 15 minutes as root, and the
[response engine](response-engine.md) reads it on every pass.

## How containers are found

Containers are found from their processes' control groups, so every runtime
is covered:
- Docker;
- Podman;
- containerd and Kubernetes;
- CRI-O;
- LXC;
- systemd-nspawn.

Each process's namespaces, capabilities, seccomp mode and mount table are
read from `/proc` and compared with the host's own, which are those of
process 1. A host mount is recognized by its device and its path within that
filesystem, so a bind mount is seen whatever path it is mounted at inside the
container, including on a Btrfs subvolume root mounted from `/@`.

A process in a container's control group that runs in the host's mount
namespace is an escape. There are two exceptions:
- **runtime helpers,** but only when the process runs the installed `runc`,
  `crun`, `conmon`, containerd shim, `systemd-nspawn` or similar file (the same
  file, by inode). Process names are the process's own to set, so they are not
  trusted;
- **processes gone a second later,** such as runc's own init step, which runs
  from an in-memory copy for a few milliseconds. Everything else is looked at
  again after a second and reported if it is still there, with the same start
  time.

When the Docker (or Podman) socket can be read, container names and images
are asked of it with a read-only `GET /containers/json`. Otherwise containers
are named by their ID. Nothing is started, stopped, entered or changed.

## Escapes as they start: `containers watch`

```bash
sudo megalodon containers watch
```

`check` looks every 15 minutes, and an escape that is over within a second,
such as one command run in the host's namespace, is gone by then. `watch`
loads two small eBPF programs, the [exec trace](credential-watch.md#naming-readers-gone-at-once-watch---trace-execs),
and reports each program the kernel starts in the host's mount namespace
from a container's control group, as `CONTAINER_ESCAPE` (CRITICAL), one JSON
line each, however soon it exits. On this machine, a throwaway runc
container sharing the host's process table, with `SYS_ADMIN`, joined the
host's mount namespace and ran `/usr/bin/true` there. `check` missed it,
since it was gone within a second; `watch` reported it.

* **How.** At each exec, the kernel records the new program's mount
  namespace, its executable's device and inode, and its control groups'
  path names: the unified hierarchy's and the memory controller's, which
  holds containers on cgroup v1. Containers are named from those paths as
  `check` names them. The host's mount namespace is process 1's, or the
  watch's own where process 1's cannot be read.
* **Runtimes are told apart by their files, not their names.** An installed
  runtime helper (`runc`, `crun`, `conmon`, a containerd shim and the
  others `check` knows) is not an escape, by device and inode. Nor is the
  step where runc runs itself again to set a container up: an exec whose
  parent runs the installed runc, of a sealed copy with the same inode
  number, or, before runc 1.2, of its deleted in-memory copy
  (`runc_cloned`). With cgroup v2, `runc exec` starts that step inside the
  container's control group already. Anything else a runtime starts in the
  host's namespace is an escape: `nsenter` run by `docker exec` is too. The
  helper files are read again before an escape is reported, so an upgraded
  runtime is still known. A parent's program is the one the trace last saw it
  run, its own exec or its parent's at its fork, so a reused process ID does
  not keep runc's identity. Only a parent the trace never saw is read from
  `/proc`.
* **Once an hour.** The same program from the same container is reported
  once an hour; the statistics printed when the watch stops count the rest.
* **Records the kernel had no room for.** If programs start faster than the
  watch reads, the kernel drops records, and an escape among them is not
  reported. The programs count them: each time the count rises, the watch
  says so on standard error, and its statistics show it as `dropped`.
* **Response.** With `--respond`, each finding is decided at once by the
  **container-escape** playbook, as the pass would decide it, and the same
  process is decided only once. With `--alert`, findings also go to the
  off-machine alerts.
* **What it changes.** As with the exec trace, the programs only read; they
  are removed when the watch stops. It needs root, a kernel with BTF and
  BPF ring buffers (Linux 5.8 or later), on x86-64 or arm64. Where they
  cannot be loaded, the watch says so and exits 2: `check` still runs. The
  [scheduler](scheduling.md) runs it as root, as the `container-escapes`
  job, where the kernel has what it needs.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `CONTAINER_ESCAPE` | CRITICAL | A process in a container's control group runs in the host's mount namespace: it has left its container. Reported on every check, even after `accept`. |
| `ESCAPE_HOOK_SET` | CRITICAL | `core_pattern`, `modprobe`, `uevent_helper` or a cgroup `release_agent` now runs a program outside the system folders, or one the host does not have. These are the hooks that container escapes overwrite. |
| `RUNTIME_API_EXPOSED` | CRITICAL | The runtime API listens on unencrypted TCP port 2375. Reported on every check. |
| `RUNTIME_SOCKET_WORLD_WRITABLE` | CRITICAL | A Docker, containerd, Podman or CRI-O socket can be written by every account. Reported on every check. |
| `CONTAINER_PRIVILEGED` | HIGH | A container runs with every capability |
| `CONTAINER_RUNTIME_SOCKET` | HIGH | A runtime socket is mounted into a container |
| `CONTAINER_HOST_PATH_MOUNTED` | HIGH | The host's `/`, `/etc`, `/root`, `/home`, `/boot`, `/usr`, `/var`, `/run`, `/proc`, `/dev`, runtime state folders, or files such as `/etc/shadow`, `/etc/sudoers` and `/etc/ssh`, are mounted into a container |
| `CONTAINER_DANGEROUS_CAPABILITY` | HIGH | A container holds `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `DAC_READ_SEARCH`, `MAC_ADMIN`, `MAC_OVERRIDE` or `BPF` |
| `CONTAINER_HOST_PID` | HIGH | A container shares the host's process namespace |
| `ESCAPE_HOOK_CHANGED` | HIGH | One of those hooks changed to another program in the system folders |
| `RUNTIME_GROUP_MEMBER_ADDED` | HIGH | An account joined `docker`, `lxd`, `incus-admin` or `microk8s`, each as good as root, or now has one as its own (primary) group. Against a baseline from before primary groups were read, such an account is reported once, as first checked now. |
| `CONTAINER_HOST_NETWORK` | MEDIUM | A container shares the host's network namespace |
| `CONTAINER_UNCONFINED` | MEDIUM | A container runs with seccomp off |

Container findings are reported when a container gains a risk the baseline
did not record for it. That applies to a new container, or a known one
restarted with more.

A container in its own user namespace, such as rootless Podman, holds its
capabilities only inside that namespace. Its capabilities are therefore not
reported.

## Response

* **container-escape** covers the CRITICAL rules. It plans to collect
  evidence, suspend the escaped process by PID and start time, and notify you.
* **container-exposure** covers the HIGH rules. It plans to collect evidence
  and notify you. Monitoring agents and CI runners are set up this way on
  purpose.

## Limits

* **Root is needed** to read other processes' namespaces. Without it, the
  check reports how many container processes it could not inspect.
* **An escape that finishes within a second** (one command run in the
  host's namespace) may be gone before `check`'s second look; `watch`
  reports it as it starts. The hook, mount or socket it used is still
  reported. `watch` sees programs started: a process that joins the host's
  namespace and works there without starting another program is seen only
  by `check`, if it lasts.
* **An escape that stays in the container's mount namespace** but writes to
  the host through a mounted folder, a socket or a hook is not caught as an
  escape. The exposure that made it possible is reported instead.
* **Host agents that enter the host's namespaces from a container on purpose**
  (some Kubernetes node agents use `nsenter`) are reported as escapes on every
  check. Run them on the host instead.
* **Without the Docker socket,** containers are named by ID. A container
  recreated with a new ID is compared as a new container.
* **Local accounts and groups only.** Members are read from `/etc/group` and
  `/etc/passwd`. Accounts and groups from a directory service (LDAP, SSSD)
  are not read.
