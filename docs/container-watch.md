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
  - the members of root-equivalent groups.

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
| `RUNTIME_GROUP_MEMBER_ADDED` | HIGH | An account joined `docker`, `lxd`, `incus-admin` or `microk8s`, each as good as root |
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
  host's namespace) may be gone before the second look. The hook, mount or
  socket it used is still reported.
* **An escape that stays in the container's mount namespace** but writes to
  the host through a mounted folder, a socket or a hook is not caught as an
  escape. The exposure that made it possible is reported instead.
* **Host agents that enter the host's namespaces from a container on purpose**
  (some Kubernetes node agents use `nsenter`) are reported as escapes on every
  check. Run them on the host instead.
* **Without the Docker socket,** containers are named by ID. A container
  recreated with a new ID is compared as a new container.
* **Primary group membership** in `docker` (a user whose own group is
  `docker`) is not read. Only the listed members are.
