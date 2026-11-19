# eBPF watch

Modern Linux rootkits load eBPF programs instead of kernel modules. An eBPF
program runs inside the kernel and can:
- hide files and processes from every program that lists them;
- change what system calls return;
- wake a backdoor when a magic network packet arrives.

There is no module to find (ATT&CK T1014, T1205). The
[rootkit cross-checks](rootkit-check.md) look at kernel modules, not at
these. `megalodon ebpf` records the loaded programs and reports what changes.

```bash
sudo megalodon ebpf baseline
```

```bash
sudo megalodon ebpf check
```

```bash
sudo megalodon ebpf accept
```

* **`baseline`** records the following in `~/.config/megalodon/ebpf.json`
  (mode 600):
  - every loaded eBPF program, by its type, name and tag (a hash of its
    instructions), with the account that loaded it and the processes that
    hold it;
  - the objects pinned under `/sys/fs/bpf`;
  - the `kernel.unprivileged_bpf_disabled` setting.

  A program already hidden or held by a dropped tool is reported at once.
* **`check`** reports new, changed and hidden programs, most severe first.
  It exits 1 on findings and 2 on an error. Programs that were unloaded
  are listed under `removed`.
* **`accept`** records the current programs after review, for example after
  installing a tracing or networking tool that uses eBPF.

Programs are listed through the kernel's own `bpf()` interface, which needs
root. No program is loaded, attached or changed. The holders come from each
process's open descriptors. With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The
[scheduler](scheduling.md) runs the check every 15 minutes as root.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `EBPF_HIDDEN_PROGRAM` | CRITICAL | A process holds an eBPF program that the kernel's program list does not show, which is how a rootkit that hides its own programs looks |
| `EBPF_LOADED_BY_DROPPED_TOOL` | CRITICAL | A program is held by something run from a temporary folder, a deleted file or memory, or by a script in a temporary folder. This is reported even after `accept`. |
| `EBPF_PROGRAM_CHANGED` | HIGH | A known program (same type and name) now has different instructions |
| `EBPF_NEW_PROGRAM` | HIGH | A new program of a kind that can watch or change the kernel or network traffic: kprobe, tracepoint, tracing (fentry/fexit), LSM, struct_ops, syscall, XDP, traffic control, netfilter and similar |
| `EBPF_UNPRIVILEGED_ENABLED` | HIGH | Unprivileged users may now load eBPF programs |
| `EBPF_NEW_FILTER` | MEDIUM | A new program of a less powerful kind, such as a socket or cgroup filter |
| `EBPF_PINNED_ADDED` | MEDIUM | A new object pinned under `/sys/fs/bpf`, which keeps a program or map alive without any process |

## Response

* **ebpf-rootkit** covers `EBPF_HIDDEN_PROGRAM` and
  `EBPF_LOADED_BY_DROPPED_TOOL`. It plans to collect evidence, suspend the
  holding process by PID and start time, and notify you.
* **ebpf-change** covers the HIGH rules. It plans to collect evidence and
  notify you: tracing, security and networking tools load programs too.

## Limits

* **Root is needed** to list programs. Without it, the check reports a gap.
* **A rootkit that hooks the kernel's own program list *and* the descriptor
  tables is not seen.** The hidden-program cross-check catches one that
  hooks only the list.
* **Programs with no holder** (kept alive by an attachment or a pin) are
  listed without a process. systemd's cgroup filters are usually like this.
* **The tag identifies the instructions, not their intent.** A new program
  is a reason to look: run `bpftool prog show` and `bpftool prog dump
  xlated id N` to see what it does.
