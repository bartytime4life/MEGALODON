# Operator hardening recipe for the Qwen/Ollama provider

Status: **operator guidance only. No MEGALODON code, dependency, service,
install step, or default changes.** This document supports issue
[#261](https://github.com/bartytime4life/MEGALODON/issues/261) ("Post-RC
operator-host acceptance only; no new model, tool, persistence, or action
authority") and the open gates in
[`docs/model-containment-review.md`](model-containment-review.md). MEGALODON
does not install, start, stop, configure, or restart Ollama, before or after
following this recipe, and nothing here is applied, checked, or enforced
automatically. It is the operator's own action, on the operator's own host.

## What this closes, and what it does not

[`docs/model-containment-review.md`](model-containment-review.md) names the
open gap precisely: MEGALODON's client-side controls (one bounded request to
a compiled-in `127.0.0.1:11434`, no retry/fallback/redirect) say nothing
about "ownership and integrity of the process bound to that port... the
provider's own outbound access or reachable shared services." The systemd
profile below targets that gap on an operator's own host, and
[`megalodon/provider_containment.py`](../megalodon/provider_containment.py)
can observe part of the result read-only and after the fact. The rootless
Podman example supplies a narrower container boundary; it does not deny
outbound traffic and cannot by itself close the no-egress or identity-
separation gates.

It does **not**: attest the loaded model artifact's authenticity, sandbox GPU
driver interaction, cover Windows or macOS, or change what MEGALODON's own
client already does. Both examples below assume a Linux host, matching the
rest of this repository's platform baseline.

## Principle

Ollama is operator-installed and separately run software, not a MEGALODON
dependency (`docs/local-model-advisory-contract.md`). The goal is: even if
Ollama, a loaded model, or anything it talks to is fully compromised, it
should not be able to (a) become reachable from anything other than
loopback, (b) read or write anything outside its own model-storage
directory, (c) reach the network beyond loopback itself, or (d) run as, or
escalate to, a privileged or MEGALODON-owned identity. Recipe A targets all
four goals. Recipe B is intentionally partial: it supplies loopback-only
inbound publication and container/filesystem/resource restrictions, but it
does not establish no-egress or a UID distinct from the invoking operator.
Do not run both examples against the same instance.

## Recipe A: a hardened systemd unit

```ini
# /etc/systemd/system/ollama.service
[Unit]
Description=Ollama (Qwen provider), loopback-only, MEGALODON-independent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ollama serve
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_MODELS=/var/lib/ollama
Restart=on-failure

# Identity: a dedicated, ephemeral, unprivileged UID/GID distinct from the
# operator's own account and from whatever account runs MEGALODON.
DynamicUser=yes
StateDirectory=ollama
# StateDirectory=ollama creates /var/lib/ollama, owned by the DynamicUser
# identity, as the only writable path; OLLAMA_MODELS points Ollama at it
# instead of the default $HOME/.ollama, which DynamicUser has none of.

# Network: kernel-enforced loopback-only, independent of the application's
# own bind-address setting. Even a misconfigured OLLAMA_HOST=0.0.0.0 cannot
# make this unit reachable from anywhere but 127.0.0.0/8 and ::1/128.
IPAddressDeny=any
IPAddressAllow=127.0.0.0/8 ::1/128
PrivateNetwork=no
# PrivateNetwork=yes would put this unit in its own loopback, unreachable
# from MEGALODON's process at 127.0.0.1; do not set it here.

# Filesystem: read-only everywhere except the declared state directory
# (ProtectSystem=strict already covers /; StateDirectory is the one
# writable exception it carves out automatically).
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

# Kernel and privilege surface.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictNamespaces=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
SystemCallFilter=@system-service
SystemCallFilter=~@mount @debug @swap @reboot @privileged @cpu-emulation @obsolete
SystemCallErrorNumber=EPERM

# Bounded resources: an operator value, not a MEGALODON-selected default.
MemoryMax=8G
CPUQuota=400%
TasksMax=256

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ollama.service
```

`MemoryDenyWriteExecute=yes` is deliberately **not** set above: some GPU
runtimes JIT-compile kernels and need writable+executable memory. Add it,
and confirm Ollama still starts, if this host runs CPU-only inference.
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` is likewise left out by
default because GPU driver IPC sometimes needs `AF_NETLINK`; add it and
retest if this host has no GPU. GPU passthrough (`DeviceAllow=char-nvidia
rw`, or the ROCm/oneAPI equivalent) requires its own review and further
loosens this profile — treat a GPU-enabled host as a materially different,
separately reviewed configuration from the CPU-only one above.

## Recipe B: a rootless container (partial boundary only)

```bash
podman run -d \
  --name ollama \
  --security-opt no-new-privileges \
  --cap-drop=ALL \
  --read-only --tmpfs /tmp \
  -v ollama-models:/root/.ollama \
  -p 127.0.0.1:11434:11434 \
  --pids-limit=256 --memory=8g --cpus=4 \
  docker.io/ollama/ollama@sha256:<pinned-digest>
```

Pin the image by digest, not a mutable tag such as `:latest` or `:0.x.y`: this
repository has already documented elsewhere the difference between a pinned
identity and a mutable tag for this exact provider
(`docs/evidence-alignment-review.md`). Resolve the digest once
(`podman pull docker.io/ollama/ollama:<version>` then
`podman images --digests docker.io/ollama/ollama`) and record it, rather than
trusting the tag to still mean the same bytes later.

The load-bearing flag for the **inbound** boundary is
`-p 127.0.0.1:11434:11434`, not `--network=host` or a bare
`-p 11434:11434`: it binds the published host port to loopback. It does not
restrict outbound connections from the container. Rootless Podman's default
network ordinarily permits outbound traffic, so this example must not be
recorded as no-egress evidence for issue #261. Do **not** add
`--network=host`; it also defeats the inbound port-isolation boundary by
sharing the host's network stack directly.

The identity boundary is similarly limited. Without an explicit `--userns`
mode, container UID 0 maps to the invoking user in the rootless Podman user
namespace. That mapping is not host root, but it is also not an identity
separate from an operator who runs MEGALODON under the same account.
`--userns=keep-id` maps the invoking UID/GID to the same values inside the
container; it does not solve that separation requirement. This document does
not prescribe an alternative user-namespace or no-egress design because one
has not been exercised against the pinned image and the required host-
loopback service path. Those controls require a separately tested and
reviewed design before this container example can support containment
acceptance.

## Verifying the result

Neither example is proven by writing it down. After starting Ollama, use the
read-only observer already in this repository — it contacts nothing and
changes nothing:

```bash
python -c "
from megalodon.provider_containment import qwen_provider_posture
import json
print(json.dumps(qwen_provider_posture(), indent=2, default=dict))
"
```

| Field | Expected observation | What it would mean if wrong |
| --- | --- | --- |
| `listening` | `"yes"` | Ollama did not start, or is on a different port than MEGALODON expects |
| `loopback_only` | `true` | The service is reachable beyond loopback — recheck `IPAddressAllow`/`-p` above |
| `bindings[].uid_matches_self` | Recipe A: `false`; Recipe B: may be `true` or unavailable | Recipe A lacks the intended identity separation; Recipe B never claimed it |
| `owning_process.resolution` | usually `"permission_denied"` | A `"resolved"` result here is expected only if you ran the check as the same user/root as Ollama; it is not itself a finding |

A `"permission_denied"` resolution is the **correct, hardened** outcome per
the observer's own documentation, not an error to fix. This check proves
only what it says: current binding scope, and (when resolvable) identity
separation. It does not prove the running binary is unmodified, that a
loaded model is authentic, or that egress beyond loopback is blocked from
inside Ollama's own process. Recipe A is intended to supply that network
control; Recipe B is not. The observer cannot see whether Recipe A's controls
were actually applied versus merely intended.

## Explicit non-goals

- MEGALODON does not read, apply, template, or ship either example; both are
  copy-paste operator actions against operator-owned host configuration.
- Neither example is exercised by this repository's test suite: systemd units
  and container runtimes are not available in CI, so this document is
  reviewed guidance, not a tested contract like `contracts/*/v1`.
- Model artifact authenticity, GPU driver containment, and Windows/macOS
  equivalents remain open and are not addressed here.
- Applying either example does not change, weaken, or replace any bound in
  `docs/local-model-advisory-contract.md`; the client-side request remains
  exactly as bounded as before.
