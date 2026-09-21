# Operator-host AI observation — 2026-09-21

Repository source pin before this branch: `main@bdddd427df3c06e30c0d7e6e3405a0e1932fc971`.
This is one host snapshot, not a portable installation claim or provider
acceptance record.

| Check | Observation |
| --- | --- |
| Kernel/OS | Linux `7.0.0-31-generic`, Ubuntu 24.04.5 LTS, x86_64 |
| Operator | UID 1000 `bartytime`; groups `bartytime`, `nogroup` |
| Python | global `python3` 3.10.9; repository `.venv312` points to Python 3.12 |
| Ollama executable | `/usr/local/bin/ollama`, version `0.24.0`; systemd starts that binary. `dpkg-query` does not own this path. A separate Snap `ollama` v0.32.14 is installed but disabled. |
| Ollama service | `ollama.service` active/enabled, `User=ollama`, `Group=ollama`; no observed root service configuration. |
| Effective environment | `OLLAMA_HOST=0.0.0.0:11434`, `OLLAMA_MODELS=/var/snap/ollama/common/models`; service PATH includes user-local Node/Python entries. |
| Listener | `ss -lntp` showed `*:11434`; **not loopback-only**. The new AI adapter refuses inference under this posture. |
| Service isolation | Effective `IPAddressDeny` and `IPAddressAllow` were empty; `NoNewPrivileges=no`, `ProtectSystem=no`, `ProtectHome=no`, `PrivateTmp=no`, `MemoryMax=infinity`. Ollama process egress and resource containment are not established. |
| Qwen tags | `qwen2.5:7b-instruct-fp16` with local manifest digest `59805ce4a4046be2d8f63231a78daacd2e66f5dccf1a64d0d138ebeeb26ff16c`; `qwen3.6:35b` and `qwen3.6:latest` both showed `07d35212591fc27746f0a317c975a6d68754fb38e9053d82e25f06057af28522`. |
| GPU | Service log announced CUDA 13.0 inference compute on an NVIDIA GeForce RTX 5080 with 15.9 GiB VRAM. The sandboxed `nvidia-smi` could not access the driver, but normal-host `nvidia-smi` succeeded: driver 580.173.02, reported CUDA 13.0, compute capability 12.0, 16303 MiB. Driver visibility is confirmed; this control plane has **not** run Qwen inference or proved model GPU use because the non-loopback listener is refused. |
| MEGALODON | Local-first Python CLI, private SQLite schema v3, read-only telemetry HUD, plan-only nftables backend, existing advisory-only Qwen adapter and model-containment observer. |

The installed binary plus disabled Snap indicate a local binary/systemd runtime
with reused Snap model storage; the exact `/usr/local` installer provenance was
not established. The current service override is a root-owned operator task.
No service setting, model, firewall rule, package or GPU driver was changed as
part of this observation.
