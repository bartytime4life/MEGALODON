# Suricata engine-regression research packet

Status: **research recorded; experiment not run**.

This packet records two upstream Suricata changes published on 2026-10-22 that
are relevant to the bounded offline producer profile:

- fragmented TLS handshake headers could disable subsequent protocol
  inspection before
  [`bea218e7b1dd8ffb09f250e62c096c6b3da749b4`](https://github.com/OISF/suricata/commit/bea218e7b1dd8ffb09f250e62c096c6b3da749b4);
- a PCRE-only TCP stream rule group could repeatedly scan the entire growing
  stream before
  [`f87b8e64a5fb80788897f7a9073c5407a2f5bc96`](https://github.com/OISF/suricata/commit/f87b8e64a5fb80788897f7a9073c5407a2f5bc96).

The machine-readable [`research-packet.json`](research-packet.json) pins those
commit identities, the upstream claims, proposed experiment ceilings and every
remaining acceptance hold. That original packet contains no packet capture,
rule, configuration, executable, generated EVE output or pass result. The
adjacent [`experiment`](experiment/README.md) directory now supplies a separate
synthetic fixture-and-oracle candidate; it remains explicitly unexecuted.
The subsequent [`offline laboratory harness`](experiment/harness/README.md)
supplies deterministic controls and a separate opt-in runner. It does not
integrate engine operation into MEGALODON or claim native qualification.

## Why this does not run Suricata

MEGALODON's implemented boundary accepts one separately produced, completed
Suricata 8.0.7 alert-only EVE file. It does not install, launch, configure,
update or control Suricata. Parser fixtures establish only the MEGALODON
converter's behavior; they cannot establish whether an engine continued TLS
inspection or bounded its PCRE work.

No Suricata executable is available in the current verification runner, and
the repository has no accepted installed-producer identity. Treating a static
review or synthetic EVE line as a native engine pass would erase that evidence
gap.

## Separately authorized native experiment

The candidate packet now adds independently authored, non-sensitive synthetic
PCAPs and a minimal dedicated rule/configuration set. A later native experiment
still requires separate owner authorization and must:

1. bind the fixture, rule, configuration and both producer binaries by SHA-256;
2. run only a fixed direct argument vector against completed local PCAP files,
   with no shell, interface, network, rule update, service or watcher;
3. use one thread and enforce the packet, byte, output, address-space and
   elapsed-time ceilings in `research-packet.json` outside the producer;
4. define the TLS continuity oracle and PCRE scaling oracle before execution;
5. retain only whitelisted alert EVE and privacy-minimized timing/resource
   totals; and
6. produce a deterministic receipt that reports timeout, truncation,
   unavailable prerequisites and non-zero exit as explicit non-pass states.

The first comparison target remains the declared 8.0.7 profile. An unreleased
upstream commit is a research candidate, not a producer upgrade. A successful
bounded comparison would still not establish capture completeness, rule
quality, operational privacy, installed-host safety, deployment authority or
automatic response authority.
