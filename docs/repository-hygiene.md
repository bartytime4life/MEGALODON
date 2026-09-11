# Repository hygiene guard

The required `test` job runs `tools/check_repository_hygiene.py` before package
installation. It scans only files tracked by Git and emits bounded finding
categories without printing file contents.

The guard fails on:

- a tracked filename that looks like a local secret or private key, with
  `.env.example` and `.env.*.example` retained as explicit examples;
- a tracked file larger than 5 MiB; or
- a tracked binary file larger than 1 MiB.

It also reports high-confidence private-key, AWS access-key, GitHub token, and
Slack token markers. This is a lightweight repository guard, not a complete
secret scanner, history rewrite, malware detector, SBOM, or substitute for
external credential rotation. The existing `.gitignore`, exact CI constraints,
full-SHA Actions, and no-persisted-checkout-credentials checks remain separate
controls.

Run it from a trusted checkout with:

```bash
python tools/check_repository_hygiene.py
```

A clean result is repository-state evidence only; it does not authorize a
release, package publication, deployment, or production-readiness claim.
