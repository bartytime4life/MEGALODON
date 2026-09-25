# Native Linux installer lifecycle qualification

The `Native Linux installer lifecycle` pull-request workflow qualifies the real
installer on Ubuntu 24.04 x86-64 / Python 3.12 as a non-root user. Existing unit
tests keep their synthetic release builder; this separate rehearsal calls the
unchanged real builder three times, creating private virtual environments and
installing the core package from the exact clean candidate commit and tree.

Build requirements are downloaded using the existing
`constraints/build-linux-cp312.txt` wheel hashes. The collector checks the exact
wheel set and bytes before and after the rehearsal. Installer subprocesses use
only this wheelhouse with `PIP_NO_INDEX=1`; additional pip source settings are
removed for the rehearsal. This qualifies the bounded offline build inputs of
this check, not general offline installation from a checkout.

Every installer destination is an explicit `InstallPaths` field under one new
private temporary directory. The rehearsal does not change `HOME`, use the
operator's installation paths, bypass the supported-user or filesystem guards,
run launchers, open a browser, start the HUD or any service, or exercise capture,
models or firewall operations. Isolated installed Python runs outside the
checkout, verifies installed package bytes against the candidate source, checks
dependencies, and executes CLI help.

The phases establish:

1. Initial installation creates a usable real release.
2. Reinstalling the **same source** selects a new real release and retains the
   previous release. This does not qualify upgrades between different versions.
3. Repair restores a missing HUD launcher with its exact original bytes.
4. Modified desktop-entry bytes make repair and uninstall refuse without
   changing the selection, manifest, managed artifacts, data or settings.
5. An injected manifest-write failure occurs after a third real release has
   been built, installed, activated and independently import/CLI checked.
   Rollback preserves the former selection, manifest and artifact bytes/modes,
   removes the failed release, and leaves the selected installed CLI usable.
6. Uninstall removes managed releases and desktop artifacts. Synthetic data and
   operator-edited settings remain byte-identical through every phase.
7. The outer temporary directory is removed before a success receipt is emitted.

Only a closed, bounded JSON receipt is retained, containing source commit/tree,
platform/Python profile, locked build-wheel identities, the package content
digest, fixed outcomes and explicit exclusions. Host paths, usernames, raw
manifests, data, settings, subprocess output, and virtual environments are not
uploaded. The verifier rejects changed source pins, unsupported claims, extra
fields and noncanonical JSON. The receipt is qualification evidence, not an
authenticated attestation or independent acceptance.
Offline `verify` checks the recorded receipt and its source/input bindings; it
does not rerun the installer phases or authenticate their origin.

This same-source rehearsal does not prove desktop startup, arbitrary host
compatibility, cross-version migration, physical power-loss or disk-full
durability, Windows/macOS parity, operational acceptance, release publication or
permission to install on a host. Those remain separate gates.

For an already reviewed clean checkout, use Python 3.12 as an ordinary Linux
user. The following writes only new temporary directories; no `sudo` is used:

```bash
cd /path/to/reviewed/MEGALODON
evidence_dir="$(mktemp -d)"
mkdir -m 700 "$evidence_dir/wheels"
python3.12 -I -m pip download --require-hashes --only-binary=:all: --no-cache-dir \
  -r constraints/build-linux-cp312.txt --dest "$evidence_dir/wheels"
source_commit="$(git rev-parse HEAD)"
source_tree="$(git rev-parse 'HEAD^{tree}')"
python3.12 -I tools/installer_lifecycle_evidence.py --checkout "$PWD" \
  --expected-commit "$source_commit" --expected-tree "$source_tree" collect \
  --wheelhouse "$evidence_dir/wheels" > "$evidence_dir/receipt.json"
python3.12 -I tools/installer_lifecycle_evidence.py --checkout "$PWD" \
  --expected-commit "$source_commit" --expected-tree "$source_tree" \
  verify "$evidence_dir/receipt.json"
```
