# Package sources and signing keys

Every package the machine installs comes from a source the package manager
knows about, and is checked against a signing key. Each of these lets an
intruder install their own code as root:
- adding a key;
- pointing a source at their own server;
- turning signature checks off.

The next routine update does it for them. A package manager hook is worse: the
intruder's command runs as root on every install. These are ATT&CK T1195.002,
T1553 and T1546.016. `megalodon packages` records the sources, keys and hooks
and reports what changes.

```bash
sudo megalodon packages baseline
```

```bash
sudo megalodon packages check
```

```bash
sudo megalodon packages accept
```

* **`baseline`** records the following in `~/.config/megalodon/packages.json`
  (mode 600):
  - every package source;
  - every signing key, where it is kept and which sources use it;
  - every package manager hook;
  - every setting that weakens signature checks.

  Signature checks that are already off, weakened settings, hooks that already
  look wrong, and files an ordinary account can already change are reported at
  once. They are not recorded as normal.
* **`check`** reports what changed, most severe first. It exits 1 on findings
  and 2 on an error. Sources, keys and hooks that went away are listed under
  `removed`.
* **`accept`** records the current state after review, for example after you
  add a vendor's source on purpose.

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The [scheduler](scheduling.md)
runs the check hourly, and the [response engine](response-engine.md) reads it
on every pass.

Read-only: files are only read. Keys are read straight from the keyring
files, not with `gpg`, which would create files in a home folder. On rpm
systems, the keys imported into rpm are listed with `rpm -q`, which only
reads.

## What is checked

* **apt sources.** It reads `/etc/apt/sources.list` and the `.list` and
  `.sources` files in `sources.list.d`, in both the one-line and the deb822
  formats; deb822 sources set to `Enabled: no` are skipped. For each source it
  records:
  - the server and suite;
  - the key it names with `signed-by`, which can be a file, a fingerprint or an
    inline key.

  A source with `trusted=yes` is not checked at all. `allow-insecure`,
  `allow-downgrade-to-insecure`, `allow-weak` and `check-valid-until=no`
  check it less strictly.
* **apt keys.** apt trusts keys in `/etc/apt/trusted.gpg` and
  `/etc/apt/trusted.gpg.d` for every source that does not name its own key.
  Keys in `/etc/apt/keyrings` and `/usr/share/keyrings` are used only by the
  sources that name them. Each key is recorded by fingerprint, with its
  algorithm, size and first user ID. Armored and binary keyrings are both
  read. A GnuPG keybox, which apt cannot use, is listed as a gap.
* **apt settings.** `/etc/apt/apt.conf` and `apt.conf.d` are read with apt's
  own rules: nested blocks, lists, comments, and the files apt skips. These
  settings are reported:
  - **Signature checks off:** `APT::Get::AllowUnauthenticated`.
  - **Signature checks weakened:** `Acquire::AllowInsecureRepositories`,
    `Acquire::AllowDowngradeToInsecureRepositories`,
    `Acquire::AllowWeakRepositories`, and `Acquire::Check-Valid-Until "false"`.
  - **Connections not verified:** `Acquire::https::Verify-Peer` or
    `Verify-Host` set to false, for every host or for one.
  - **apt moved elsewhere:** `Dir::Etc::Trusted`, `TrustedParts`, `SourceList`
    or `SourceParts` set, which makes apt read its keys or sources from
    another folder.
* **apt hooks.** These are commands run as root:
  - `DPkg::Pre-Invoke`, `Post-Invoke` and `Pre-Install-Pkgs`;
  - `APT::Update::Pre-Invoke` and `Post-Invoke`;
  - the proxy auto-detect command;
  - `Dir::Bin`, the programs apt runs in place of dpkg and its download methods.
* **dnf and yum.** It reads `/etc/dnf/dnf.conf`, `/etc/yum.conf` and the
  enabled sources in `/etc/yum.repos.d`. These are reported:
  - **Signature checks off:** `gpgcheck=0` on a source, or in `[main]` for
    sources that do not set it. A source with no `gpgcheck` anywhere is also
    reported, because dnf does not check by default.
  - **Connections not verified:** `sslverify=0`.
  - **Keys over plain connections:** a `gpgkey` fetched over plain HTTP or FTP.

  The keys are those in `/etc/pki/rpm-gpg` and those imported into rpm.
  Hooks are the commands in dnf's post-transaction actions.
* **Who can change it.** These folders, every folder above them, the files in
  them, and every keyring a source names are checked for whether an account
  other than root can change them:
  - `/etc/apt` and its folders;
  - `/usr/share/keyrings`;
  - `/etc/yum.repos.d`, `/etc/dnf`;
  - `/etc/pki/rpm-gpg`.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `PACKAGE_SIGNATURES_OFF` | CRITICAL | A source with `trusted=yes`, `APT::Get::AllowUnauthenticated`, or a dnf or yum source that does not check signatures. Reported at baseline time too. |
| `PACKAGE_CONFIG_WRITABLE` | CRITICAL when everyone can write, HIGH otherwise | A source list, keyring, package manager setting or one of their folders can be changed by an ordinary account. Reported at baseline time too. |
| `PACKAGE_MANAGER_HOOK_ADDED` | CRITICAL when it runs from a temporary folder or fetches from the network, HIGH otherwise | A new command runs as root when packages are installed or the lists refresh |
| `SIGNING_KEY_ADDED` | HIGH when apt trusts it for every source or a source names it, MEDIUM when nothing uses it yet | A new signing key, or a key moved to where apt trusts it for every source |
| `PACKAGE_SOURCE_REDIRECTED` | HIGH | A source in the same file and suite now points at another server |
| `PACKAGE_SOURCE_CHANGED` | HIGH | A source now names another key, or the keyring it names holds other keys |
| `PACKAGE_CONFIG_REDIRECTED` | HIGH | apt is told to read its keys, sources or settings from another folder. Reported at baseline time too. |
| `PACKAGE_MANAGER_HOOK_SUSPICIOUS` | HIGH | At baseline: a hook already runs from a temporary folder or fetches from the network |
| `PACKAGE_SIGNATURE_CHECK_WEAKENED` | HIGH | Signatures are checked less strictly, or a signing key is fetched over a plain connection. Reported at baseline time too. |
| `PACKAGE_SOURCE_ADDED` | MEDIUM | A new source |
| `PACKAGE_TRANSPORT_WEAKENED` | MEDIUM | HTTPS certificates or host names are not checked. Signatures still protect packages, but not keys or lists downloaded that way. |
| `WEAK_SIGNING_KEY` | MEDIUM | A key that is trusted, or used by a source, is RSA or DSA under 2048 bits or an old version 3 key. Keys kept only as removed keys, which nothing uses, are not reported. |

The **package-trust-changed** response playbook covers the HIGH and CRITICAL
rules. It collects evidence and notifies you. Keys, sources and hooks are the
administrator's to put back.

## Limits

* **The settings, not what a run used.** A source added, used and removed
  between checks is not seen. The [program integrity](binary-integrity.md)
  check and package-manager logs cover what got installed.
* **Signatures, not trust.** A source that is signed by the key it names is
  accepted, even if the key and the source were added together by an intruder.
  That is why every added key and source is reported for you to confirm.
* **apt and dnf only.** pip, npm, snap, flatpak and container registries are
  not read.
* **No expiry or revocation.** Key signatures are not parsed, so an expired or
  revoked key is reported only by its size and algorithm.
* **The files as written.** Settings given on apt's command line, or a
  configuration file named by `APT_CONFIG`, are not seen.
