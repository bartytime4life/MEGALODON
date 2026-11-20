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
* **apt settings.** `apt.conf.d` (in name order) and then `/etc/apt/apt.conf`
  are read with apt's own rules: nested blocks, lists, comments, and the files
  apt skips. A setting assigned more than once is judged by its last value, the
  one apt uses. Hook lists keep every item. These settings are reported:
  - **Signature checks off:** `APT::Get::AllowUnauthenticated`.
  - **Signature checks weakened:** `Acquire::AllowInsecureRepositories`,
    `Acquire::AllowDowngradeToInsecureRepositories`,
    `Acquire::AllowWeakRepositories`, and `Acquire::Check-Valid-Until "false"`.
  - **Connections not verified:** `Acquire::https::Verify-Peer` or
    `Verify-Host` set to false, for every host or for one.
  - **apt moved elsewhere:** `Dir`, `Dir::Etc`, `Dir::Etc::Trusted`,
    `TrustedParts`, `SourceList` or `SourceParts` set, which makes apt read its
    keys or sources from another folder. The check reads them from there too,
    so sources and keys at the new place are recorded and reported like any
    others. A relocation is recorded with its value, so pointing it somewhere
    else again is reported.
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
* **pip.** It reads `/etc/pip.conf`, `/etc/xdg/pip/pip.conf` and each
  account's own `~/.config/pip/pip.conf` and `~/.pip/pip.conf`, the last value
  winning, as pip does. Accounts with no settings of their own use the
  system's and are not listed apart. It records `index-url`, with PyPI when it
  is not set, and every `extra-index-url`. pip packages are not signed: TLS is
  their only check. So these are reported:
  - an index or a `trusted-host` that pip reaches without checking its
    certificate;
  - an `extra-index-url`. pip takes whichever index offers the higher version,
    so a package with an internal name can be replaced from the other index
    (dependency confusion).
* **npm.** It reads npm's built-in `npmrc`, `/etc/npmrc`, `/usr/etc/npmrc`,
  `/usr/local/etc/npmrc` and each account's `~/.npmrc`. It records `registry`,
  with the npm registry when it is not set, and every scoped registry, such as
  `@corp:registry`. npm packages are checked only by TLS too, so a
  plain-HTTP registry and `strict-ssl=false` are reported.
* **pip and npm environment variables.** These override the settings files,
  so they are read where a login sets them:
  - for every account: `/etc/environment`, `/etc/environment.d/*.conf`,
    `/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc` and
    `/etc/zsh/zshenv`;
  - for one account: its `~/.pam_environment`,
    `~/.config/environment.d/*.conf`, `~/.profile`, `~/.bash_profile`,
    `~/.bashrc`, `~/.zshenv` and `~/.zshrc`.

  The variables read are `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`,
  `PIP_TRUSTED_HOST`, npm's `npm_config_registry` and `npm_config_strict_ssl`
  in any letter case, and the variables that name another settings file:
  `PIP_CONFIG_FILE`, `npm_config_userconfig` and `npm_config_globalconfig`.
  That file is then read too. A source or setting found this way says where
  it was set, for example `/etc/environment (PIP_INDEX_URL)`. An index set
  for every login is reported like one set in `/etc/pip.conf`: a move away
  from PyPI is a redirect. A value built from other variables or commands,
  such as `"$CORP_INDEX/simple"`, cannot be known without running the shell.
  It is listed as a gap, not guessed.
* **Projects and virtual environments.** These have settings of their own,
  which win over the system's and the account's:
  - a virtual environment's own `pip.conf`, in the folder that holds its
    `pyvenv.cfg`, read after the account's files;
  - a project's own `.npmrc`, read after the account's `~/.npmrc`;
  - the pip options in a `requirements*.txt` or `constraints*.txt` file, or
    a pip-tools `.in` file:
    `-i`/`--index-url` (the last one wins), `--extra-index-url`,
    `--trusted-host` and `-f`/`--find-links`. They apply to
    `pip install -r` on that file, over every settings file.

  Each is labelled with where it is, for example `pip for virtual environment
  /home/dev/app/.venv` or `npm for project /srv/web`. Only what that file
  sets itself is recorded; what it inherits is recorded once, for the
  account or the system. Environment variables still win over these files,
  as they do in pip and npm. A virtual environment or project first seen with
  its own index is reported as an added source. A later change of that index
  is reported as a redirect. Plain HTTP, trusted hosts, extra indexes and
  `strict-ssl=false` are reported as for any other scope. A value built from
  an environment variable, such as `registry=${NPM_REGISTRY}` or
  `--index-url ${CORP_INDEX}`, is listed as a gap.

  They are looked for in each account's home and in `/opt`, `/srv`,
  `/var/www` and `/app`, up to 6 folders deep and 20,000 folders in all.
  Beyond that a gap is listed. Symbolic links are not followed. Hidden
  folders are skipped, except `.venv` and `.virtualenvs`. Nothing inside a
  virtual environment, `node_modules` or `site-packages` is read. A home's
  own `.npmrc` is the account's, not a project's. On this project's test
  machine, a warm check took 0.2 seconds over 4,500 folders; the first after
  a boot can take much longer on slow disks.
* **Python project files.** In the same folders:
  - **`pyproject.toml`:** Poetry's `[[tool.poetry.source]]`, uv's
    `index-url`, `extra-index-url`, `find-links` and `[[tool.uv.index]]` (also
    under `[tool.uv.pip]`), and PDM's `[[tool.pdm.source]]`;
  - **`Pipfile`:** Pipenv's `[[source]]` entries.

  Each index is recorded as a source labelled with the tool and the file, for
  example `poetry for /srv/api/pyproject.toml`. These are reported:
  - a plain-HTTP index;
  - `verify_ssl = false` (Pipenv, PDM) and uv's `allow-insecure-host`;
  - mixed indexes, only where the tool compares versions across them. That is
    uv with `index-strategy = "unsafe-best-match"`, and PDM without
    `respect-source-order = true` for a source without `include_packages`.
    Poetry, Pipenv and uv's default take each package from one index.
* **npm and yarn lockfiles.** `package-lock.json`, `npm-shrinkwrap.json` and
  `yarn.lock` give a URL for every package, and `npm ci` downloads each one
  from that URL. npm swaps `registry.npmjs.org` for the configured registry,
  but any other host is fetched as written. So an edited lockfile can install
  code from anywhere, whatever the settings say.
  - **Recorded.** The hosts each lockfile downloads from, as sources labelled
    `npm lockfile PATH`. Lockfile versions 1, 2 and 3 are read, and yarn's
    `resolved` and `resolution` URLs. Git and file dependencies are not
    hosts, and are skipped.
  - **Foreign hosts.** A host that none of the project's registries names is
    `PACKAGE_LOCKFILE_FOREIGN_HOST`. The registries are the system's,
    account's and project's `.npmrc` and the environment, as for that
    project; `registry.npmjs.org` and `registry.yarnpkg.com` always count.
    It is reported at baseline time too. On this project's test machine it
    found two tool folders built against a private mirror the machine's own
    settings do not name.
  - **Plain HTTP.** A host reached over plain HTTP is reported as
    `PACKAGE_TRANSPORT_WEAKENED`.
* **flatpak.** It reads the remotes in `/var/lib/flatpak/repo/config` and in
  each account's `~/.local/share/flatpak/repo/config`. Disabled remotes are
  skipped. Each remote's trusted keys, `NAME.trustedkeys.gpg`, are read and
  recorded like apt keys, so a key added to a remote is reported.
  `gpg-verify=false` turns signature checks off. `gpg-verify-summary=false`
  leaves the remote's list of apps unchecked.
* **snap.** A snap installed with `snap install --dangerous` has a revision
  starting with `x`, and its signature was not checked. `SNAPPY_FORCE_API_URL`
  and snapd's other store variables, set in a `snapd.service.d` drop-in, send
  snapd to another store.
* **When these tools are present.** pip and npm are recorded when the
  program or a settings file is there, flatpak when it has a repository, and
  snap when snapd has a state folder. A tool's default index, first seen after
  an upgrade, is not reported as added. A move away from it is reported as
  redirected.
* **Who can change it.** These folders, every folder above them and the files
  in them are checked for whether an account other than root can change them.
  So is every keyring a source names, together with the folders above it and,
  for a symlinked keyring, the file it leads to and the folders above that.
  The folders checked are:
  - `/etc/apt` and its folders;
  - `/usr/share/keyrings`;
  - `/etc/yum.repos.d`, `/etc/dnf`;
  - `/etc/pki/rpm-gpg`;
  - the system-wide pip and npm settings, flatpak's repository settings and
    its trusted keys, snapd's drop-ins, and root's own pip and npm settings;
  - the system's environment and login files listed above, since whoever
    can change them can point every install elsewhere.

  Other accounts' own settings are theirs to change, and are not reported as
  writable.

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
| `PACKAGE_TRANSPORT_WEAKENED` | MEDIUM; HIGH for pip and npm | HTTPS certificates or host names are not checked, or a pip or npm index is reached over plain HTTP. For apt and dnf, signatures still protect packages, but not keys or lists downloaded that way. pip and npm packages have no signatures, so nothing checks them. |
| `PACKAGE_INDEX_MIXED` | MEDIUM | pip installs from an `extra-index-url` as well as its index and takes the higher version: a package with an internal name can be replaced from the other index. Reported at baseline time too. |
| `PACKAGE_LOCKFILE_FOREIGN_HOST` | MEDIUM | A lockfile downloads packages from a host none of its project's registries names, which `npm ci` fetches as written. Reported at baseline time too. |
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
* **The settings files, not every way to name an index.** Projects outside
  the folders above, or deeper or past the limit, are not seen. Nor are:
  - an environment variable set anywhere other than the login files above,
    such as a systemd unit, a CI job or a command line;
  - yarn's and pnpm's own settings (`.yarnrc.yml`, `pnpm-workspace.yaml`), or
    pnpm's lockfile;
  - indexes in `setup.cfg`, `tox.ini` or a `uv.toml` outside a project;
  - which host a lockfile's package actually came from, or whether its
    integrity hash matches;
  - a snap store proxy set with `snap set`;
  - container registries.
* **A project's files are its owner's to change.** Write access is checked
  for the system's files only, as for accounts' own settings.
* **No expiry or revocation.** Key signatures are not parsed, so an expired or
  revoked key is reported only by its size and algorithm.
* **The files as written.** Settings given on apt's command line, or a
  configuration file named by `APT_CONFIG`, are not seen.
