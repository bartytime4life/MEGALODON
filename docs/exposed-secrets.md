# Exposed secrets

Secrets belong where only their owner can read them. They leak when:
- a private key or credential file can be read by other accounts;
- a token sits in a file or shell history that others can read;
- a password is passed on a command line, which every local user can see;
- a copy of a configuration file, a database dump, an `.env` file or a `.git`
  folder is left under a web root, where a server may hand it to anyone.

Intruders look for exactly these first (ATT&CK T1552.001, T1552.003,
T1552.004). `megalodon secrets` finds them and says who can read each one.

```bash
sudo megalodon secrets scan
```

```bash
sudo megalodon secrets baseline
```

```bash
sudo megalodon secrets check
```

```bash
sudo megalodon secrets accept
```

* **`scan`** reports every exposed secret now and records nothing. `--path`
  searches a folder of your choice instead of the default ones.
* **`baseline`** scans, reports everything it finds, and records the findings
  in `~/.config/megalodon/secrets.json` (mode 600) as reviewed. An exposed
  secret is never recorded as normal without being reported.
* **`check`** reports exposed secrets that are not in the baseline. It exits 1
  on findings and 2 on an error.
* **`accept`** records the current findings after review.

With `--alert`, findings also go to the
[off-machine alerts](off-machine-alerts.md). The [scheduler](scheduling.md)
runs the check daily at 04:23, and the [response engine](response-engine.md)
reads it on every pass.

## Secret values never leave the file

A report names the kind of secret, where it is, its length, and who can read
it. For tokens it adds a short SHA-256 fingerprint, so the same token can be
recognized in two places. A password gets no fingerprint: a hash of a short
password lets anyone holding the report test guesses against it. Values are
not stored in the baseline either.

## What is checked

* **Who can read a file.** A file counts as exposed only if another account
  can actually reach and read it. Each account other than the owner and root
  is judged as the kernel judges it, by the owner, group or other bits of the
  file and of every folder on the way. That covers:
  - a file anyone can read;
  - a file readable by its group;
  - a file anyone could read, inside a folder only one group can enter. Then
    the members of that group can read it.

  The report names the accounts, or says `everyone`. Members of `shadow`
  reading the password files, and of `ssl-cert` reading TLS keys, do not count:
  those groups exist to be read that way. Files only their owner can read are
  not opened at all.
* **Credential files by name:**
  - **In each home folder:** `.ssh/id_*` (not `.pub`), `.aws/credentials`,
    `.docker/config.json`, `.kube/config`, `.netrc`, `.pgpass`, `.my.cnf`,
    `.git-credentials`, `.npmrc`, `.pypirc`, `.vault-token`, and the gcloud,
    gh, Azure and Terraform credential stores.
  - **System-wide:** `/etc/shadow` and `/etc/gshadow` and their backups, SSH
    host keys, Wi-Fi and VPN secrets, WireGuard configurations,
    Let's Encrypt keys, `/etc/ssl/private`, the Kerberos keytab, LDAP secrets,
    and Kubernetes admin files.
* **Secrets by content.** Files that others can read are searched in `/etc`,
  `/home`, `/root`, `/srv`, `/opt`, `/var/www`, `/usr/local/etc`,
  `/var/backups`, `/var/lib/jenkins`, `/tmp`, `/var/tmp` and `/dev/shm`. Shell
  histories are included. They are searched for:
  - **Private keys** with real key material. PEM, OpenSSH and PGP keys are
    read; an encrypted key is one severity step lower.
  - **Token shapes specific enough to trust:** AWS access keys, GitHub,
    GitLab, Slack, Stripe live, Anthropic, npm and PyPI tokens, and Slack
    webhooks.
  - **In configuration files and histories only:** passwords in URLs (such as
    `postgres://app:...@db`) and Google API keys. Program code and
    documentation are full of example passwords, and SDKs ship Google keys
    that are public by design.

  Placeholders such as `password`, `changeme`, `${VAR}` and `<token>` are
  ignored, as are example hosts and AWS's documented example key.
* **Installed code is skipped.** These folders are not searched, because
  libraries ship sample keys and passwords by the hundred:
  - `node_modules`, `site-packages`, gems and vendored `third_party` code;
  - tests, fixtures, examples and documentation;
  - caches and language version managers.
* **Web roots.** Under `/var/www`, `/srv/www`, `/srv/http`,
  `/usr/share/nginx/html` and Tomcat `webapps`, these are reported:
  - `.env` files;
  - copies of scripts or configuration files, such as `wp-config.php.bak`, which
    a server hands out as plain text;
  - database files and dumps, backup archives, key stores and credential
    files;
  - `.git`, `.svn` and `.hg` folders;
  - tokens or private keys in any file that is not a server-side script.
* **Command lines.** Every process's command line is checked. It flags options
  such as `--password` and `--token`, `mysql -p...`, `sshpass -p`,
  `curl -u user:pass`, and any token shape. When `/proc` is mounted with
  `hidepid`, other users cannot see command lines, and none are reported.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `SECRET_FILE_IN_WEB_ROOT` | CRITICAL; HIGH for `.htpasswd` | A file that holds secrets is under a web root |
| `VERSION_CONTROL_IN_WEB_ROOT` | CRITICAL | A `.git`, `.svn` or `.hg` folder is under a web root |
| `SECRET_IN_WEB_ROOT` | CRITICAL | A token or private key is in a web-root file that is not a server-side script |
| `PRIVATE_KEY_EXPOSED` | CRITICAL when everyone can read it, HIGH for a group; one step lower when encrypted | A private key can be read by other accounts |
| `CREDENTIAL_FILE_EXPOSED` | CRITICAL when everyone can read it, HIGH for a group | A password file or credential store can be read by other accounts |
| `SECRET_IN_COMMAND_LINE` | HIGH | A password or token is on a running process's command line |
| `SECRET_IN_EXPOSED_FILE` | HIGH when everyone can read it, MEDIUM for a group | A token or password is in a readable file or shell history |

The **secret-exposed** response playbook covers the HIGH and CRITICAL rules
and notifies you. Nothing on the machine needs preserving: the fix is to
restrict or move the secret and then **replace it**. Taking away access does
not undo a copy someone already made.

## Limits

* **Shapes, not proof.** A token shape can be a sample value, and a secret in
  an unknown shape, such as a database password in a custom setting, is not
  recognized. Credential files and keys are found by name and structure, not
  by guessing.
* **Text up to 1 MiB.** Binary files and the rest of larger files are not
  searched. A web-root key store or database file is still reported by name.
* **Root is needed** to search other accounts' home folders. Without it, the
  report says so.
* **The search stops** after 500,000 files or two minutes, and the report
  says so.
* **Environment variables** are not read: only a process's owner and root
  can read them.
