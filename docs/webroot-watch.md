# Web-root watch

A web shell is a script dropped where the web server will run it:
- a `.php` file in an upload folder;
- a `.jsp` in a `webapps` folder;
- PHP code hidden inside a `.jpg`;
- a backdoor added to an existing page.

`megalodon webroot` records the server-side scripts under the web roots and
reports what is new or changed. It also looks inside those files for
well-known web-shell shapes (ATT&CK T1505.003).

```bash
megalodon webroot baseline
```

```bash
megalodon webroot check
```

```bash
megalodon webroot watch
```

```bash
megalodon webroot accept
```

* **`baseline`** records every server-side script under the web roots in
  `~/.config/megalodon/webroot.json` (mode 600). The default roots are
  `/var/www`, `/srv/www`, `/srv/http`, `/usr/share/nginx/html` and Tomcat
  `webapps` folders. Pass `--root` (repeatable) for this server's own
  document roots. A web shell already present would otherwise be recorded
  as normal, so `baseline` reports any it finds and exits 1.
* **`check`** reports new and changed scripts, most severe first. It exits 1
  on findings and 2 on an error. Removed scripts are listed under `removed`
  and are not findings.
* **`watch`** (Linux) looks at each file as it is written or moved in,
  through inotify, instead of every 15 minutes. It compares each one with
  the baseline as `check` does and prints each finding once as a JSON line,
  with `--alert` as well. A script that appeared while it watched and is
  deleted, or moved out of the web roots, within an hour is reported as
  `WEB_SCRIPT_DROPPED_AND_REMOVED`, with the hash it had: a web shell
  dropped, used and removed between two checks. That includes a script in a
  folder moved out of the web roots, and a rename within them keeps the
  time the script first appeared. It looks at every file once when it
  starts; when the kernel drops file events under load, it watches every
  folder again and looks at every file. An `accept` made while it runs is
  picked up.
* **`accept`** records the current scripts once you have reviewed them, for
  example after a deployment or a CMS update.

Run it as root or as the account that owns the site, so every script can be
read. With `--alert`, a summary also goes to the
[off-machine alerts](off-machine-alerts.md). The
[response engine](response-engine.md) reads `check` on every pass.

## What is reported

| Rule | Severity | When |
| --- | --- | --- |
| `CODE_IN_NON_SCRIPT_FILE` | CRITICAL | A file that should only be served (an image, text, CSS, font, archive) contains server-side code (`<?php`, `<%`, `<script runat="server">`) |
| `SCRIPT_IN_UPLOAD_FOLDER` | CRITICAL | A new script in a folder meant for uploads or static files: `uploads`, `images`, `media`, `files`, `cache`, `tmp`, `static`, `assets` and similar |
| `WEB_SHELL_PATTERN` | HIGH | The file contains a known web-shell shape (see below) |
| `WEB_SCRIPT_REPLACED_BY_LINK` | HIGH | A recorded script is now a symbolic link, so the web server serves another file in its place |
| `WEB_SCRIPT_ADDED` | HIGH | A new script elsewhere under a web root |
| `WEB_SCRIPT_CHANGED` | MEDIUM | A script's contents changed |
| `WEB_LINK_ADDED` | MEDIUM | A new symbolic link under a web root |
| `WEB_LINK_CHANGED` | MEDIUM | A link now leads elsewhere, or the file it leads to changed |
| `WEB_SCRIPT_DROPPED_AND_REMOVED` | HIGH | `watch`: a script that appeared while watching was deleted, or moved out of the web roots, within an hour (also T1070.004) |

Symbolic links are recorded with their targets. A link to a file has that
file's contents hashed and checked for web-shell shapes, wherever it is. A
link to a folder is recorded but not followed, since it may lead out of the
web root or loop, and the report lists it under `gaps`.

A script is a file with a server-side extension (`.php` and its variants,
`.phtml`, `.phar`, `.jsp`, `.asp`, `.aspx`, `.ashx`, `.cfm`, `.cgi`, `.pl`,
`.py`, `.sh` and others), or any file whose first 4 KiB open server-side
code. `.git`, `node_modules` and other version-control folders are skipped.

### Web-shell shapes

* a command or `eval` call fed straight from request input
  (`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`...);
* `eval` of decoded or decompressed text (`base64_decode`, `gzinflate`,
  `str_rot13`...);
* `preg_replace` with the code-running `/e` flag;
* `create_function` or backticks built from request input;
* Java `Runtime.getRuntime().exec(request.getParameter(...))`;
* ASP `eval(Request...)`, `Execute(Request...)` or `Process.Start(...Request...)`.

These are looked for in each new, changed or baselined file, in its first
2 MiB.

## Response

The `web-shell-file` playbook covers `SCRIPT_IN_UPLOAD_FOLDER`,
`CODE_IN_NON_SCRIPT_FILE` and `WEB_SHELL_PATTERN`. It plans to collect
evidence, quarantine the file and notify you. `/var/www/` is among the
default `quarantine_roots` for that reason. New and changed scripts
elsewhere are left to you, since deployments add and change them.

## Limits

* **Shapes, not proof.** An attacker can write a web shell that matches none
  of the shapes; it is still reported as new or changed. Some legitimate
  tools also match.
* **Between checks.** `check` does not see a script dropped and deleted
  between two runs; `watch` does. `watch` keeps the hash and the shapes it
  found, not a copy of the file. It watches at most 65,536 folders; past
  that, `check` still covers them. A shell's commands are also seen, if a
  service runs them, by the [process ancestry watch](process-ancestry.md).
* **Code in a database** (stored templates, plugin code kept in SQL) is not
  read.
* **Files over 16 MiB** and unreadable scripts are compared by size and
  modification time instead of their contents.
