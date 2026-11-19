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
| `WEB_SCRIPT_ADDED` | HIGH | A new script elsewhere under a web root |
| `WEB_SCRIPT_CHANGED` | MEDIUM | A script's contents changed |

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
* **Between checks.** A script dropped and deleted between two checks is not
  seen. Its commands are, if a service runs them, by the
  [process ancestry watch](process-ancestry.md).
* **Code in a database** (stored templates, plugin code kept in SQL) is not
  read.
* **Files over 16 MiB** and unreadable scripts are compared by size and
  modification time instead of their contents.
