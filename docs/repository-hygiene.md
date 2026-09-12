# Repository hygiene guard

The required `test` job runs `tools/check_repository_hygiene.py` before package
installation. It scans only files tracked by Git and emits bounded finding
categories without printing file contents. It reads at most 5 MiB plus one byte
per file, and refuses tracked symlinks and other non-regular final path
components. The checkout and its parent directories must remain trusted.

The guard fails on:

- a tracked filename that looks like a local secret or private key, with
  `.env.example` and `.env.*.example` retained as explicit examples;
- a tracked file larger than 5 MiB;
- a tracked binary file larger than 1 MiB; or
- a file that is unreadable, replaced, or changes during its scan.

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

## Read consistency and failure evidence

The initial pathname size is not sufficient: a file can grow between `lstat`
and the bounded read. The guard compares the initial file signature with the
opened descriptor before reading, then rechecks both descriptor and pathname
before accepting the bytes. Device, inode, file mode, link count, size, and
nanosecond modification/change timestamps must agree. Access time is excluded
because the scan itself can update it. The actual bytes returned, including the
one-byte overflow sentinel, also participate in the size check.

On Linux, `O_NOFOLLOW` prevents following a final-component symlink substituted
at open, and `O_NONBLOCK` prevents a substituted FIFO from blocking that open.
The opened descriptor must still identify a regular file with the original
signature before any content read. It is closed on success and refusal. Missing
platform flags are not evidence of equivalent native-platform protection;
native Windows acceptance remains separate.

A detected change produces `tracked file changed during scan` plus the tracked
relative name. An open/read/stat failure remains `tracked file is unreadable`.
Neither finding prints content, secret matches, or raw exceptions; the command
exits nonzero. Stop the concurrent writer, inspect the intended changes, and
rerun the check rather than accepting a partial scan or increasing the limits.

Regression tests inject growth, truncation, same-length rewriting, pathname
replacement, and deletion before or after the read. Synthetic Linux symlink and
FIFO substitutions are refused before content access; the FIFO probe has an
outer subprocess timeout. Unchanged boundary-size inputs and existing secret
markers retain their behavior. All fixtures are temporary and synthetic.

These are sampled consistency checks, not an atomic filesystem snapshot,
whole-checkout confinement, or protection from a malicious privileged runner.
Timestamp resolution varies by filesystem; changes that restore every sampled
attribute are not ruled out. A file may also change after its final check. The
guard reads working-tree bytes for Git-tracked names, not all Git history or a
frozen Git-index snapshot. Git enumeration/output limits, path-list validation,
and aggregate scan/output budgets remain separate controls. The diagnostic
filename bound below does not bound those operations.

Primary API basis: [Python file descriptors and stat fields](https://docs.python.org/3.12/library/os.html).

## Safe filename diagnostics

A tracked filename is untrusted log data too. On Linux, a name can contain a
newline, terminal escape, bidirectional text, or a runner-command delimiter.
Printing it verbatim can split one finding into forged log lines or pass command
text to a CI runner even though the guard still exits nonzero. This is a logging
boundary, not evidence that a real credential was exposed or a command executed.

Every finding renders the original relative name as printable ASCII using
JSON string escapes without surrounding quotes. Colons and hash characters are
also escaped as `\u003a` and `\u0023`, preventing both `::` and `##[` runner
command delimiters, including in the middle of a line. Literal backslashes are
escaped rather than changed to slashes, so a POSIX filename is not mislabeled
as a different directory path. Ordinary short ASCII names keep their display.

The rendered name is at most 256 ASCII characters, including `...[truncated]`
when needed. Space for that marker is reserved from the prefix budget, and the
prefix ends only between complete escapes. Encoding stops at that bound instead
of expanding an arbitrarily long suffix. This is a display abbreviation, not
an identity token, safe shell argument, reusable path, or complete JSON document.
Do not copy an escaped or truncated diagnostic into a command as a file path.

Only presentation is shortened. Sensitive-name matching and file opening use
the full original input under the existing rules; content checks, limits,
descriptor consistency and exit statuses are unchanged. Multiple findings
remain multiple lines; one filename cannot add a line or a raw terminal control.
The number of files and findings, Git output size and duration, all-history
secret detection, and malicious-runner protection remain outside this control.

Synthetic regressions cover controls, Unicode/bidirectional characters, both
runner delimiter forms, all finding categories, a long path whose content must
still be scanned, and distinct POSIX backslash/slash paths. A temporary local Git
repository plus an outer-time-limited child process exercises the real path-list
and CLI output. Output is captured and asserted, never sent as runner commands.
Native Windows filename acceptance is not established by the POSIX fixtures.

Primary references: [Python JSON escaping](https://docs.python.org/3.11/library/json.html)
and [GitHub workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands).
