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
frozen Git-index snapshot. Git enumeration/output limits and filename rendering
remain separate controls; this correction does not claim to bound them.

Primary API basis: [Python file descriptors and stat fields](https://docs.python.org/3.12/library/os.html).
