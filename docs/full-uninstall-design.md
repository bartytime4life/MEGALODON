# Full uninstall: inventory and removal gates

The current command is a **read-only inventory**:

```bash
cd /path/to/reviewed/MEGALODON
python3.12 -m megalodon.uninstall_audit --json
```

Run it once before a removal and again afterward to compare known surfaces.
It lists the installed HUD manifest, launchers, user service, managed data and
configuration, the named Wireshark profile, possible private Zeek prefixes,
selected companion directories, and fixed Ubuntu package presence. It does
not inspect evidence contents, search the whole disk, execute package removal,
stop services, change permissions, or delete files. Presence is not ownership.
The scan records current `dumpcap` mode and whether capability and ACL
metadata are present; these observations cannot reconstruct prior values.

## Proposed full removal sequence

1. Choose the exact scope: MEGALODON-owned software versus independently
   installed companion apps; managed evidence and settings versus external
   backups; shared Ollama models versus only MEGALODON selections. Record
   those choices before any deletion.
2. Capture a fresh read-only inventory and verify the local install manifest,
   launchers, user service identity, running work, and each candidate path.
   Stop only verified MEGALODON-owned jobs and the user HUD service.
3. Preview package-manager dependencies for each chosen companion. The
   current installer has no proof that a package was absent before MEGALODON,
   so historical installations cannot be automatically classified as owned.
   Preserve Python and Git. Treat nftables and other host protection as a
   separate host change with its own review and recovery path.
4. Restore only settings with a recorded before-state. The capture permission
   workflow can change `dumpcap` mode, ACL and file capabilities, but did not
   save their previous values. A full uninstaller must not guess an earlier
   ACL or capability set. Review this host setting explicitly before removal.
5. After the selected external dependencies and host settings are resolved,
   remove the verified MEGALODON user service, code, launchers, app-owned data
   and configuration. Refuse changed manifests, symlinks, foreign-owned files,
   or unfamiliar contents; preserve them for review. Deleting ordinary files
   is not a secure erase of storage media or backups.
6. Run the bounded inventory again. Report any remaining known artifacts,
   package presence, unknown custom directories, and host settings as
   remaining work rather than claiming a clean computer.

The existing `megalodon-manage uninstall` removes manifest-verified code and
launchers but intentionally preserves settings and data. The companion
terminal removal commands operate one tool at a time and require an exact
typed confirmation. Neither command implements the proposed full removal.
An applying full uninstaller needs the scope and provenance gates above before
it can be offered safely.
