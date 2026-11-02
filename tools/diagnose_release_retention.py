#!/usr/bin/env python3
"""Read-only explanation of Linux process holds on manifest-listed MEGALODON releases."""
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.local_install import _current_target, _load_manifest, install_paths


def report(paths, manifest, proc=Path('/proc')):
    releases = Path(os.path.normpath(paths.releases))
    selected = _current_target(paths)
    protected = {manifest['active_release'], manifest['previous_release']}
    if selected is not None and Path(os.path.normpath(selected)).parent == releases:
        protected.add(Path(os.path.normpath(selected)).name)
    protected.update(row['id'] for row in manifest['releases'][-4:])
    ids = [row['id'] for row in manifest['releases']]
    candidates = [i for i in ids if i not in protected and (paths.releases/i).exists()]
    names = {i: os.fsencode(releases/i) for i in candidates}
    held = set()
    unknown = False
    print(f'Installed copies: {len(ids)}. Protected by policy: {sum(i in protected for i in ids)}. Older copies on disk: {len(candidates)}.')
    for pid in sorted((p for p in proc.iterdir() if p.name.isdecimal()), key=lambda p:int(p.name)):
        step = 'process owner'
        try:
            if pid.stat().st_uid != os.getuid():
                continue
            step = 'command line'
            command = (pid/'cmdline').read_bytes()
            step = 'open files'
            fds = []
            for fd in (pid/'fd').iterdir():
                try:
                    fds.append(str(fd.readlink()))
                except FileNotFoundError:
                    continue
            marker = any(f.startswith(str(releases)+'/') and f.endswith('/megalodon') for f in fds)
            links = list(fds)
            for field in ('cwd', 'exe'):
                step = field
                try:
                    links.append(str((pid/field).readlink()))
                except FileNotFoundError:
                    continue
            alias = os.fsencode(paths.current) in command and not marker
            matched = {i for i, name in names.items()
                       if name in command or os.fsencode(paths.releases/i) in command
                       or any(f == str(releases/i) or f.startswith(str(releases/i)+'/') for f in links)}
            if alias:
                reason = 'mentions the current launcher but has no release marker'
                unknown = True
            else:
                step = 'memory maps'
                maps = (pid/'maps').read_bytes()
                matched.update(i for i, name in names.items() if name in maps)
                if not matched:
                    continue
                held.update(matched)
                reason = f'references {len(matched)} older release(s)'
        except FileNotFoundError:
            continue
        except OSError as exc:
            unknown = True
            reason = f'could not inspect {step} (errno {exc.errno}); release use unknown'
        try:
            with (pid/'comm').open('rb') as f:
                name = re.sub(r'[^A-Za-z0-9._+ -]', '?', f.read(64).decode('ascii','replace').strip())[:32]
        except OSError:
            name = 'unknown'
        print(f'PID {pid.name} [{name}]: {reason}')
    if unknown:
        print('At least one process could not be tied to a specific release.')
    elif held:
        print(f'Observed direct references to {len(held)} older release(s).')
    else:
        print('No process hold was observed among processes visible in this snapshot.')
    print('Read-only check complete.')


def main():
    paths = install_paths()
    manifest = _load_manifest(paths)
    if manifest is None:
        print('No managed installation found for this user.')
        return
    report(paths, manifest)


if __name__ == '__main__':
    main()
