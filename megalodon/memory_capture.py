"""Process memory: find code that lives only in memory, and save it before the process is gone.

Fileless tools leave nothing on disk to scan. They load an ELF image straight
into anonymous memory, map code from a memfd or from a file they then delete,
or inject into a process that is already running (ATT&CK T1620, T1055,
T1070.004). When the process ends, or is suspended and killed, that code is
lost. `megalodon memory` finds it and saves it:

* `inspect PID` lists a process's memory regions and flags the suspicious ones;
* `sweep` does the same for every process and reports what it finds;
* `capture PID` saves the suspicious regions (or, with --all, every readable
  region) into a sealed evidence bundle that `megalodon evidence verify` checks.

Memory is read through /proc/<pid>/mem, which does not stop or change the
process. A capture can hold passwords and keys the process had in memory: the
bundle is readable only by its owner. Root is needed for other users'
processes.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re

from . import evidence
from .process_network import TEMPORARY

SCHEMA = evidence.SCHEMA
REPORT_SCHEMA = 'megalodon-memory-report-v1'
DEFAULT_ROOT = evidence.DEFAULT_ROOT
MAX_REGIONS = 65536
MAX_CAPTURE = 256 * 1024 * 1024
MAX_REGION = 64 * 1024 * 1024
MAX_PROBES = 4096
CHUNK = 1 << 20
RANK = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
_MAP = re.compile(r'([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) ([0-9a-f]+:[0-9a-f]+) (\d+)\s*(.*)')
# Kernel-provided regions, never anything a program loaded.
KERNEL = ('[vdso]', '[vsyscall]', '[vvar]', '[vvar_vclock]', '[uprobes]')
SYSTEM_DIRS = ('/usr/', '/lib/', '/lib64/', '/lib32/', '/bin/', '/sbin/', '/opt/', '/snap/')

RULES = {
    'MEMORY_ELF_IN_ANONYMOUS': ('CRITICAL', ['T1620'], 'An ELF program image sits in executable anonymous memory: '
                                                       'code loaded without a file, as reflective loaders and '
                                                       'injected implants do.'),
    'MEMORY_EXECUTABLE_MEMFD': ('HIGH', ['T1620'], 'Code runs from a memory-only file (memfd), which leaves nothing '
                                                   'on disk.'),
    'MEMORY_EXECUTABLE_TEMPORARY': ('HIGH', ['T1055', 'T1574.006'], 'A process runs code mapped from a temporary '
                                                                    'folder, where dropped libraries are put.'),
    'MEMORY_EXECUTABLE_DELETED': ('MEDIUM', ['T1070.004'], 'A process runs code from a file outside the system '
                                                           'folders that was deleted after it was loaded.'),
}


class MemoryCaptureError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc)


def _open_process(pid, root):
    """A handle on /proc/<pid> that stays bound to this one process: reads through it fail, rather than reach a new
    process, once this one has exited and its PID is reused."""
    try:
        return os.open(Path(root, 'proc', str(pid)), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        raise MemoryCaptureError(f'process {pid} does not exist') from None
    except OSError as exc:
        raise MemoryCaptureError(f'process {pid} cannot be opened: {exc.strerror}') from None


def _read_at(handle, name, limit=65536):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=handle)
    except OSError:
        return None
    try:
        data, chunk = b'', b'x'
        while chunk and len(data) < limit:
            chunk = os.read(fd, min(1 << 20, limit - len(data)))
            data += chunk
        return data.decode('utf-8', 'replace')
    except OSError:
        return None
    finally:
        os.close(fd)


def _start_at(handle):
    text = _read_at(handle, 'stat', 4096) or ''
    try:
        return int(text[text.rindex(')') + 2:].split()[19])
    except (ValueError, IndexError):
        return None


def regions(pid, root='/', handle=None):
    """[{start, end, perms, offset, inode, path}] from /proc/<pid>/maps."""
    own = handle is None
    handle = _open_process(pid, root) if own else handle
    try:
        text = _read_at(handle, 'maps', 64 * 1024 * 1024)
    finally:
        if own:
            os.close(handle)
    if text is None:
        raise MemoryCaptureError(f'the memory map of process {pid} cannot be read; run as root')
    lines = text.splitlines()
    out = []
    for line in lines[:MAX_REGIONS]:
        match = _MAP.match(line)
        if match:
            out.append(dict(start=int(match[1], 16), end=int(match[2], 16), perms=match[3], offset=int(match[4], 16),
                            inode=int(match[6]), path=match[7].strip()))
    return out


def _anonymous(region):
    """Memory no file backs: private anonymous maps, the heap and stack, and shared anonymous memory (which the
    kernel shows as /dev/zero (deleted) or a SysV segment)."""
    path = region['path']
    if path.startswith('/dev/zero') or path.startswith('/SYSV'):
        return True
    return region['inode'] == 0 and (path == '' or path in ('[heap]', '[stack]') or path.startswith('[anon'))


def _probe(memory, region):
    """The first four bytes of a region, or None when they cannot be read."""
    if memory is None:
        return None
    try:
        return os.pread(memory, 4, region['start'])
    except (OSError, OverflowError):
        return None


def flags(region, head=None):
    """The reasons a region is suspicious (empty for ordinary ones)."""
    out, path, perms = [], region['path'], region['perms']
    if path in KERNEL or 'x' not in perms:
        return out
    if _anonymous(region):
        out.append('anonymous_executable')
        if head == b'\x7fELF':
            out.append('elf_in_anonymous')
    if 'w' in perms:
        out.append('writable_executable')
    if path.startswith('/memfd:'):
        out.append('memfd')
    elif path.endswith(' (deleted)') and not _anonymous(region):
        out.append('deleted')
    if path.startswith(TEMPORARY):
        out.append('temporary')
    return out


def _process(pid, handle):
    try:
        exe = os.readlink('exe', dir_fd=handle)
    except OSError:
        exe = None
    return dict(pid=pid, start=_start_at(handle), program=exe)


def _open_memory(handle):
    try:
        return os.open('mem', os.O_RDONLY | os.O_CLOEXEC, dir_fd=handle)
    except OSError:
        return None


def inspect(pid, root='/'):
    """Every executable region of a process, flagged, with findings for the suspicious ones."""
    handle = _open_process(pid, root)
    try:
        process = _process(pid, handle)
        found = regions(pid, root, handle)
        memory = _open_memory(handle)
    finally:
        os.close(handle)
    gaps = [] if memory is not None else [f'the memory of process {pid} cannot be read; ELF images were not looked for'
                                          + ('; run as root' if os.geteuid() else '')]
    shown, findings, probes, unread, skipped = [], [], 0, 0, 0
    try:
        for region in found:
            head = None
            if _anonymous(region) and 'x' in region['perms'] and memory is not None:
                if probes >= MAX_PROBES:
                    skipped += 1
                else:
                    head, probes = _probe(memory, region), probes + 1
                    unread += head is None or len(head) < 4
            why = flags(region, head)
            if not why:
                continue
            shown.append(dict(address=f"{region['start']:x}-{region['end']:x}", perms=region['perms'],
                              size=region['end'] - region['start'], path=region['path'], flags=why))
            findings += _judge(process, region, why)
    finally:
        if memory is not None:
            os.close(memory)
    if unread:
        gaps.append(f'{unread} executable regions of process {pid} could not be read; they were not looked at for '
                    'ELF images')
    if skipped:
        gaps.append(f'process {pid} has more than {MAX_PROBES} executable anonymous regions; {skipped} were not looked '
                    'at for ELF images')
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return dict(schema=REPORT_SCHEMA, action='inspect', process=process, regions=shown, findings=findings, gaps=gaps)


def _judge(process, region, why):
    where = f"{region['start']:x}-{region['end']:x} {region['perms']}"
    path = region['path'].removesuffix(' (deleted)')
    out = []

    def add(rule, detail):
        severity, techniques, summary = RULES[rule]
        out.append(dict(rule_id=rule, severity=severity, techniques=techniques,
                        subject=f"memory:{process['pid']}:{region['start']:x}", detail=detail, summary=summary,
                        region=where, evidence=dict(processes=[dict(pid=process['pid'], start=process['start'],
                                                                    program=process['program'])])))
    who = f"{process['program']} (pid {process['pid']})"
    if 'elf_in_anonymous' in why:
        add('MEMORY_ELF_IN_ANONYMOUS', f'{who} has an ELF image in executable anonymous memory at {where}')
    elif 'memfd' in why:
        add('MEMORY_EXECUTABLE_MEMFD', f'{who} runs code from {path} at {where}')
    elif 'temporary' in why:
        add('MEMORY_EXECUTABLE_TEMPORARY', f'{who} runs code mapped from {path} at {where}')
    elif 'deleted' in why and not path.startswith(SYSTEM_DIRS):
        # Libraries under the system folders are replaced by updates while programs run; those are left out.
        add('MEMORY_EXECUTABLE_DELETED', f'{who} runs code from the deleted file {path} at {where}')
    return out


def sweep(root='/'):
    """Inspect every process; findings for the suspicious regions."""
    findings, gaps, unreadable, seen = [], [], 0, 0
    try:
        pids = sorted(int(p.name) for p in Path(root, 'proc').iterdir() if p.name.isdigit())
    except OSError:
        raise MemoryCaptureError('/proc cannot be listed') from None
    for pid in pids:
        if pid == os.getpid():
            continue
        try:
            report = inspect(pid, root)
        except MemoryCaptureError:
            unreadable += 1
            continue
        seen += 1
        findings += report['findings']
        unreadable += bool(report['gaps'])
    if unreadable:
        gaps.append(f'{unreadable} processes could not be read in full' + ('; run as root' if os.geteuid() else ''))
    findings.sort(key=lambda f: (RANK.index(f['severity']), f['subject']))
    return dict(schema=REPORT_SCHEMA, action='sweep', checked_at=_now().strftime('%Y-%m-%dT%H:%M:%SZ'),
                processes=seen, findings=findings, gaps=gaps,
                note='`megalodon memory capture PID` saves a flagged process\'s memory before it is gone.')


def capture(pid, *, start=None, output=None, everything=False, command_line=False, root='/', limit=MAX_CAPTURE,
            now=None):
    """Save a process's suspicious (or, with everything, all readable) memory regions into a sealed bundle."""
    handle = _open_process(pid, root)
    memory = None
    try:
        process = _process(pid, handle)
        if process['start'] is None:
            raise MemoryCaptureError(f'process {pid} does not exist')
        if start is not None and process['start'] != start:
            raise MemoryCaptureError(f'process {pid} started at {process["start"]}, not {start}: it is a different '
                                     'process')
        found = regions(pid, root, handle)
        memory = _open_memory(handle)
        if memory is None:
            raise MemoryCaptureError(f'the memory of process {pid} cannot be read'
                                     + ('; run as root' if os.geteuid() else ''))
        # Checked again with the memory open: the handle cannot have moved to another process, but the process
        # could have exited, and then nothing below would be its memory.
        if _start_at(handle) != process['start']:
            raise MemoryCaptureError(f'process {pid} exited while its memory was being opened')
        status = _read_at(handle, 'status') or ''
        maps = _read_at(handle, 'maps', 64 * 1024 * 1024) or ''
        cmdline = _read_at(handle, 'cmdline', evidence.MAX_CMDLINE) or ''
    except BaseException:
        if memory is not None:
            os.close(memory)
        raise
    finally:
        os.close(handle)
    now = now or _now()
    base = (Path(output).expanduser() if output else
            Path(DEFAULT_ROOT).expanduser() / f"memory-{pid}-{now.strftime('%Y%m%dT%H%M%SZ')}")
    if base.exists():
        os.close(memory)
        raise MemoryCaptureError(f'{base} already exists; evidence bundles are never overwritten')
    base.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.mkdir(mode=0o700)
    (base / 'regions').mkdir(mode=0o700)
    saved, gaps, total = [], [], 0
    try:
        for region in found:
            head = _probe(memory, region) if _anonymous(region) and 'x' in region['perms'] else None
            why = flags(region, head)
            # Flagged regions are tried even without the read bit: /proc/<pid>/mem reads execute-only memory too.
            if region['path'] in KERNEL or not (why or (everything and 'r' in region['perms'])):
                continue
            size = region['end'] - region['start']
            if size > MAX_REGION or total + size > limit:
                gaps.append(f"region {region['start']:x}-{region['end']:x} ({size} bytes) was left out: over the "
                            f"{'region' if size > MAX_REGION else 'capture'} limit")
                continue
            name = f"regions/{region['start']:016x}-{region['end']:016x}.bin"
            digest, written = hashlib.sha256(), 0
            fd = os.open(base / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                offset = region['start']
                while offset < region['end']:
                    try:
                        chunk = os.pread(memory, min(CHUNK, region['end'] - offset), offset)
                    except OSError:
                        break
                    if not chunk:
                        break
                    os.write(fd, chunk)
                    digest.update(chunk)
                    written += len(chunk)
                    offset += len(chunk)
            finally:
                os.close(fd)
            total += written
            if not written:
                os.unlink(base / name)
                gaps.append(f"region {region['start']:x}-{region['end']:x} could not be read")
                continue
            saved.append(dict(file=name, address=f"{region['start']:x}-{region['end']:x}", perms=region['perms'],
                              path=region['path'], flags=why, size=size, read=written, sha256=digest.hexdigest()))
            if written < size:
                gaps.append(f"region {region['start']:x}-{region['end']:x} could be read only in part "
                            f"({written} of {size} bytes)")
    finally:
        os.close(memory)
    (base / 'maps.txt').write_text(maps)
    (base / 'status.txt').write_text(status)
    os.chmod(base / 'maps.txt', 0o600)
    os.chmod(base / 'status.txt', 0o600)
    info = dict(process, regions_saved=len(saved), bytes_saved=total)
    if command_line:
        info['command_line'] = cmdline.replace('\0', ' ').strip()
    evidence._write(base, 'process.json', info)
    evidence._write(base, 'regions.json', saved)
    listed = [dict(file=str(p.relative_to(base)), size=p.stat().st_size, sha256=evidence._file_digest(p))
              for p in sorted(p for p in base.rglob('*') if p.is_file())]
    manifest = dict(schema=SCHEMA, kind='memory', collected_at=evidence._iso(now), finished_at=evidence._iso(_now()),
                    host=evidence.host_info(root), options=dict(everything=everything, command_line=command_line,
                                                                limit=limit),
                    counts=dict(regions=len(saved), bytes=total), gaps=gaps, files=listed,
                    note='Process memory, read-only: the process was not stopped or changed. It may hold passwords '
                         'and keys. Keep manifest_sha256 off the machine.')
    evidence._write(base, 'manifest.json', manifest)
    digest = evidence._file_digest(base / 'manifest.json')
    evidence._seal(base)
    return dict(schema=REPORT_SCHEMA, action='capture', bundle=str(base), manifest_sha256=digest, process=process,
                regions=len(saved), bytes=total, gaps=gaps,
                note='Keep manifest_sha256 off this machine; `megalodon evidence verify` checks the bundle.')
