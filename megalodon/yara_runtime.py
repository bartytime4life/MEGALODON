"""Explicit installation of the optional, hash-pinned YARA runtime for file inspection.

A sibling of the LIEF / Detect It Easy runtime with its own catalog and tree
pins, so neither changes the other. Only the yara-python extension, its bundled
crypto library and the license are extracted from the reviewed wheel; no pip
resolver, build step or package script runs, and nothing on the host imports it.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import zipfile

from .local_install import _owned_directory, InstallError
from .file_inspection_runtime import _save, download, tree_digest
from .file_inspection_sandbox import supported

CATALOG = Path(__file__).parent / 'assets/yara-runtime.json'


def catalog():
    value = json.loads(CATALOG.read_text())
    if value['schema'] != 'megalodon-yara-runtime-v1':
        raise ValueError('Unsupported YARA runtime catalog.')
    return value


def _tag():
    return f'cp{sys.version_info.major}{sys.version_info.minor}'


def runtime_path(home=None):
    return Path(home or Path.home()) / '.local/share/megalodon/support/file-inspector' / ('yara-v1-' + _tag())


def validate(home=None):
    if not supported():
        raise ValueError('Use non-root Linux x86-64 with Python 3.11 or 3.12.')
    root = runtime_path(home)
    if not root.is_dir():
        raise ValueError('Install the optional YARA runtime before applying rules.')
    if tree_digest(root) != catalog()['trees'][_tag()]:
        raise ValueError('YARA runtime files changed or are incomplete. Preserve them and review the installation.')
    return root


def assemble(wheel, root, tag):
    """Extract the closed file set: the extension module, its libraries and the license."""
    module = f'yara.cpython-{tag[2:]}-x86_64-linux-gnu.so'
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            name = member.filename
            if member.is_dir():
                continue
            if not (name == module or (name.startswith('yara_python.libs/') and '.so' in name)
                    or (name.startswith('yara_python-') and name.endswith('.dist-info/licenses/LICENSE'))):
                continue
            if member.file_size > 40 * 1024 * 1024 or stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError('Unexpected YARA wheel entry.')
            _save(root, 'python/' + name, archive.read(member))
    if not (root / 'python' / module).is_file() or not (root / 'python/yara_python.libs').is_dir():
        raise ValueError('YARA wheel is incomplete.')


def install(home=None, *, acquire=download):
    if not supported():
        raise ValueError('YARA runtime installation requires non-root Linux x86-64 and Python 3.11 or 3.12.')
    root = runtime_path(home)
    _owned_directory(root.parent, private=True)
    fd = os.open(root.parent / 'yara-install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('YARA installation lock is unsafe.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.path.lexists(root):
            validate(home)
            return
        tag, definition = _tag(), catalog()
        item = definition['artifacts'][tag]
        with tempfile.TemporaryDirectory(prefix='.prepare-yara-', dir=root.parent) as temporary:
            stage = Path(temporary) / 'runtime'
            stage.mkdir(mode=0o700)
            wheel = Path(temporary) / 'wheel'
            acquire(item, wheel)
            # Verify injected/offline downloaders too before parsing the archive.
            if wheel.stat().st_size != item['size'] or hashlib.sha256(wheel.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('YARA artifact identity mismatch.')
            assemble(wheel, stage, tag)
            if tree_digest(stage) != definition['trees'][tag]:
                raise ValueError('YARA runtime did not match the reviewed file set.')
            os.rename(stage, root)
    finally:
        os.close(fd)


def main():
    try:
        install()
    except (OSError, ValueError, InstallError, subprocess.SubprocessError):
        print('YARA runtime installation did not complete. Check prerequisites, artifact availability and the private runtime.')
        return 1
    print('Optional YARA runtime installed. Put rules in ~/.config/megalodon/yara-rules and run megalodon yara check.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
