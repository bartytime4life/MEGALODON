"""Explicit installation of an isolated, hash-pinned optional analyzer runtime.

No pip resolver, system package replacement, desktop launcher or user plugin is
used. Downloaded dependency archives are distinct from user-selected samples.
"""
from __future__ import annotations

import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from .local_install import _owned_directory, _validate_directory_chain, InstallError
from .file_inspection_sandbox import supported

CATALOG = Path(__file__).parent / 'assets/file-inspection-runtime.json'
MAX_TREE = 160 * 1024 * 1024


def catalog():
    value = json.loads(CATALOG.read_text())
    if value['schema'] != 'megalodon-file-inspection-runtime-v1':
        raise ValueError('Unsupported inspector runtime catalog.')
    return value


def runtime_path(home=None):
    tag = f'cp{sys.version_info.major}{sys.version_info.minor}'
    return Path(home or Path.home()) / '.local/share/megalodon/support/file-inspector' / ('v1-' + tag)


def tree_digest(root):
    """Pin exact file bytes, names and modes, rejecting any added code or links."""
    _validate_directory_chain(root)
    records, total = [], 0
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        if (info.st_uid != os.geteuid() or stat.S_ISLNK(info.st_mode)
                or info.st_mode & 0o077):
            raise ValueError('Inspector runtime is unsafe or modified.')
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 40 * 1024 * 1024:
            raise ValueError('Inspector runtime is unsafe or modified.')
        total += info.st_size
        if total > MAX_TREE or len(records) >= 4000:
            raise ValueError('Inspector runtime exceeds its bound.')
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        records.append([path.relative_to(root).as_posix(), stat.S_IMODE(info.st_mode), info.st_size, digest])
    return hashlib.sha256(json.dumps(records, separators=(',', ':')).encode()).hexdigest()


def validate(home=None):
    if not supported():
        raise ValueError('Use non-root Linux x86-64 with Python 3.11 or 3.12.')
    root = runtime_path(home)
    if not root.is_dir():
        raise ValueError('Install the optional file inspector before inspecting a file.')
    expected = catalog()['trees'][f'cp{sys.version_info.major}{sys.version_info.minor}']
    if tree_digest(root) != expected:
        raise ValueError('Inspector files changed or are incomplete. Preserve them and review the installation.')
    return root


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        from urllib.parse import urlsplit
        url = urlsplit(newurl)
        if (url.scheme != 'https' or url.username or url.password
                or url.hostname not in {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}):
            raise ValueError('Inspector download redirected outside its publisher.')
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def download(item, destination):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _Redirect())
    request = urllib.request.Request(item['url'], headers={'Accept-Encoding': 'identity', 'User-Agent': 'MEGALODON-file-inspector/1'})
    digest, total, deadline = hashlib.sha256(), 0, time.monotonic() + 120
    with opener.open(request, timeout=15) as response, destination.open('xb') as output:
        os.chmod(destination, 0o600)
        if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise ValueError('Inspector download unavailable.')
        while True:
            if time.monotonic() >= deadline:
                raise ValueError('Inspector download deadline exceeded.')
            part = response.read(65536)
            if not part:
                break
            total += len(part)
            if total > item['size']:
                raise ValueError('Inspector download exceeded its bound.')
            digest.update(part)
            output.write(part)
    if total != item['size'] or digest.hexdigest() != item['sha256']:
        raise ValueError('Inspector download did not match the reviewed artifact.')


def _save(root, relative, value, executable=False):
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('Invalid inspector artifact path.')
    destination = root / str(path)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # mkdir parents uses the process umask; enforce privacy on every component.
    for parent in destination.relative_to(root).parents:
        (root / parent).chmod(0o700)
    with destination.open('xb') as output:
        output.write(value)
    destination.chmod(0o500 if executable else 0o400)


def assemble(artifacts, root, tag):
    """Extract only the closed regular-file subset; never run package scripts."""
    for name in ('die', 'qtcore', 'qtscript', 'icu'):
        path = artifacts[name]
        # dpkg only decompresses the reviewed archive; no install or maintainer
        # scripts are invoked. Fixed source sizes bound this trusted input.
        result = subprocess.run(['/usr/bin/dpkg-deb', '--fsys-tarfile', str(path)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=30, check=True, env={'PATH': '/usr/bin', 'LC_ALL': 'C'})
        if len(result.stdout) > MAX_TREE:
            raise ValueError('Inspector archive exceeds its bound.')
        with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
            for member in archive:
                source = member.name.removeprefix('./')
                target = None
                if name == 'die':
                    if source == 'usr/bin/diec':
                        target = 'die/diec'
                    elif source.startswith('usr/lib/die/db/'):
                        target = 'die/db/' + source.removeprefix('usr/lib/die/db/')
                elif source == {
                        'qtcore': 'usr/lib/x86_64-linux-gnu/libQt5Core.so.5.15.13',
                        'qtscript': 'usr/lib/x86_64-linux-gnu/libQt5Script.so.5.15.13',
                        'icu': ''}[name]:
                    target = 'lib/' + ('libQt5Core.so.5' if name == 'qtcore' else 'libQt5Script.so.5')
                elif name == 'icu' and source in {
                        'usr/lib/x86_64-linux-gnu/libicudata.so.74.2',
                        'usr/lib/x86_64-linux-gnu/libicuuc.so.74.2',
                        'usr/lib/x86_64-linux-gnu/libicui18n.so.74.2'}:
                    target = 'lib/' + source.rsplit('/', 1)[1].removesuffix('.2')
                if source.endswith('/copyright') and source.startswith('usr/share/doc/'):
                    target = 'licenses/' + name + '-' + source.split('/')[3] + '-copyright'
                if target is None or member.isdir():
                    continue
                if not member.isfile() or not 0 <= member.size <= 40 * 1024 * 1024:
                    raise ValueError('Unexpected inspector archive entry.')
                value = archive.extractfile(member).read()
                _save(root, target, value, executable=target == 'die/diec')
    with zipfile.ZipFile(artifacts[tag]) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            if not (member.filename.startswith('lief/') or '.dist-info/licenses/' in member.filename):
                continue
            if member.file_size > 40 * 1024 * 1024 or stat.S_ISLNK(member.external_attr >> 16):
                raise ValueError('Unexpected inspector wheel entry.')
            _save(root, 'python/' + member.filename, archive.read(member))
    for name in ('die/db', 'lib', 'python'):
        if not (root / name).is_dir():
            raise ValueError('Inspector archive is incomplete.')


def install(home=None, *, acquire=download):
    if not supported():
        raise ValueError('File inspector installation requires non-root Linux x86-64 and Python 3.11 or 3.12.')
    # Prerequisites are never installed or enabled implicitly. Existing Setup
    # explains fixed OS packages; no downgrade or unrestricted fallback exists.
    if not all(Path(p).is_file() for p in ('/usr/bin/bwrap', '/usr/bin/dpkg-deb', '/usr/bin/systemd-run')):
        raise ValueError('Install bubblewrap, dpkg and systemd first, using your operating system package manager.')
    root = runtime_path(home)
    _owned_directory(root.parent, private=True)
    lock_path = root.parent / 'install.lock'
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Inspector installation lock is unsafe.')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.path.lexists(root):
            validate(home)
            return
        tag = f'cp{sys.version_info.major}{sys.version_info.minor}'
        definition = catalog()
        with tempfile.TemporaryDirectory(prefix='.prepare-', dir=root.parent) as temporary:
            stage = Path(temporary) / 'runtime'
            stage.mkdir(mode=0o700)
            artifacts = {}
            for name in ('die', 'qtcore', 'qtscript', 'icu', tag):
                item = definition['artifacts'][name]
                path = Path(temporary) / name
                acquire(item, path)
                # Also verify injected/offline downloaders; acquisition alone
                # never grants the artifact parser authority.
                if path.stat().st_size != item['size'] or hashlib.sha256(path.read_bytes()).hexdigest() != item['sha256']:
                    raise ValueError('Inspector artifact identity mismatch.')
                artifacts[name] = path
            assemble(artifacts, stage, tag)
            if tree_digest(stage) != definition['trees'][tag]:
                raise ValueError('Inspector runtime did not match the reviewed file set.')
            os.rename(stage, root)
    finally:
        os.close(fd)


def main():
    try:
        install()
    except (OSError, ValueError, InstallError, subprocess.SubprocessError):
        print('File inspector installation did not complete. Check prerequisites, artifact availability and the private runtime. No system libraries were replaced.')
        return 1
    print('Optional file inspector installed. Check inspector in the local HUD before inspecting a file.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
