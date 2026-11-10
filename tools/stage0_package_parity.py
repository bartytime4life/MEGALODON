#!/usr/bin/env python3
"""Compare bounded source/wheel Stage 0 projections, never grant acceptance."""

from __future__ import annotations

import argparse
from hashlib import sha256
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

DENIAL = 'STAGE0_PACKAGE_PARITY_INVALID'
MAX_FILE = 8 * 1024 * 1024
MAX_PACKAGE = 16 * 1024 * 1024
MAX_FILES = 2048
MAX_OUTPUT = 16384
COMMAND_SECONDS = 45
STATUS = {
    'schema': 'megalodon-execution-boundary-v1', 'mode': 'stage0_offline',
    'effectful_entries_denied': True, 'denial_code': 'STAGE0_OFFLINE_EFFECT_DENIED',
    'scope': 'application_entry_fences_not_os_containment', 'acceptance_authority': False,
}


def require(condition):
    if not condition:
        raise ValueError(DENIAL)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(raw):
    return sha256(raw).hexdigest()


def read_bounded(path, limit=MAX_FILE):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        raw = stream.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def package_files(root):
    """Hash the complete package tree, excluding interpreter caches only."""
    require(root.is_dir() and not root.is_symlink())
    result, total, entries = {}, 0, 0
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            entries += 1
            require(entries <= MAX_FILES * 2)
            require(not path.is_symlink())
            if path.is_dir():
                if path.name != '__pycache__':
                    pending.append(path)
            elif path.suffix != '.pyc':
                raw = read_bounded(path)
                total += len(raw)
                result[path.relative_to(root).as_posix()] = digest(raw)
                require(len(result) <= MAX_FILES and total <= MAX_PACKAGE)
    require(bool(result))
    return result, total


def wheel_files(raw):
    result, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        members = archive.infolist()
        require(0 < len(members) <= MAX_FILES * 2)
        require(len({item.filename for item in members}) == len(members))
        require(sum(item.file_size for item in members) <= MAX_PACKAGE * 2)
        for item in members:
            name = PurePosixPath(item.filename)
            require(not name.is_absolute() and '..' not in name.parts and '\\' not in item.filename)
            require(item.filename.rstrip('/') == name.as_posix())
            require(not stat.S_ISLNK(item.external_attr >> 16))
            require(item.file_size <= MAX_FILE)
            if item.filename.startswith('megalodon/') and not item.is_dir():
                relative = item.filename[len('megalodon/'):]
                require('__pycache__' not in name.parts and name.suffix != '.pyc')
                data = archive.read(item)
                require(len(data) == item.file_size)
                total += len(data)
                result[relative] = digest(data)
                require(len(result) <= MAX_FILES and total <= MAX_PACKAGE)
    require(bool(result))
    return result


def command(arguments, directory, timeout=COMMAND_SECONDS, limit=MAX_OUTPUT):
    """Bound both output streams and terminate the disposable process group."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in {'PYTHONPATH', 'PYTHONHOME'} and not key.startswith('GIT_')}
    environment['PYTHONNOUSERSITE'] = '1'
    with subprocess.Popen(arguments, cwd=directory, env=environment, start_new_session=True,
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE) as process:
        output, error, size = bytearray(), bytearray(), 0
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0)
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        size += len(chunk)
                        require(size <= limit)
                        (output if key.fileobj is process.stdout else error).extend(chunk)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
            require(process.returncode == 0 and not error)
        finally:
            # Descendants retaining pipe handles must not outlive the deadline.
            try:
                import signal
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return bytes(output)


def source_identity(checkout, commit, tree):
    require(all(type(value) is str and re.fullmatch('[0-9a-f]{40}', value)
                for value in (commit, tree)))
    def git(*args):
        return command(['git', *args], checkout).decode().strip()
    require(Path(git('rev-parse', '--show-toplevel')).resolve() == checkout)
    require(git('rev-parse', '--verify', 'HEAD') == commit)
    require(git('rev-parse', '--verify', 'HEAD^{tree}') == tree)
    require(not git('status', '--porcelain', '--untracked-files=normal'))
    return {'commit': commit, 'tree': tree, 'working_tree_dirty': False}


# The same stdlib-only program probes fresh source and installed processes.
# Only the source lane inserts the explicitly verified checkout into sys.path.
PROBE = r'''
import contextlib, hashlib, importlib.metadata, io, json, os, pathlib
import runpy, stat, sys, sysconfig, threading
mode, source_arg, wheel_hash, case = sys.argv[1:]
source = pathlib.Path(source_arg).resolve()
assert sys.flags.isolated == 1 and sys.dont_write_bytecode and sys.flags.optimize == 0
assert sys.version_info[:2] >= (3, 11)
assert not pathlib.Path.cwd().resolve().is_relative_to(source)
# -B prevents writes but still permits reads of existing bytecode. Redirect
# project cache lookup to an unused path so excluded caches cannot supply code.
cache = pathlib.Path.cwd() / 'unused-project-bytecode'
assert not cache.exists()
sys.pycache_prefix = str(cache)
if mode == 'source':
    sys.path.insert(0, str(source))
else:
    assert mode == 'installed' and sys.prefix != sys.base_prefix
    assert not any(pathlib.Path(p).resolve().is_relative_to(source) for p in sys.path)
import megalodon
from megalodon import cli
root = pathlib.Path(megalodon.__file__).resolve().parent
version = megalodon.__version__
if mode == 'source':
    assert root == source / 'megalodon'
else:
    prefix = pathlib.Path(sys.prefix).resolve()
    assert root == pathlib.Path(sysconfig.get_path('purelib')).resolve() / 'megalodon'
    assert root.is_relative_to(prefix) and not root.is_relative_to(source)
    distributions = list(importlib.metadata.distributions())
    assert len(distributions) == 1
    dist = importlib.metadata.distribution('megalodon-defense')
    assert distributions[0].metadata['Name'] == 'megalodon-defense'
    assert dist.version == version
    direct = json.loads(dist.read_text('direct_url.json') or '{}')
    assert 'dir_info' not in direct
    assert direct.get('archive_info', {}).get('hashes', {}).get('sha256') == wheel_hash
for name, module in tuple(sys.modules.items()):
    if name == 'megalodon' or name.startswith('megalodon.'):
        location = getattr(module, '__file__', None)
        assert location and pathlib.Path(location).resolve().is_relative_to(root)
if case == 'identity':
    files, total, entries, pending = {}, 0, 0, [root]
    while pending:
        for path in pending.pop().iterdir():
            entries += 1
            assert entries <= 4096
            assert not path.is_symlink()
            if path.is_dir():
                if path.name != '__pycache__':
                    pending.append(path)
            elif path.suffix != '.pyc':
                assert stat.S_ISREG(path.stat().st_mode) and path.stat().st_size <= 8*1024*1024
                with path.open('rb') as stream:
                    raw = stream.read(8*1024*1024 + 1)
                assert len(raw) <= 8*1024*1024
                total += len(raw)
                files[path.relative_to(root).as_posix()] = hashlib.sha256(raw).hexdigest()
                assert len(files) <= 2048 and total <= 16*1024*1024
    assert files
    result = {'version': version, 'file_count': len(files), 'size_bytes': total,
              'runtime': {'python': list(sys.version_info[:3]),
                  'implementation': sys.implementation.name, 'isolated': True,
                  'bytecode_writes_disabled': True},
              'file_map_sha256': hashlib.sha256(json.dumps(files, sort_keys=True,
                  separators=(',', ':')).encode()).hexdigest()}
else:
    assert case in ('status', 'denial')
    # Imports and byte inspection above are trusted setup, outside this guard.
    def forbidden(*args, **kwargs):
        raise RuntimeError('EXCLUDED_EFFECT')
    threading.Thread.start = forbidden
    def guard(event, args):
        if (event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn', 'sqlite3.connect'))
                or event in ('os.system', 'os.fork', 'os.forkpty', 'os.posix_spawn',
                    'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.chmod',
                    'os.chown', 'os.link', 'os.symlink', 'os.truncate', 'os.utime')):
            forbidden()
        if event == 'open' and args[2] & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):
            forbidden()
    sys.addaudithook(guard)
    sys.argv = ['megalodon', '--stage0-offline', 'stage0-status' if case == 'status' else '--help']
    budget = [0]
    class Capture(io.StringIO):
        def write(self, value):
            budget[0] += len(value.encode('utf-8'))
            if budget[0] > 8192:
                raise RuntimeError('PROBE_OUTPUT_LIMIT')
            return super().write(value)
    with contextlib.redirect_stdout(Capture()) as out, contextlib.redirect_stderr(Capture()) as err:
        try:
            runpy.run_module('megalodon', run_name='__main__')
        except SystemExit as exit_result:
            code = exit_result.code
        else:
            code = 0
    result = {'exit_code': code, 'stdout': out.getvalue(), 'stderr': err.getvalue()}
print(json.dumps(result, sort_keys=True, separators=(',', ':')))
'''


def probe(python, mode, checkout, wheel_hash, case, directory):
    raw = command([str(python), '-I', '-B', '-c', PROBE,
                   mode, str(checkout), wheel_hash, case], directory)
    return json.loads(raw), digest(raw)


def collect(checkout, commit, tree, wheel, installed_python):
    require(sys.platform == 'linux' and os.geteuid() != 0 and not sys.flags.optimize)
    checkout = checkout.resolve(strict=True)
    wheel = wheel.resolve(strict=True)
    require(re.fullmatch(r'megalodon_defense-[A-Za-z0-9_.+-]+\.whl', wheel.name))
    source = source_identity(checkout, commit, tree)
    files, package_size = package_files(checkout / 'megalodon')
    tracked = command(['git', 'ls-files', '-z', '--', 'megalodon'], checkout,
                      limit=MAX_OUTPUT * 8).decode().split('\0')
    require(tracked[-1] == '' and len(tracked[:-1]) == len(files))
    require(set(tracked[:-1]) == {'megalodon/' + name for name in files})
    raw = read_bounded(wheel, MAX_PACKAGE)
    wheel_hash = digest(raw)
    require(wheel_files(raw) == files)
    hashes = {}
    identity = None
    expected_status = {'exit_code': 0, 'stdout': None, 'stderr': ''}
    expected_denial = {'exit_code': 2, 'stdout': '', 'stderr': STATUS['denial_code'] + '\n'}
    with tempfile.TemporaryDirectory(prefix='megalodon-stage0-parity-') as temporary:
        directory = Path(temporary).resolve()
        require(not directory.is_relative_to(checkout))
        for mode, python in (('source', sys.executable), ('installed', installed_python)):
            hashes[mode] = {}
            observed, hashes[mode]['identity'] = probe(python, mode, checkout, wheel_hash, 'identity', directory)
            require(type(observed) is dict and set(observed) == {
                'version', 'file_count', 'size_bytes', 'file_map_sha256', 'runtime'})
            require(type(observed['version']) is str and 0 < len(observed['version']) <= 64)
            require(type(observed['file_count']) is int and observed['file_count'] == len(files))
            require(type(observed['size_bytes']) is int and observed['size_bytes'] == package_size)
            require(observed['file_map_sha256'] == digest(canonical(files)))
            require(canonical(observed['runtime']) == canonical({
                'python': list(sys.version_info[:3]), 'implementation': sys.implementation.name,
                'isolated': True, 'bytecode_writes_disabled': True}))
            if identity is None:
                identity = observed
            require(observed == identity)
            status, hashes[mode]['status'] = probe(python, mode, checkout, wheel_hash, 'status', directory)
            require(type(status) is dict and set(status) == set(expected_status))
            require(type(status['exit_code']) is int and status['exit_code'] == 0 and status['stderr'] == '')
            require(canonical(json.loads(status['stdout'])) == canonical(STATUS))
            if expected_status['stdout'] is None:
                expected_status['stdout'] = status['stdout']
            require(status == expected_status)
            denial, hashes[mode]['denial'] = probe(python, mode, checkout, wheel_hash, 'denial', directory)
            require(type(denial) is dict and type(denial.get('exit_code')) is int
                    and denial == expected_denial)
    require(package_files(checkout / 'megalodon') == (files, package_size))
    require(digest(read_bounded(wheel, MAX_PACKAGE)) == wheel_hash)
    require(source_identity(checkout, commit, tree) == source)
    return {
        'schema': 'megalodon-stage0-package-projection-parity-v1',
        'status': 'scoped_projection_parity', 'evidence_level': 'synthetic',
        'source': source,
        'package': {'distribution': 'megalodon-defense', **{
            key: value for key, value in identity.items() if key != 'runtime'}},
        'runtime': identity['runtime'],
        'wheel': {'filename': wheel.name, 'sha256': wheel_hash, 'size_bytes': len(raw)},
        'comparison': {'package_files': 'source_wheel_installed_equal',
                       'stage0_status': 'equal', 'stage0_help_denial': 'equal'},
        'stage0_status': STATUS.copy(), 'denied_exit_code': 2,
        'probe_sha256': hashes,
        'installed_origin': 'isolated_venv_local_wheel_outside_checkout',
        'invocation_guard': 'python_audit_hook_and_thread_start_guard_after_trusted_imports',
        'tripwire_counts': None, 'tripwire_measurement': 'not_aggregated',
        'full_stage0_suite_package_parity': 'NOT_RUN',
        'native_lanes': {name: 'NOT_RUN' for name in ('tshark', 'zeek', 'suricata', 'qwen')},
        'independent_review': 'NOT_RECORDED', 'owner_acceptance': 'NOT_RECORDED',
        'authority': {name: False for name in ('release', 'deployment', 'installation',
                      'model_execution', 'detector', 'response', 'host_control')},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--tree', required=True)
    parser.add_argument('--wheel', required=True, type=Path)
    parser.add_argument('--installed-python', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        value = collect(args.checkout, args.commit, args.tree, args.wheel, args.installed_python)
    except (OSError, ValueError, TypeError, KeyError, RecursionError,
            zipfile.BadZipFile, subprocess.SubprocessError):
        print(DENIAL, file=sys.stderr)
        return 2
    print(canonical(value).decode())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
