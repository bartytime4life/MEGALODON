"""Disposable, non-root Linux lock acceptance; never opens an operator database.

The caller provides only the expected descriptor-filesystem shape. Container
mounts establish that shape; this probe does not emulate filesystem calls or
change permissions outside its private temporary fixture. Network setup is
separate from execution. --expect-lock-loss is a bounded baseline negative
control, using competing fcntl probes rather than writes to a damaged fixture.
"""
from __future__ import annotations

import argparse
import errno
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon import storage

LOCK_PROBE = r"""
import errno, fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    try:
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, int(sys.argv[3]), int(sys.argv[2]))
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.EAGAIN):
            raise
        print('held')
    else:
        print('released')
finally:
    os.close(fd)
"""
SQLITE_PROBE = r"""
import sqlite3, sys
c = sqlite3.connect(sys.argv[1], timeout=0)
try:
    assert c.execute('SELECT group_concat(v) FROM probe').fetchone() == ('1',)
    try:
        c.execute('BEGIN IMMEDIATE')
    except sqlite3.OperationalError as exc:
        assert exc.sqlite_errorcode == sqlite3.SQLITE_BUSY
        print('busy')
    else:
        c.rollback()
        print('admitted')
finally:
    c.close()
"""


def child(source: str, *args: object) -> str:
    return subprocess.run(
        [sys.executable, '-c', source, *(str(arg) for arg in args)],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()


def locks(path: Path, journal: str) -> dict[str, str]:
    result = {'database_shared': child(LOCK_PROBE, path, 0x40000002, 510)}
    if journal == 'WAL':
        result['shm_dead_man_switch'] = child(LOCK_PROBE, str(path) + '-shm', 128, 1)
    return result


def check_shape(shape: str, descriptor: int) -> None:
    proc = Path(f'/proc/self/fd/{descriptor}')
    dev = Path(f'/dev/fd/{descriptor}')
    if shape == 'available':
        assert proc.exists() and dev.exists()
    else:
        assert not proc.exists() and not dev.exists()
        assert Path('/proc/self/fd').is_dir() == (shape == 'unusable')


def exercise(journal: str, shape: str, expect_loss: bool) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix='megalodon-lock-acceptance-') as directory:
        path = Path(directory) / 'disposable.db'
        c = sqlite3.connect(path, timeout=0)
        try:
            assert c.execute(f'PRAGMA journal_mode={journal}').fetchone()[0].upper() == journal
            c.execute('CREATE TABLE probe(v INTEGER)')
            c.execute('INSERT INTO probe VALUES (1)')
            c.commit()
            path.chmod(0o600)
            c.execute('BEGIN IMMEDIATE')
            c.execute('INSERT INTO probe VALUES (2)')
            before = locks(path, journal)
            assert set(before.values()) == {'held'}
            assert child(SQLITE_PROBE, path) == 'busy'
            # This O_PATH descriptor cannot itself release the transaction's locks.
            shape_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                check_shape(shape, shape_fd)
                if shape != 'available':
                    try:
                        storage._anchored_database_path(shape_fd, path, 'STORAGE_PATH')
                    except storage.StorageSchemaError as exc:
                        assert str(exc) == 'STORAGE_PATH:DESCRIPTOR_PATH_UNAVAILABLE'
                    else:
                        raise AssertionError('unanchored database was admitted')
            finally:
                os.close(shape_fd)
            refused = False
            try:
                descriptor = storage._open_for_identity(path, os.O_RDWR | os.O_NOFOLLOW)
            except OSError as exc:
                assert exc.errno == errno.ENOTSUP
                refused = True
            else:
                try:
                    assert os.path.samestat(path.stat(), os.fstat(descriptor))
                finally:
                    os.close(descriptor)
            after_database = locks(path, journal)
            if expect_loss:
                assert not refused
                assert after_database['database_shared'] == 'released'
                assert c.in_transaction
                return {'journal': journal, 'outcome': 'baseline_lock_loss_reproduced'}
            assert after_database == before
            assert refused == (shape != 'available')
            if shape == 'available':
                denied = Path(directory) / 'permission.db'
                denied.write_bytes(b'')
                denied.chmod(0o400)
                try:
                    storage._open_for_identity(denied, os.O_RDWR | os.O_NOFOLLOW)
                except OSError as exc:
                    assert exc.errno == errno.EACCES
                else:
                    raise AssertionError('write permission refusal was bypassed')
            try:
                storage._validate_sqlite_sidecars(
                    path, None, writable=True, prefix='STORAGE_PATH'
                )
            except storage.StorageSchemaError as exc:
                assert shape != 'available'
                assert str(exc) == 'STORAGE_PATH:UNSAFE_SIDECAR'
            else:
                assert shape == 'available'
            assert locks(path, journal) == before
            assert child(SQLITE_PROBE, path) == 'busy'
            c.rollback()
            assert c.execute('SELECT group_concat(v) FROM probe').fetchone() == ('1',)
            other = sqlite3.connect(path, timeout=0)
            try:
                other.execute('INSERT INTO probe VALUES (3)')
                other.commit()
            finally:
                other.close()
            assert c.execute('SELECT group_concat(v) FROM probe').fetchone() == ('1,3',)
            assert c.execute('PRAGMA integrity_check').fetchone() == ('ok',)
            return {'journal': journal, 'outcome': 'refused_safely' if refused else 'preserved'}
        finally:
            c.rollback()
            c.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--shape', choices=('available', 'absent', 'unusable'), required=True)
    parser.add_argument('--expect-lock-loss', action='store_true')
    args = parser.parse_args()
    assert sys.platform.startswith('linux') and hasattr(os, 'O_PATH')
    assert os.geteuid() != 0, 'probe refuses root operation'
    assert not args.expect_lock_loss or args.shape != 'available'
    results = [exercise(journal, args.shape, args.expect_lock_loss) for journal in ('WAL', 'DELETE')]
    print(json.dumps({
        'platform': sys.platform, 'kernel': platform.release(),
        'uid': os.geteuid(), 'python': platform.python_version(),
        'sqlite': sqlite3.sqlite_version, 'shape': args.shape,
        'filesystem_emulation': False, 'results': results,
    }, sort_keys=True))


if __name__ == '__main__':
    main()
