"""CI-only synthetic recovery rehearsal; no operator acceptance or activation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import sys
import tempfile


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def command(arguments, directory, expected_code=0):
    result = subprocess.run(
        [sys.executable, '-m', 'megalodon', *arguments], cwd=directory,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30,
    )
    require(result.returncode == expected_code, 'COMMAND_FAILED')
    require(len(result.stdout.encode()) <= 8192 and len(result.stderr.encode()) <= 8192, 'OUTPUT_LIMIT')
    return result.stdout


def read_only_count(path):
    with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as connection:
        connection.execute('PRAGMA query_only=ON')
        require(connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'INTEGRITY')
        require(connection.execute('PRAGMA foreign_key_check').fetchall() == [], 'FOREIGN_KEYS')
        return connection.execute('SELECT count(*) FROM events').fetchone()[0]


def main():
    require(sys.platform == 'linux' and os.getuid() != 0, 'NONROOT_LINUX_REQUIRED')
    release = platform.freedesktop_os_release()
    require((release.get('ID'), release.get('VERSION_ID')) == ('ubuntu', '24.04'), 'PLATFORM')
    pins = {key: os.environ.get(key, '') for key in ('EXPECTED_COMMIT', 'EXPECTED_TREE')}
    require(all(re.fullmatch('[0-9a-f]{40}', value) for value in pins.values()), 'SOURCE_PIN')
    with tempfile.TemporaryDirectory(prefix='megalodon-recovery-') as directory:
        root = Path(directory)
        for name in ('source', 'backup', 'restored'):
            (root / name).mkdir(mode=0o700)
        source = root / 'source/audit.db'
        config = root / 'settings.toml'
        config.write_text('[app]\ndb_path = ' + json.dumps(str(source)) + '\n')
        config.chmod(0o600)
        command(['run', '--source', 'sample', '--max-events', '13', '--config', str(config)], root)
        artifact = root / 'backup/audit.db'
        manifest = root / 'backup/audit.manifest.json'
        backup = json.loads(command([
            'database-backup', str(artifact), '--manifest', str(manifest),
            '--operation-id', 'synthetic-rehearsal-backup', '--config', str(config),
        ], root))
        require(backup['status'] == 'completed', 'BACKUP')
        destination = root / 'restored/audit.db'
        restore_args = [
            'database-restore', str(artifact), str(destination), '--manifest', str(manifest),
            '--artifact-sha256', backup['artifact_sha256'], '--operation-id', 'synthetic-rehearsal-restore',
        ]
        restored = json.loads(command(restore_args, root))
        require(restored['status'] == 'completed', 'RESTORE')
        require(restored['artifact_sha256'] == backup['artifact_sha256'], 'ARTIFACT_BINDING')
        require(restored['manifest_sha256'] == backup['manifest_sha256'], 'MANIFEST_BINDING')
        require(not any(backup['effects'].values()) and not any(restored['effects'].values()), 'EFFECTS')
        counts = [read_only_count(source), read_only_count(destination)]
        require(counts == [13, 13], 'EVENT_COUNTS')
        identity = (destination.stat().st_dev, destination.stat().st_ino)
        collision = json.loads(command(restore_args, root, expected_code=2))
        require(collision['reason'] == 'DESTINATION_EXISTS', 'COLLISION_REFUSAL')
        require((destination.stat().st_dev, destination.stat().st_ino) == identity, 'DESTINATION_CHANGED')
        require(read_only_count(destination) == 13, 'DESTINATION_CONTENT')
        result = {
            'schema_version': 'synthetic-recovery-rehearsal-v1', 'status': 'passed',
            'basis': 'synthetic_only_temporary_rehearsal',
            'commit': pins['EXPECTED_COMMIT'], 'tree': pins['EXPECTED_TREE'],
            'os': 'ubuntu-24.04', 'python': platform.python_version(), 'uid': os.getuid(),
            'source_events': counts[0], 'restored_events': counts[1],
            'integrity': 'ok', 'foreign_key_violations': 0,
            'backup': 'completed', 'restore': 'completed',
            'existing_destination': 'refused_and_preserved',
            'activated': False, 'operator_acceptance': 'not_assessed',
        }
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError):
        print('{"status":"failed","reason":"RECOVERY_REHEARSAL_FAILED"}', file=sys.stderr)
        raise SystemExit(2)
