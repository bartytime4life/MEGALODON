"""Owner-selected executable directories for fixed local companion tools.

This profile contains directories, never commands. Discovery checks a fixed
executable name for each tool; only explicit tool actions may execute one.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

SCHEMA = 'megalodon-tool-directories-v1'
MAX_FILE_BYTES = 8192
MAX_DIRECTORY_BYTES = 1024
EXECUTABLES = {
    'tshark': ('tshark',), 'zeek': ('zeek',), 'suricata': ('suricata',),
    'nftables': ('nft',), 'clamav': ('clamscan',),
    'osquery': ('osqueryi', 'osqueryd'), 'qwen': ('ollama',), 'nmap': ('nmap',),
}


def profile_path(home: Path) -> Path:
    return Path(home) / '.config/megalodon/tool-directories.json'


def valid_directory(value: object) -> str:
    if not isinstance(value, str) or not value or value.startswith('//'):
        raise ValueError('Choose an absolute installation directory.')
    try:
        encoded = value.encode('utf-8')
    except UnicodeEncodeError:
        raise ValueError('Choose a valid installation directory.') from None
    if (len(encoded) > MAX_DIRECTORY_BYTES or not value.startswith('/')
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or any(part in {'.', '..'} for part in value.split('/'))):
        raise ValueError('Choose a bounded absolute installation directory.')
    return value.rstrip('/') or '/'


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate tool directory field.')
        result[key] = value
    return result


def load_directories(home: Path) -> dict[str, str]:
    """Read only one private owner profile; missing means automatic discovery."""
    path = profile_path(home)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return {}
    except OSError as exc:
        raise ValueError('Tool directory profile is unavailable.') from exc
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_FILE_BYTES):
            raise ValueError('Tool directory profile is unsafe.')
        raw = os.read(fd, MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('Tool directory profile is too large.')
    finally:
        os.close(fd)
    try:
        value = json.loads(raw, object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('Tool directory profile is invalid.') from exc
    if (type(value) is not dict or set(value) != {'schema', 'directories'}
            or value['schema'] != SCHEMA or type(value['directories']) is not dict
            or len(value['directories']) > len(EXECUTABLES)):
        raise ValueError('Tool directory profile is invalid.')
    for tool, directory in value['directories'].items():
        if tool not in EXECUTABLES or valid_directory(directory) != directory:
            raise ValueError('Tool directory profile is invalid.')
    return dict(value['directories'])


def trusted_executable(directory: str, name: str) -> bool:
    # Reject a selected executable that another account can replace.
    path = Path(directory) / name
    owners = {os.geteuid(), os.lstat('/').st_uid}
    try:
        for parent in reversed(path.parents):
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners
                    or info.st_mode & 0o002
                    or (info.st_mode & 0o020 and info.st_uid != os.geteuid())):
                return False
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid in owners
                and not info.st_mode & 0o022 and os.access(path, os.X_OK, effective_ids=True))
    except OSError:
        return False


def save_directory(home: Path, tool: str, directory: str) -> dict[str, str]:
    """Save or clear one bounded directory, without running the tool."""
    if tool not in EXECUTABLES:
        raise ValueError('Choose a supported tool.')
    if directory:
        directory = valid_directory(directory)
        location = Path(directory)
        if not location.is_dir() or location.is_symlink():
            raise ValueError('Choose an existing real installation directory.')
        if not any(trusted_executable(directory, name) for name in EXECUTABLES[tool]):
            raise ValueError('The selected directory has no trusted executable for this tool.')
    previous = load_directories(home)
    updated = dict(previous)
    if directory:
        updated[tool] = directory
    else:
        updated.pop(tool, None)
    from .local_install import _atomic_write, _owned_directory
    parent = profile_path(home).parent
    _owned_directory(parent, private=True)
    if updated:
        raw = json.dumps({'schema': SCHEMA, 'directories': updated}, sort_keys=True).encode()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('Tool directory profile is too large.')
        _atomic_write(profile_path(home), raw, 0o600)
    elif profile_path(home).exists():
        # Keep a valid empty profile, preserving owner/private metadata.
        _atomic_write(profile_path(home), json.dumps({'schema': SCHEMA, 'directories': {}}).encode(), 0o600)
    return updated
