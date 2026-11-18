"""Operator-authored YARA rules for the optional file inspector.

Rules live in one folder, by default ``~/.config/megalodon/yara-rules``. Each
``.yar`` or ``.yara`` file is a namespace named after the file. The host reads
the files into one bounded bundle, which is copied into a sealed memory file:
the rules are compiled and matched only inside the inspection sandbox, so a
hostile or malformed rule meets the same confinement as the sample. Nothing on
the host imports YARA.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from threading import Event
import time

from .file_inspection_contract import (BUNDLE_SCHEMA, MAX_BUNDLE, MAX_RULE_FILE, MAX_RULE_FILES,
                                       NAMESPACE, _RULE_CONTROLS, decode, rules_result, validate_rules)

RULES_DIR = Path('.config/megalodon/yara-rules')
SUFFIXES = ('.yar', '.yara')
DEADLINE = 15


class RulesError(ValueError):
    pass


def rules_dir(home=None):
    return Path(home or Path.home()) / RULES_DIR


def _read(directory_fd, name):
    # O_NONBLOCK: a FIFO named like a rule file is refused instead of blocking.
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise RulesError(f'{name} is not a regular file.')
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RulesError(f'{name} must be owned by you and not writable by others.')
        if info.st_size > MAX_RULE_FILE:
            raise RulesError(f'{name} is larger than 1 MiB.')
        data = b''
        while len(data) <= MAX_RULE_FILE:
            part = os.read(fd, MAX_RULE_FILE + 1 - len(data))
            if not part:
                break
            data += part
        if len(data) > MAX_RULE_FILE:
            raise RulesError(f'{name} is larger than 1 MiB.')
    finally:
        os.close(fd)
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise RulesError(f'{name} is not UTF-8 text.') from None
    if _RULE_CONTROLS.search(text):
        # Tab and line breaks only, which also bounds the escaped bundle size.
        raise RulesError(f'{name} contains a control character other than tab or a line break.')
    return text


def load(directory=None, *, home=None):
    """Return {'sources', 'digest', 'files'} or None when no rules are configured.

    A missing folder, or one without rule files, means not configured. Anything
    unsafe or out of bounds is refused rather than skipped, so a rule never
    silently drops out of coverage.
    """
    directory = Path(directory) if directory is not None else rules_dir(home)
    try:
        info = os.lstat(directory)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RulesError('The YARA rules folder must be a real directory, not a link.')
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise RulesError('The YARA rules folder must be owned by you and not writable by others.')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise RulesError('The YARA rules folder changed while it was read.')
        names = sorted(entry.name for entry in os.scandir(fd)
                       if not entry.name.startswith('.') and entry.name.endswith(SUFFIXES))
        if len(names) > MAX_RULE_FILES:
            raise RulesError(f'The YARA rules folder has more than {MAX_RULE_FILES} rule files.')
        sources, total = {}, 0
        for name in names:
            namespace = name.rsplit('.', 1)[0]
            if not re.fullmatch(NAMESPACE, namespace):
                raise RulesError(f'{name}: use letters, digits, dot, dash or underscore in rule file names.')
            if namespace in sources:
                raise RulesError(f'{name}: another rule file already uses the name {namespace}.')
            sources[namespace] = _read(fd, name)
            total += len(sources[namespace].encode('utf-8'))
            if total > MAX_BUNDLE:
                raise RulesError('The YARA rules together exceed 4 MiB.')
    finally:
        os.close(fd)
    if not sources:
        return None
    return dict(sources=sources, files=len(sources), digest=hashlib.sha256(bundle_bytes(sources)).hexdigest())


def bundle_bytes(sources):
    return json.dumps(dict(schema=BUNDLE_SCHEMA, sources=sources), ensure_ascii=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')


def normalize(raw):
    """A worker result as a complete rules section; unknown shapes fail closed."""
    value = decode(raw)
    if type(value) is dict and value.get('state') in ('invalid_rules', 'timed_out', 'failed') and len(value) == 1:
        return rules_result(value)
    if type(value) is not dict or value.get('state') != 'completed':
        raise ValueError('Unsupported rules result.')
    return validate_rules(value)


def scan(home, fd, cancelled, *, runner, loader=None, validator=None, directory=None):
    """Apply the operator's rules to the sealed input in the sandbox; return a rules section."""
    from . import file_inspection_sandbox as sandbox
    from . import yara_runtime
    loader = loader or load
    validator = validator or yara_runtime.validate
    try:
        bundle = loader(directory, home=home)
    except (OSError, ValueError):
        return rules_result(dict(state='invalid_rules'))
    if bundle is None:
        return rules_result()
    if cancelled.is_set():
        return rules_result(dict(state='cancelled'))
    try:
        root = validator(home)
    except (OSError, ValueError):
        return rules_result(dict(state='unavailable'))
    try:
        rules_fd = sandbox.sealed_input()
    except OSError:
        return rules_result(dict(state='unavailable'))
    try:
        data = memoryview(bundle_bytes(bundle['sources']))
        while data:
            data = data[os.write(rules_fd, data):]
        sandbox.seal(rules_fd)
        state, raw = runner(root, fd, 'yara', deadline=time.monotonic() + DEADLINE,
                            cancelled=cancelled, rules=rules_fd)
    except OSError:
        return rules_result(dict(state='unavailable'))
    finally:
        os.close(rules_fd)
    if state != 'completed':
        return rules_result(dict(state=state if state in ('cancelled', 'timed_out', 'unavailable') else 'failed'))
    try:
        return normalize(raw)
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        return rules_result(dict(state='failed'))


def check(directory=None, *, home=None, runner=None, validator=None):
    """Bundle check, and a sandboxed compile against a one-byte input when the runtime is ready."""
    from . import file_inspection_sandbox as sandbox
    from . import yara_runtime
    path = Path(directory) if directory is not None else rules_dir(home)
    bundle = load(path)
    result = dict(folder=str(path), files=0, digest=None, namespaces=[], runtime='unavailable', compile=None)
    if bundle is None:
        result['compile'] = 'not_configured'
        return result
    result.update(files=bundle['files'], digest=bundle['digest'], namespaces=sorted(bundle['sources']))
    try:
        (validator or yara_runtime.validate)(home)
    except (OSError, ValueError):
        return result
    result['runtime'] = 'ready'
    fd = sandbox.sealed_input()
    try:
        os.write(fd, b'\0')
        sandbox.seal(fd)
        section = scan(home, fd, Event(), runner=runner or sandbox.run, directory=path,
                       loader=lambda _d, home=None: bundle, validator=validator)
    finally:
        os.close(fd)
    result['compile'] = section['state']
    result['rule_count'] = section['rule_count']
    return result
