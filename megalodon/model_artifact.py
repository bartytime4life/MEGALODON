"""Explicit offline verification of one local Ollama/Qwen artifact's bytes.

This is an evidence collector, not runtime admission. It never contacts Ollama,
executes a provider, reads prompt contents into a receipt, or changes a binding.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from time import monotonic

SCHEMA = 'megalodon-local-model-artifact-observation-v1'
MAX_MANIFEST_BYTES = 65536
MAX_COMPONENTS = 32
MAX_TOTAL_BYTES = 32 * 1024**3
MAX_PROVIDER_BYTES = 256 * 1024**2
MAX_SECONDS = 120
CHUNK_BYTES = 1024**2
MODEL = re.compile(r'(qwen[0-9]+(?:\.[0-9]+)?):([A-Za-z0-9][A-Za-z0-9_.-]{0,95})')
HEX = re.compile(r'[a-f0-9]{64}')
ROLES = {
    'application/vnd.docker.container.image.v1+json': 'config',
    'application/vnd.ollama.image.model': 'weights',
    'application/vnd.ollama.image.template': 'template',
    'application/vnd.ollama.image.system': 'system',
    'application/vnd.ollama.image.params': 'parameters',
    'application/vnd.ollama.image.license': 'license',
}


class ArtifactError(ValueError):
    """Fixed, path-free diagnostic; no caller or file content is echoed."""


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


@contextmanager
def _directory(path):
    """Pin every directory, rejecting links and parent traversal in the path."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ArtifactError('ABSOLUTE_DIRECTORY_REQUIRED')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _child_directory(parent, parts):
    fd = os.dup(parent)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


class _Reader:
    def __init__(self, clock):
        self.clock = clock
        self.deadline = clock() + MAX_SECONDS
        self.total = 0

    def check(self):
        if self.clock() >= self.deadline:
            raise ArtifactError('VERIFICATION_DEADLINE')

    def read(self, directory, name, limit, *, retain=False, expected_size=None,
             expected_digest=None, executable=False):
        self.check()
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ArtifactError('REGULAR_FILE_REQUIRED')
            if executable and (not before.st_mode & 0o111 or before.st_mode & 0o022):
                raise ArtifactError('UNSAFE_PROVIDER_FILE')
            if not 0 < before.st_size <= limit:
                raise ArtifactError('FILE_SIZE_LIMIT')
            if expected_size is not None and before.st_size != expected_size:
                raise ArtifactError('COMPONENT_SIZE_MISMATCH')
            if self.total + before.st_size > MAX_TOTAL_BYTES:
                raise ArtifactError('TOTAL_BYTES_LIMIT')
            digest = hashlib.sha256()
            chunks = []
            count = 0
            while True:
                self.check()
                data = os.read(fd, min(CHUNK_BYTES, before.st_size - count + 1))
                if not data:
                    break
                count += len(data)
                self.total += len(data)
                if count > before.st_size or self.total > MAX_TOTAL_BYTES:
                    raise ArtifactError('FILE_CHANGED')
                digest.update(data)
                if retain:
                    chunks.append(data)
            self.check()
            if (count != before.st_size or _identity(os.fstat(fd)) != _identity(before)
                    or _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)) != _identity(before)):
                raise ArtifactError('FILE_CHANGED')
            value = digest.hexdigest()
            if expected_digest is not None and value != expected_digest:
                raise ArtifactError('COMPONENT_DIGEST_MISMATCH')
            return value, count, b''.join(chunks), _identity(before)
        finally:
            os.close(fd)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError('DUPLICATE_MANIFEST_FIELD')
        result[key] = value
    return result


def _descriptors(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ArtifactError('INVALID_MANIFEST')))
    except (ValueError, RecursionError, UnicodeError) as exc:
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError('INVALID_MANIFEST') from None
    if (type(value) is not dict or set(value) != {'schemaVersion', 'mediaType', 'config', 'layers'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 2
            or value['mediaType'] != 'application/vnd.docker.distribution.manifest.v2+json'
            or type(value['layers']) is not list or not 1 <= len(value['layers']) < MAX_COMPONENTS):
        raise ArtifactError('INVALID_MANIFEST')
    result, seen = [], set()
    for index, row in enumerate([value['config'], *value['layers']]):
        if (type(row) is not dict or set(row) not in ({'mediaType', 'digest', 'size'}, {'mediaType', 'digest', 'size', 'from'})
                or type(row['mediaType']) is not str or row['mediaType'] not in ROLES
                or type(row['digest']) is not str or re.fullmatch(r'sha256:[a-f0-9]{64}', row['digest']) is None
                or type(row['size']) is not int or not 0 < row['size'] <= MAX_TOTAL_BYTES):
            raise ArtifactError('INVALID_COMPONENT')
        # Ollama adds optional source labels to imported layers. They are bounded
        # metadata only: never a path to read, URL to fetch, or provenance proof.
        if 'from' in row and (type(row['from']) is not str
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}', row['from']) is None):
            raise ArtifactError('INVALID_COMPONENT')
        role = ROLES[row['mediaType']]
        if (index == 0) != (role == 'config') or row['digest'] in seen:
            raise ArtifactError('INVALID_COMPONENT_CLOSURE')
        seen.add(row['digest'])
        result.append(dict(role=role, sha256=row['digest'][7:], size_bytes=row['size']))
    if sum(row['role'] == 'weights' for row in result) != 1:
        raise ArtifactError('EXACTLY_ONE_WEIGHT_COMPONENT_REQUIRED')
    if sum(row['size_bytes'] for row in result) > MAX_TOTAL_BYTES - MAX_MANIFEST_BYTES:
        raise ArtifactError('TOTAL_BYTES_LIMIT')
    return result


def observe_artifact(store, model, provider='/usr/local/bin/ollama', *,
                     manifest_pin=None, provider_pin=None, clock=monotonic):
    """Hash one explicit artifact and provider; no provider API or activation.

    Pins are optional independently obtained comparison targets. A content-address
    match verifies consistency with the local manifest, not publisher provenance.
    The time budget is cooperative: it cannot interrupt a blocked kernel read.
    """
    match = MODEL.fullmatch(model) if type(model) is str else None
    if match is None or match[2] == 'latest' or '..' in match[2]:
        raise ArtifactError('EXACT_QWEN_TAG_REQUIRED')
    for pin in (manifest_pin, provider_pin):
        if pin is not None and (type(pin) is not str or HEX.fullmatch(pin) is None):
            raise ArtifactError('INVALID_PIN')
    reader = _Reader(clock)
    try:
        provider = Path(provider)
        with _directory(provider.parent) as directory:
            provider_digest, provider_size, _, provider_identity = reader.read(
                directory, provider.name, MAX_PROVIDER_BYTES, executable=True)
        if provider_pin is not None and provider_digest != provider_pin:
            raise ArtifactError('PROVIDER_PIN_MISMATCH')
        with _directory(store) as root:
            with _child_directory(root, ['manifests', 'registry.ollama.ai', 'library', match[1]]) as manifests:
                manifest_digest, _, raw, manifest_identity = reader.read(
                    manifests, match[2], MAX_MANIFEST_BYTES, retain=True)
                if manifest_pin is not None and manifest_digest != manifest_pin:
                    raise ArtifactError('MANIFEST_PIN_MISMATCH')
                descriptors = _descriptors(raw)
                identities = []
                with _child_directory(root, ['blobs']) as blobs:
                    blob_directory_identity = _directory_identity(blobs)
                    for row in descriptors:
                        _, _, _, identity = reader.read(
                            blobs, 'sha256-' + row['sha256'], MAX_TOTAL_BYTES,
                            expected_size=row['size_bytes'], expected_digest=row['sha256'])
                        identities.append(identity)
                    # Recheck every directory entry after the complete closure read.
                    for row, identity in zip(descriptors, identities):
                        if _identity(os.stat('sha256-' + row['sha256'], dir_fd=blobs,
                                             follow_symlinks=False)) != identity:
                            raise ArtifactError('FILE_CHANGED')
                if _identity(os.stat(match[2], dir_fd=manifests, follow_symlinks=False)) != manifest_identity:
                    raise ArtifactError('FILE_CHANGED')
                # Also re-resolve the operator's path: a renamed whole store or
                # component directory must not leave a stale open directory valid.
                with _directory(store) as current_root:
                    if _directory_identity(current_root) != _directory_identity(root):
                        raise ArtifactError('FILE_CHANGED')
                    with _child_directory(current_root, ['manifests', 'registry.ollama.ai', 'library', match[1]]) as current_manifests:
                        if (_directory_identity(current_manifests) != _directory_identity(manifests)
                                or _identity(os.stat(match[2], dir_fd=current_manifests, follow_symlinks=False)) != manifest_identity):
                            raise ArtifactError('FILE_CHANGED')
                    with _child_directory(current_root, ['blobs']) as current_blobs:
                        if _directory_identity(current_blobs) != blob_directory_identity:
                            raise ArtifactError('FILE_CHANGED')
                        for row, identity in zip(descriptors, identities):
                            if _identity(os.stat('sha256-' + row['sha256'], dir_fd=current_blobs,
                                                 follow_symlinks=False)) != identity:
                                raise ArtifactError('FILE_CHANGED')
        with _directory(provider.parent) as directory:
            if _identity(os.stat(provider.name, dir_fd=directory, follow_symlinks=False)) != provider_identity:
                raise ArtifactError('FILE_CHANGED')
        reader.check()
    except OSError:
        raise ArtifactError('ARTIFACT_UNAVAILABLE') from None
    return {
        'schema': SCHEMA, 'state': 'ARTIFACT_BYTES_VERIFIED', 'binding_status': 'UNBOUND',
        'observed_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'model': model, 'manifest_sha256': manifest_digest,
        'provider': {'executable_sha256': provider_digest, 'size_bytes': provider_size,
                     'version': None, 'provenance_verified': False},
        'components': descriptors, 'total_bytes_read': reader.total,
        'pin_comparisons': {'manifest': 'matched' if manifest_pin else 'not_supplied',
                            'provider': 'matched' if provider_pin else 'not_supplied'},
        'authority': {'contacts_provider': False, 'starts_model': False, 'accepts_model': False,
                      'changes_binding': False, 'changes_host_configuration': False,
                      'attests_loaded_bytes': False, 'grants_action_authority': False},
        'remaining_holds': ['PUBLISHER_PROVENANCE', 'OWNER_EXACT_BINDING', 'EVIDENCE_ORIGIN_AUTHENTICATION',
                            'SIGNED_CORPUS_EXECUTION', 'NATIVE_CONTAINMENT', 'LOADED_RUNTIME_BYTES',
                            'INDEPENDENT_SECURITY_REVIEW', 'OWNER_ACCEPTANCE', 'RUNTIME_ADMISSION'],
        'limitations': [
            'Verifies bytes against this local manifest, not publisher identity or model effectiveness.',
            'No provider was contacted; provider version and loaded model bytes remain unverified.',
            'File identity checks detect observed replacement, not an atomic snapshot or future immutability.',
            'The cooperative deadline cannot interrupt an individual blocked filesystem operation.',
            'This observation does not enable Qwen or lift the UNBOUND runtime fence.',
        ],
    }
