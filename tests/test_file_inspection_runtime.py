"""Private runtime identity, fixed install recipe and extraction admission."""
import io
import json
import os
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

from megalodon import file_inspection_runtime as runtime
from megalodon.file_inspection_sandbox import sealed_input, seal
from megalodon.tool_installer import install_command, terminal_command, RECIPES, OPTIONAL_RECIPES, INSTALLABLES


@pytest.fixture
def prerequisite_files(monkeypatch):
    # Artifact-admission unit tests do not install or execute host tools.
    # Opt-in native tests independently exercise their actual prerequisites.
    original = Path.is_file
    fixed = {'/usr/bin/bwrap', '/usr/bin/dpkg-deb', '/usr/bin/systemd-run'}
    monkeypatch.setattr(Path, 'is_file', lambda path: str(path) in fixed or original(path))


def test_catalog_pins_artifacts_and_both_complete_file_sets():
    value = runtime.catalog()
    assert value['versions']['lief'] == '1.0.0'
    assert value['versions']['die'] == '3.21'
    assert set(value['artifacts']) == {'die', 'qtcore', 'qtscript', 'icu', 'cp311', 'cp312'}
    for item in value['artifacts'].values():
        assert item['url'].startswith('https://')
        assert len(item['sha256']) == 64 and 0 < item['size'] < 32 * 1024 * 1024
    assert all(len(item) == 64 for item in value['trees'].values())


def test_inspector_recipe_is_optional_and_fixed(monkeypatch):
    monkeypatch.setattr('megalodon.file_inspection_sandbox.supported', lambda: True)
    command = install_command('file-inspector')
    assert command[1:] == ['-I', '-m', 'megalodon.file_inspection_runtime']
    assert 'file-inspector' not in RECIPES and 'file-inspector' in INSTALLABLES
    assert OPTIONAL_RECIPES['file-inspector'].kind == 'inspector'
    assert terminal_command('file-inspector', 'uninstall') is None
    monkeypatch.setattr('megalodon.file_inspection_sandbox.supported', lambda: False)
    assert install_command('file-inspector') is None


def test_exact_tree_rejects_added_changed_and_public_files(tmp_path):
    tmp_path.chmod(0o700)
    file = tmp_path / 'worker'
    file.write_bytes(b'fixed reviewed dependency bytes')
    file.chmod(0o400)
    original = runtime.tree_digest(tmp_path)
    file.chmod(0o600)
    file.write_bytes(b'changed')
    file.chmod(0o400)
    assert runtime.tree_digest(tmp_path) != original
    file.chmod(0o444)
    with pytest.raises(ValueError):
        runtime.tree_digest(tmp_path)


def test_tree_refuses_symlinks_and_hardlinks(tmp_path):
    tmp_path.chmod(0o700)
    (tmp_path / 'link').symlink_to('/etc/passwd')
    with pytest.raises(ValueError):
        runtime.tree_digest(tmp_path)
    (tmp_path / 'link').unlink()
    file = tmp_path / 'one'
    file.write_bytes(b'fixed')
    file.chmod(0o400)
    os.link(file, tmp_path / 'two')
    with pytest.raises(ValueError):
        runtime.tree_digest(tmp_path)


def test_sealed_sample_cannot_be_modified_or_made_executable():
    fd = sealed_input()
    try:
        os.write(fd, b'synthetic input')
        seal(fd)
        with pytest.raises(OSError):
            os.write(fd, b'change')
        with pytest.raises(OSError):
            os.fchmod(fd, 0o700)
    finally:
        os.close(fd)


def test_traversal_and_link_entries_never_leave_stage(tmp_path, monkeypatch):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as archive:
        member = tarfile.TarInfo('./usr/lib/die/db/../../escape')
        member.size = 5
        archive.addfile(member, io.BytesIO(b'fixed'))
    monkeypatch.setattr(runtime.subprocess, 'run', lambda *a, **k: SimpleNamespace(stdout=raw.getvalue()))
    with pytest.raises(ValueError):
        runtime.assemble({'die': Path('/fixed')}, tmp_path, 'cp312')
    assert not (tmp_path.parent / 'escape').exists()


def test_injected_downloader_does_not_bypass_artifact_identity(tmp_path, monkeypatch, prerequisite_files):
    tmp_path.chmod(0o700)
    monkeypatch.setattr(runtime, 'supported', lambda: True)
    def acquire(item, path):
        path.write_bytes(b'wrong bytes')
    with pytest.raises(ValueError, match='identity mismatch'):
        runtime.install(tmp_path, acquire=acquire)
    assert not runtime.runtime_path(tmp_path).exists()
    assert not list(runtime.runtime_path(tmp_path).parent.glob('.prepare-*'))


def test_modified_runtime_is_preserved_not_overwritten(tmp_path, monkeypatch, prerequisite_files):
    tmp_path.chmod(0o700)
    root = runtime.runtime_path(tmp_path)
    runtime._owned_directory(root.parent, private=True)
    root.mkdir(mode=0o700)
    sentinel = root / 'unfinished'
    sentinel.write_text('preserve this')
    sentinel.chmod(0o400)
    monkeypatch.setattr(runtime, 'supported', lambda: True)
    with pytest.raises(ValueError, match='changed'):
        runtime.install(tmp_path, acquire=lambda *_: pytest.fail('No acquisition for an existing runtime.'))
    assert sentinel.read_text() == 'preserve this'


def test_missing_prerequisite_refuses_before_acquisition(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'supported', lambda: True)
    original = Path.is_file
    monkeypatch.setattr(Path, 'is_file', lambda path: str(path) != '/usr/bin/bwrap' and original(path))
    with pytest.raises(ValueError, match='Install bubblewrap'):
        runtime.install(tmp_path, acquire=lambda *_: pytest.fail('Missing prerequisites must refuse acquisition.'))
    assert not runtime.runtime_path(tmp_path).exists()
