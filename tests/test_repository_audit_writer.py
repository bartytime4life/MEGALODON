"""Repository inventory writes cannot replace the preserved historical audit."""
from pathlib import Path

import pytest

from tools import repository_audit


def audit_root(tmp_path, monkeypatch):
    root=tmp_path/'repository';(root/'docs/audit').mkdir(parents=True)
    monkeypatch.setattr(repository_audit,'ROOT',root)
    return root


def test_new_dated_inventory_path_is_admitted(tmp_path,monkeypatch):
    root=audit_root(tmp_path,monkeypatch)
    value=repository_audit.inventory_output('docs/audit/repository-files-20261024.json')
    assert value==root/'docs/audit/repository-files-20261024.json'


@pytest.mark.parametrize('value',['docs/audit/repository-files.json','repository-files.json',
                                  'docs/repository-files.json','docs/audit/inventory.txt'])
def test_historical_or_out_of_scope_inventory_path_is_refused(tmp_path,monkeypatch,value):
    audit_root(tmp_path,monkeypatch)
    with pytest.raises(ValueError):repository_audit.inventory_output(value)


def test_existing_file_and_symlink_are_refused(tmp_path,monkeypatch):
    root=audit_root(tmp_path,monkeypatch)
    existing=root/'docs/audit/existing.json';existing.write_text('{}')
    with pytest.raises(ValueError,match='already exists'):
        repository_audit.inventory_output('docs/audit/existing.json')
    outside=tmp_path/'outside.json';link=root/'docs/audit/link.json';link.symlink_to(outside)
    with pytest.raises(ValueError):repository_audit.inventory_output('docs/audit/link.json')


def test_dangling_in_directory_symlink_is_refused_before_resolution(tmp_path,monkeypatch):
    root=audit_root(tmp_path,monkeypatch)
    link=root/'docs/audit/snapshot.json';link.symlink_to('other.json')
    with pytest.raises(ValueError,match='already exists'):
        repository_audit.inventory_output('docs/audit/snapshot.json')
    assert link.is_symlink() and not (root/'docs/audit/other.json').exists()


def test_late_file_creation_cannot_replace_a_snapshot(tmp_path,monkeypatch):
    root=audit_root(tmp_path,monkeypatch)
    target=repository_audit.inventory_output('docs/audit/new.json')
    target.write_text('preserved')
    with pytest.raises(FileExistsError):repository_audit.write_inventory(target,{'value':'replacement'})
    assert target.read_text()=='preserved'
