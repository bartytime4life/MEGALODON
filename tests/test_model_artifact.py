"""Byte verification is explicit offline evidence, never model acceptance."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest

from megalodon import local_model_runtime, model_artifact as artifact


def digest(data):
    return hashlib.sha256(data).hexdigest()


@pytest.fixture
def store(tmp_path):
    root = tmp_path / 'store'
    folder = root / 'manifests/registry.ollama.ai/library/qwen2.5'
    folder.mkdir(parents=True)
    blobs = root / 'blobs'
    blobs.mkdir()
    descriptors = []
    for media_type, data in [
            ('application/vnd.docker.container.image.v1+json', b'{"model_format":"gguf"}'),
            ('application/vnd.ollama.image.model', b'private-inert-weight-fixture'),
            ('application/vnd.ollama.image.template', b'private-inert-template'),
            ('application/vnd.ollama.image.license', b'private-inert-license')]:
        (blobs / ('sha256-' + digest(data))).write_bytes(data)
        descriptors.append(dict(mediaType=media_type, digest='sha256:' + digest(data), size=len(data)))
    manifest = folder / '7b-instruct-fp16'
    manifest.write_text(json.dumps(dict(schemaVersion=2,
        mediaType='application/vnd.docker.distribution.manifest.v2+json',
        config=descriptors[0], layers=descriptors[1:])))
    provider = tmp_path / 'ollama'
    provider.write_bytes(b'inert-provider-fixture-not-executed')
    provider.chmod(0o700)
    return root, manifest, provider


def observe(store, **kwargs):
    root, _, provider = store
    return artifact.observe_artifact(root, 'qwen2.5:7b-instruct-fp16', provider, **kwargs)


def change_manifest(store, mutate):
    _, manifest, _ = store
    value = json.loads(manifest.read_bytes())
    mutate(value)
    manifest.write_text(json.dumps(value))


def weight(store):
    root, manifest, _ = store
    row = json.loads(manifest.read_bytes())['layers'][0]
    return root / 'blobs' / row['digest'].replace(':', '-')


@pytest.mark.parametrize('model,registry,namespace,name,tag', [
    ('qwen2.5:7b-instruct-fp16','registry.ollama.ai','library','qwen2.5','7b-instruct-fp16'),
    ('llama3.2:3b','registry.ollama.ai','library','llama3.2','3b'),
    ('nemotron-3-super:120b-a12b-q4_K_M','registry.ollama.ai','library','nemotron-3-super','120b-a12b-q4_K_M'),
    ('acme/llama3.2:3b','registry.ollama.ai','acme','llama3.2','3b'),
    ('hf.co/acme/model:Q4_K_M','hf.co','acme','model','Q4_K_M'),
    ('registry.ollama.ai/library/qwen2.5:7b-instruct-fp16','registry.ollama.ai','library','qwen2.5','7b-instruct-fp16'),
])
def test_real_bytes_and_external_comparison_pins_without_provider_operation(store, monkeypatch, model, registry, namespace, name, tag):
    _, manifest, provider = store
    expected=store[0]/'manifests'/registry/namespace/name/tag
    if expected!=manifest:
        expected.parent.mkdir(parents=True,exist_ok=True)
        manifest.rename(expected)
        manifest=expected
    manifest_pin, provider_pin = digest(manifest.read_bytes()), digest(provider.read_bytes())
    before = local_model_runtime.binding_failure()
    original_open = os.open
    def read_only_open(path, flags, *args, **kwargs):
        assert flags & os.O_ACCMODE == os.O_RDONLY
        assert not flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND)
        return original_open(path, flags, *args, **kwargs)
    def forbidden(*_a, **_k):
        pytest.fail('unexpected model, network, process, thread or write effect')
    with monkeypatch.context() as guard:
        for owner, names in [(socket, ['socket', 'getaddrinfo', 'create_connection']),
                             (subprocess, ['Popen', 'run']), (threading.Thread, ['start']),
                             (os, ['write', 'mkdir', 'unlink', 'replace', 'chmod', 'system'])]:
            for operation in names:
                guard.setattr(owner, operation, forbidden)
        guard.setattr(os, 'open', read_only_open)
        result = artifact.observe_artifact(store[0],model,provider,manifest_pin=manifest_pin,provider_pin=provider_pin)
    assert result['state'] == 'ARTIFACT_BYTES_VERIFIED'
    assert result['manifest_sha256'] == manifest_pin
    assert result['provider']['executable_sha256'] == provider_pin
    assert result['pin_comparisons'] == {'manifest': 'matched', 'provider': 'matched'}
    assert not any(result['authority'].values())
    assert result['binding_status'] == 'UNBOUND'
    assert local_model_runtime.binding_failure() == before == 'OWNER_MODEL_BINDING_NOT_RECORDED'
    output = json.dumps(result)
    assert str(store[0].parent) not in output and 'private-inert' not in output
    assert result['provider']['version'] is None
    assert result['model']==model


@pytest.mark.parametrize('model', [None, [], 'qwen2.5:latest', 'qwen2.5:../x',
    'qwen2.5:7b/other','nemotron','qwen2.5:7b\n','llama:latest','acme/model:LATEST',
    '../model:tag','acme/../model:tag','acme//model:tag','/model:tag','acme/model:tag/extra',
    'https://outside.invalid/model:tag','localhost:5000/acme/model:tag','a/b/c/d:tag',
    'm'*97+':tag','model:tag\x00'])
def test_unapproved_tag_refuses_before_file_access(store, monkeypatch, model):
    monkeypatch.setattr(os, 'open', lambda *_a, **_k: pytest.fail('invalid tag opened a file'))
    with pytest.raises(artifact.ArtifactError, match='^EXACT_LOCAL_MODEL_TAG_REQUIRED$'):
        artifact.observe_artifact(store[0], model, store[2])


def test_explicit_namespace_does_not_fall_back_to_library(store):
    with pytest.raises(artifact.ArtifactError,match='^ARTIFACT_UNAVAILABLE$'):
        artifact.observe_artifact(store[0],'acme/qwen2.5:7b-instruct-fp16',store[2])


def test_namespace_links_cannot_redirect_artifact_reads(store):
    base=store[0]/'manifests/registry.ollama.ai'
    (base/'acme').symlink_to(base/'library')
    with pytest.raises(artifact.ArtifactError,match='^ARTIFACT_UNAVAILABLE$'):
        artifact.observe_artifact(store[0],'acme/qwen2.5:7b-instruct-fp16',store[2])


@pytest.mark.parametrize('pin', ['a' * 63, 'a' * 65, 'A' * 64, 'a' * 64 + '\n', 42, True])
def test_invalid_pin_is_not_a_comparison_success(store, pin):
    with pytest.raises(artifact.ArtifactError, match='^INVALID_PIN$'):
        observe(store, manifest_pin=pin)


@pytest.mark.parametrize('field,code', [('manifest_pin', 'MANIFEST_PIN_MISMATCH'),
                                      ('provider_pin', 'PROVIDER_PIN_MISMATCH')])
def test_stale_pins_fail_before_weight_reads(store, field, code, monkeypatch):
    original = artifact._Reader.read
    def read(self, directory, name, *args, **kwargs):
        assert not name.startswith('sha256-'), 'stale pins must not read model blobs'
        return original(self, directory, name, *args, **kwargs)
    monkeypatch.setattr(artifact._Reader, 'read', read)
    with pytest.raises(artifact.ArtifactError, match='^' + code + '$'):
        observe(store, **{field: '0' * 64})


@pytest.mark.parametrize('kind,code', [('missing', 'ARTIFACT_UNAVAILABLE'),
    ('digest', 'COMPONENT_DIGEST_MISMATCH'), ('size', 'COMPONENT_SIZE_MISMATCH'),
    ('link', 'ARTIFACT_UNAVAILABLE'), ('pipe', 'REGULAR_FILE_REQUIRED')])
def test_bad_or_inaccessible_component_never_verifies(store, kind, code):
    path = weight(store)
    if kind == 'digest':
        path.write_bytes(b'x' * path.stat().st_size)
    elif kind == 'size':
        path.write_bytes(b'x')
    else:
        path.unlink()
        if kind == 'link':
            path.symlink_to(store[2])
        elif kind == 'pipe':
            os.mkfifo(path)
    with pytest.raises(artifact.ArtifactError, match='^' + code + '$'):
        observe(store)


@pytest.mark.parametrize('mutation,code', [
    (lambda x: x.update(remote_host='https://untrusted.invalid'), 'INVALID_MANIFEST'),
    (lambda x: x.update(schemaVersion=True), 'INVALID_MANIFEST'),
    (lambda x: x['layers'][0].update(digest='sha256:../escape'), 'INVALID_COMPONENT'),
    (lambda x: x['layers'][0].update(size=True), 'INVALID_COMPONENT'),
    (lambda x: x['layers'][0].update(size=artifact.MAX_TOTAL_BYTES + 1), 'TOTAL_BYTES_LIMIT'),
    (lambda x: x['layers'][0].update(mediaType='application/vnd.ollama.image.projector'), 'INVALID_COMPONENT'),
    (lambda x: x['layers'].append(dict(x['layers'][0])), 'INVALID_COMPONENT_CLOSURE'),
    (lambda x: x['layers'].pop(0), 'EXACTLY_ONE_WEIGHT_COMPONENT_REQUIRED'),
])
def test_closed_manifest_refuses_unknown_ambiguous_or_unsupported_data(store, mutation, code):
    change_manifest(store, mutation)
    with pytest.raises(artifact.ArtifactError, match='^' + code + '$'):
        observe(store)


def test_duplicate_json_field_refused(store):
    store[1].write_text('{"schemaVersion":2,"schemaVersion":2}')
    with pytest.raises(artifact.ArtifactError, match='^DUPLICATE_MANIFEST_FIELD$'):
        observe(store)


def test_ollama_import_source_label_is_metadata_not_a_read_or_provenance(store):
    change_manifest(store, lambda x: x['layers'][0].update({'from': 'registry.ollama.ai/library/qwen2.5:7b'}))
    value = observe(store)
    assert 'from' not in json.dumps(value) and 'registry.ollama.ai' not in json.dumps(value)
    assert value['provider']['provenance_verified'] is False
    change_manifest(store, lambda x: x['layers'][0].update({'from': {'url': 'https://untrusted.invalid'}}))
    with pytest.raises(artifact.ArtifactError, match='^INVALID_COMPONENT$'):
        observe(store)


def test_provider_and_store_links_are_refused(store):
    link = store[0].parent / 'linked-store'
    link.symlink_to(store[0])
    with pytest.raises(artifact.ArtifactError, match='^ARTIFACT_UNAVAILABLE$'):
        artifact.observe_artifact(link, 'qwen2.5:7b-instruct-fp16', store[2])
    store[2].chmod(0o722)
    with pytest.raises(artifact.ArtifactError, match='^UNSAFE_PROVIDER_FILE$'):
        observe(store)


def test_file_replacement_during_read_is_detected(store, monkeypatch):
    target = weight(store)
    inode = target.stat().st_ino
    replacement = target.with_name('replacement')
    replacement.write_bytes(target.read_bytes())
    original = os.read
    changed = False
    def read(fd, count):
        nonlocal changed
        data = original(fd, count)
        if not changed and os.fstat(fd).st_ino == inode and data:
            replacement.replace(target)
            changed = True
        return data
    monkeypatch.setattr(os, 'read', read)
    with pytest.raises(artifact.ArtifactError, match='^FILE_CHANGED$'):
        observe(store)


@pytest.mark.parametrize('target', ['store', 'blobs', 'manifests', 'provider'])
def test_directory_or_provider_replacement_after_reads_is_refused(store, monkeypatch, target):
    root, manifest, provider = store
    original = artifact._Reader.read
    changed = False
    def read(self, directory, name, *args, **kwargs):
        nonlocal changed
        result = original(self, directory, name, *args, **kwargs)
        if not changed and name.startswith('sha256-'):
            changed = True
            path = {'store': root, 'blobs': root / 'blobs',
                    'manifests': manifest.parent, 'provider': provider}[target]
            saved = path.with_name(path.name + '-saved')
            path.rename(saved)
            if target == 'provider':
                path.write_bytes(saved.read_bytes())
                path.chmod(0o700)
            else:
                # Keep the same files accessible through new directories. The
                # verifier must still reject a detached directory observation.
                import shutil
                shutil.copytree(saved, path)
        return result
    monkeypatch.setattr(artifact._Reader, 'read', read)
    with pytest.raises(artifact.ArtifactError, match='^FILE_CHANGED$'):
        observe(store)


def test_earlier_component_mutation_is_detected_after_closure_read(store, monkeypatch):
    target = weight(store)
    original = artifact._Reader.read
    weight_completed = False
    def read(self, directory, name, *args, **kwargs):
        nonlocal weight_completed
        result = original(self, directory, name, *args, **kwargs)
        if weight_completed and name.startswith('sha256-'):
            target.write_bytes(b'x' * target.stat().st_size)
        if name == target.name:
            weight_completed = True
        return result
    monkeypatch.setattr(artifact._Reader, 'read', read)
    with pytest.raises(artifact.ArtifactError, match='^FILE_CHANGED$'):
        observe(store)


@pytest.mark.parametrize('raw', [b'{"schemaVersion":NaN}', b'\xff', b'[]'])
def test_malformed_manifest_is_refused_without_echoing_contents(store, raw):
    store[1].write_bytes(raw)
    with pytest.raises(artifact.ArtifactError, match='^INVALID_MANIFEST$'):
        observe(store)


def test_budget_and_deadline_refuse_without_acceptance(store, monkeypatch):
    monkeypatch.setattr(artifact, 'MAX_TOTAL_BYTES', 8)
    with pytest.raises(artifact.ArtifactError, match='^TOTAL_BYTES_LIMIT$'):
        observe(store)
    ticks = iter([0, artifact.MAX_SECONDS + 1])
    with pytest.raises(artifact.ArtifactError, match='^VERIFICATION_DEADLINE$'):
        observe(store, clock=lambda: next(ticks))


@pytest.mark.parametrize('profile',[None,True,{},'unbounded','standard\n','96GiB'])
def test_unknown_profiles_cannot_choose_arbitrary_budgets(store,monkeypatch,profile):
    monkeypatch.setattr(os,'open',lambda *_a,**_k:pytest.fail('invalid profile opened a file'))
    with pytest.raises(artifact.ArtifactError,match='^INVALID_VERIFICATION_PROFILE$'):
        observe(store,verification_profile=profile)


@pytest.mark.parametrize('profile,total,seconds',[
    ('standard',32*1024**3,120),('large-local',96*1024**3,300)])
def test_named_profile_reports_fixed_limits_and_enforces_deadline(store,profile,total,seconds):
    value=observe(store,verification_profile=profile)
    assert value['verification_limits']==dict(profile=profile,max_total_bytes=total,max_seconds=seconds,chunk_bytes=1024**2)
    assert value['binding_status']=='UNBOUND' and not any(value['authority'].values())
    ticks=iter([0,seconds+1])
    with pytest.raises(artifact.ArtifactError,match='^VERIFICATION_DEADLINE$'):
        observe(store,verification_profile=profile,clock=lambda:next(ticks))


@pytest.mark.parametrize('profile,total',[('standard',32*1024**3),('large-local',96*1024**3)])
def test_over_budget_closure_refuses_before_reading_any_blob(store,monkeypatch,profile,total):
    change_manifest(store,lambda x:x['layers'][0].update(size=total+1))
    original=artifact._Reader.read
    def read(self,directory,name,*args,**kwargs):
        assert not name.startswith('sha256-'),'over-budget model read a blob'
        return original(self,directory,name,*args,**kwargs)
    monkeypatch.setattr(artifact._Reader,'read',read)
    with pytest.raises(artifact.ArtifactError,match='^TOTAL_BYTES_LIMIT$'):
        observe(store,verification_profile=profile)


@pytest.mark.parametrize('entry',['local_model_artifact.py','qwen_local_artifact.py'])
def test_cli_failure_has_fixed_code_and_no_path_or_raw_text(store,entry):
    root = Path(__file__).parents[1]
    result = subprocess.run([sys.executable, str(root / 'tools' / entry),
        '--store', str(store[0]), '--provider', str(store[2]), '--model', 'qwen2.5:7b-instruct-fp16',
        '--manifest-sha256', '0' * 64], capture_output=True, text=True, timeout=5)
    assert result.returncode == 2 and not result.stderr
    value = json.loads(result.stdout)
    assert value['error_code'] == 'MANIFEST_PIN_MISMATCH' and value['binding_status'] == 'UNBOUND'
    assert str(store[0]) not in result.stdout
