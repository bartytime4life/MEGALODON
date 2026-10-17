"""Synthetic private-store restart tests; no native HUD or host actions."""
from copy import deepcopy
import json
import os
import socket
import subprocess
from threading import Thread
from types import SimpleNamespace

import pytest

from megalodon import ai_provider
from megalodon.ai_broker import BrokerError
from megalodon.config import Settings
from megalodon.evidence_storage import EvidenceStorage, GIB, utc
from megalodon.intelligence import IntelligenceService
from megalodon.managed_receipts import ManagedReceipts

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='Local Linux managed evidence')


@pytest.fixture
def manager(private_tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('Recovery must not start a thread, process, model or network operation')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)
    monkeypatch.setattr(Thread, 'start', forbidden)
    monkeypatch.setattr(ai_provider, 'generate', forbidden)
    monkeypatch.setattr(ai_provider, 'last_observation', lambda _: {})
    value = EvidenceStorage(Settings(db_path=private_tmp_path/'old.db'), home=private_tmp_path,
                            clock=lambda: 1800000000.0, monotonic=lambda: 100.0)
    value.apply(value.preview(dict(profile='home', retention_days=14, cap_bytes=20*GIB))['preview_id'])
    yield value
    value.close()


def restart(manager):
    return EvidenceStorage(manager.settings, home=manager.home,
                           clock=manager.clock, monotonic=manager.monotonic)


def interrupted(manager, edit=None):
    # Flush/close SQLite handles, then restore the pre-close catalog. This
    # models committed data with an open unit, without killing a real process.
    catalog = deepcopy(manager._catalog)
    manager.close()
    if edit is not None:
        edit(catalog)
    manager.catalog_path.write_text(json.dumps(catalog))


def database_bytes(manager):
    return {path.name: path.read_bytes() for path in manager.root.glob('*.db')}


def observe_model(manager):
    service = IntelligenceService(manager, None, SimpleNamespace(settings=manager.settings))
    service.observe_model()  # Existing producer; reads only the mocked cached observation.


@pytest.mark.parametrize('mixed', [False, True])
def test_current_model_observations_survive_audit_recovery(manager, mixed):
    observe_model(manager)
    originals = {}
    if mixed:
        for channel in ('qwen', 'defense'):
            ledger = ManagedReceipts(manager, channel)
            ledger.append('done', dict(state='not_attempted', action='analyze'))
            ledger.append('done', dict(state='observed', action='analyze', result={'synthetic': True}))
            ledger.append('pending', dict(state='not_attempted', action='apply_containment'))
            originals[channel] = ledger.recent()
    checkpoint = manager.checkpoint('patterns_model')
    interrupted(manager)
    before = database_bytes(manager)
    again = restart(manager)
    try:
        entry = again._catalog['entries'][0]
        assert entry['pending_receipts'] == (2 if mixed else 0)
        assert entry['state'] == ('open' if mixed else 'closed')
        assert again.checkpoint('patterns_model') == checkpoint
        assert database_bytes(again) == before
        observations = [row for row in again.history(category='audit')['records']
                        if row['source'] == 'local-model-observation-v1']
        assert len(observations) == 1
        assert 'state' not in observations[0]['data']
        for channel in ('qwen', 'defense'):
            ledger = ManagedReceipts(again, channel)
            assert ledger.verify_chain()['incomplete_count'] == int(mixed)
            ledger.reconcile_interrupted()
            head = ledger.verify_chain()
            assert head['incomplete_count'] == 0
            if mixed:
                assert ledger.recent()[:3] == originals[channel]
                assert ledger.latest('done')['state'] == 'observed'
                terminal = ledger.latest('pending')
                assert terminal['state'] == 'failed'
                assert terminal['outcome'] == 'unknown_after_restart'
                assert terminal['host_attempted'] is True
            else:
                assert head['sequence'] == 0 and ledger.recent() == []
            ledger.reconcile_interrupted()
            assert ledger.verify_chain() == head  # No replay or duplicate terminal receipt.
        assert all(path.stat().st_mode & 0o077 == 0 for path in again.root.iterdir())
    finally:
        again.close()


@pytest.mark.parametrize('invalid', ['missing', None, 'unknown', [], 1, 'not_an_entry'])
def test_catalog_state_refusal_precedes_all_recovery_and_preserves_files(manager, monkeypatch, invalid):
    manager.append_records('network', [dict(observed_at=utc(manager.clock()), source='fixture', data={})])
    observe_model(manager)
    def edit(catalog):
        catalog['entries'][0]['state'] = 'deleting'
        if invalid == 'missing':
            catalog['entries'][1].pop('state')
        elif invalid == 'not_an_entry':
            catalog['entries'][1] = None
        else:
            catalog['entries'][1]['state'] = invalid
    interrupted(manager, edit)
    before, catalog = database_bytes(manager), manager.catalog_path.read_bytes()
    def forbidden(*args):
        pytest.fail('Incomplete catalog must be refused before recovery or deletion')
    monkeypatch.setattr(EvidenceStorage, '_recover_open', forbidden)
    monkeypatch.setattr(EvidenceStorage, '_recover_deletion', forbidden)
    for _ in range(2):  # Failed startup also releases the exclusive lease.
        with pytest.raises(ValueError, match='catalog entry.*recovery requires review'):
            restart(manager)
        assert database_bytes(manager) == before
        assert manager.catalog_path.read_bytes() == catalog


@pytest.mark.parametrize('channel', ['qwen', 'defense'])
@pytest.mark.parametrize('corruption', ['state_missing', 'state_list', 'unknown_state',
    'id_missing', 'id_list', 'sequence_bool', 'hash_missing', 'null', 'list', 'bad_json'])
def test_malformed_action_receipts_stay_protected_and_never_verify_as_empty(manager, channel, corruption):
    ManagedReceipts(manager, channel).append('pending', dict(state='not_attempted', action='analyze'))
    entry = deepcopy(manager._catalog['entries'][0])
    interrupted(manager, lambda c: c.update(checkpoints={}))
    with manager._db(entry, write=True) as db:
        data = json.loads(db.execute('SELECT data FROM records').fetchone()[0])
        if corruption == 'state_missing': data.pop('state')
        elif corruption == 'state_list': data['state'] = []
        elif corruption == 'unknown_state': data['state'] = 'maybe_applied'
        elif corruption == 'id_missing': data.pop('receipt_id')
        elif corruption == 'id_list': data['receipt_id'] = []
        elif corruption == 'sequence_bool': data['sequence'] = True
        elif corruption == 'hash_missing': data.pop('event_hash')
        elif corruption == 'null': data = None
        elif corruption == 'list': data = []
        raw = '{' if corruption == 'bad_json' else json.dumps(data)
        db.execute('UPDATE records SET data=?', (raw,)); db.commit()
    before = database_bytes(manager)
    again = restart(manager)
    try:
        entry = again._catalog['entries'][0]
        assert entry['state'] == 'needs_review'
        assert again.snapshot()['state'] == 'needs_review'
        assert 'recovery review' in again.snapshot()['message']
        assert again._catalog['checkpoints'] == {}  # No unverified checkpoint adoption.
        assert 'audit' not in again._generic
        for source in ('qwen', 'defense'):
            ledger = ManagedReceipts(again, source)
            for read in (ledger.verify_chain, ledger.reconcile_interrupted, ledger.recent,
                         lambda: ledger.latest('pending')):
                with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'):
                    read()
            with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'):
                ledger.append('new', dict(state='not_attempted', action='analyze'))
        again._ensure_space()
        assert database_bytes(again) == before
    finally:
        again.close()
    assert database_bytes(manager) == before


@pytest.mark.parametrize('channel', ['qwen', 'defense'])
@pytest.mark.parametrize('corruption', ['payload', 'hash', 'sequence', 'checkpoint'])
def test_structurally_valid_tampering_refuses_reconciliation_without_writes(manager, channel, corruption):
    ledger = ManagedReceipts(manager, channel)
    ledger.append('pending', dict(state='not_attempted', action='analyze'))
    entry = deepcopy(manager._catalog['entries'][0])
    interrupted(manager)
    with manager._db(entry, write=True) as db:
        data = json.loads(db.execute('SELECT data FROM records').fetchone()[0])
        if corruption == 'payload': data['action'] = 'changed'
        elif corruption == 'hash': data['event_hash'] = 'f'*64
        elif corruption == 'sequence': data['sequence'] += 1
        else:
            checkpoint = json.loads(db.execute('SELECT value FROM checkpoints').fetchone()[0])
            checkpoint['head'] = 'f'*64
            db.execute('UPDATE checkpoints SET value=?', (json.dumps(checkpoint),))
        db.execute('UPDATE records SET data=?', (json.dumps(data),)); db.commit()
    before = database_bytes(manager)
    again = restart(manager)
    try:
        ledger = ManagedReceipts(again, channel)
        with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'): ledger.verify_chain()
        with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'): ledger.reconcile_interrupted()
        with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'):
            ledger.append('new', dict(state='not_attempted', action='analyze'))
        assert database_bytes(again) == before
    finally:
        again.close()


@pytest.mark.parametrize('field', ['audit_boundaries', 'boundary', 'checkpoint'])
@pytest.mark.parametrize('value', [[], {}, 'invalid', 1])
def test_malformed_chain_metadata_is_a_controlled_failure(manager, field, value):
    ledger = ManagedReceipts(manager, 'defense')
    ledger.append('pending', dict(state='not_attempted', action='analyze'))
    if field == 'audit_boundaries':
        if value == {}: value = None
        manager._catalog[field] = value
    elif field == 'boundary': manager._catalog['audit_boundaries']['audit_defense'] = value
    else: manager._catalog['checkpoints']['audit_defense'] = value
    before = deepcopy(manager._catalog)
    with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'): ledger.reconcile_interrupted()
    assert manager._catalog == before


def test_supported_optional_catalog_defaults_preserve_valid_pending_chain(manager):
    ledger = ManagedReceipts(manager, 'defense')
    ledger.append('pending', dict(state='not_attempted', action='analyze'))
    original = ledger.recent()
    def edit(catalog):
        for key in ('audit_boundaries', 'started_at', 'checkpoint_generation'):
            catalog.pop(key, None)
    interrupted(manager, edit)
    again = restart(manager)
    try:
        ledger = ManagedReceipts(again, 'defense')
        assert ledger.recent() == original
        assert ledger.verify_chain()['incomplete_count'] == 1
        ledger.reconcile_interrupted()
        assert ledger.recent()[0] == original[0]
        assert ledger.latest('pending')['outcome'] == 'unknown_after_restart'
    finally:
        again.close()


@pytest.mark.parametrize('bad_checkpoint', [None, [], {}, {'sequence': []}, {'generation': 'old'},
    {'head': '0'*64, 'sequence': True}, {'head': '0'*64, 'sequence': 0, 'pending': [[]]}, '{'])
def test_malformed_persisted_checkpoint_does_not_partially_promote_recovery(manager, bad_checkpoint):
    ledger = ManagedReceipts(manager, 'defense')
    ledger.append('pending', dict(state='not_attempted', action='analyze'))
    entry = deepcopy(manager._catalog['entries'][0])
    interrupted(manager, lambda c: c.update(checkpoints={}))
    with manager._db(entry, write=True) as db:
        raw = bad_checkpoint if bad_checkpoint == '{' else json.dumps(bad_checkpoint)
        # Insert after the valid checkpoint so partial adoption is detectable.
        db.execute('INSERT INTO checkpoints VALUES(?,?)', ('audit_qwen', raw)); db.commit()
    before = database_bytes(manager)
    again = restart(manager)
    try:
        assert again._catalog['entries'][0]['state'] == 'needs_review'
        assert again._catalog['checkpoints'] == {}
        with pytest.raises(BrokerError, match='AUDIT_INTEGRITY'):
            ManagedReceipts(again, 'defense').reconcile_interrupted()
        assert database_bytes(again) == before
    finally:
        again.close()


def test_hud_cli_reports_catalog_failure_without_a_traceback(manager, monkeypatch, capsys):
    from megalodon import cli, dashboard
    observe_model(manager)
    interrupted(manager, lambda c: c['entries'][0].pop('state'))
    monkeypatch.setattr(cli, '_load', lambda _: manager.settings)
    def serve(*args, **kwargs):
        restart(manager)  # Reach storage admission without opening a HUD socket.
    monkeypatch.setattr(dashboard, 'serve', serve)
    with pytest.raises(SystemExit) as exc:
        cli.main(['hud', '--no-auto-companions'])
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert 'recovery requires review' in output.err and 'Traceback' not in output.err
