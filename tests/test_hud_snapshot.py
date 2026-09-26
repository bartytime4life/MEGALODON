"""Exercise the real read-only export and browser import contract together."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import pytest
from megalodon.hud_snapshot import main, snapshot_from_projection
from megalodon.dashboard_traffic import TrafficDashboardStore, unavailable
from megalodon.models import PacketEvent, DetectionResult, ActionRecord
from megalodon.storage import Store


def test_export_projection_roundtrip_and_privacy(tmp_path, capsys):
    path = tmp_path / 'private' / 'audit.db'
    now = datetime.now(timezone.utc)
    with Store(path) as writer:
        run = writer.start_ingestion_run('jsonl', started_at=now)
        for severity in ('LOW', 'HIGH'):
            event = PacketEvent(now, '192.0.2.1', '198.51.100.1', 'TCP', byte_count=2**63-1)
            findings = [DetectionResult(now, 'PORT_SCAN', severity, '192.0.2.1', '198.51.100.1', 'PRIVATE_TEXT', {}, 'PRIVATE_RECOMMENDATION')]
            writer.record_event_bundle(event, findings, [ActionRecord(now, 'block', '192.0.2.1', 'not_attempted', 'PRIVATE_REASON')], run_id=run)
        writer.finish_ingestion_run(run, 'source_exhausted', finished_at=now)
        before = writer.summary()
        assert main(['--database',str(path)]) == 0
        text = capsys.readouterr().out
        value = json.loads(text)
        assert value['lanes'] == [0,1,1]
        assert value['reported_bytes'] == str(2*(2**63-1))
        assert value['events'] == sum(value['timeline']) == 2
        assert all(secret not in text for secret in ('192.0.2','198.51.100','PRIVATE_',str(path)))
        assert writer.summary() == before
        node = shutil.which('node')
        if node:
            script = "const {validateHudSnapshot}=require('./site/dist/snapshot.js');let s='';process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>{const x=validateHudSnapshot(s);if(x.events!==2)process.exit(1);});"
            subprocess.run([node,'-e',script], input=text,text=True,check=True,cwd=Path(__file__).resolve().parents[1])


def test_no_export_for_unqualified_or_missing_database(tmp_path, capsys):
    with pytest.raises(ValueError):
        snapshot_from_projection(unavailable())
    assert main(['--database',str(tmp_path/'missing.db')]) == 1
    assert not (tmp_path/'missing.db').exists()
    assert capsys.readouterr().out == ''


def test_highest_severity_counts_each_event_once():
    projection={'status':'available','generated_at':'2026-01-01T00:00:00Z','window':{'start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:00:00Z'},'truncated':False,'quality':'unknown',
      'events':[{'id':'1','observed_at':'2026-01-01T00:00:00Z','byte_count':'0','protocol':'TCP','source':'jsonl'}],
      'findings':[{'event_id':'1','severity':s,'rule_id':'PORT_SCAN'} for s in ('LOW','HIGH','CRITICAL')]}
    assert snapshot_from_projection(projection)['lanes']==[0,0,1]
