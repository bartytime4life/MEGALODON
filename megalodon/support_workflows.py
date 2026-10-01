"""Current HUD-owned workflow observations; reads never start tools."""
from .managed_capture import now
from .support_sensors import metric


def snapshot(configuration, companions):
    tools=[]
    def add(identifier,name,state,message,updated_at=None,metrics=None):
        tools.append(dict(id=identifier,name=name,state=state,message=message,updated_at=updated_at,metrics=metrics or []))
    add('core','Python and SQLite','connected','The local HUD is responding. Storage and source health are reported separately.',now())
    capture=configuration.capture.snapshot()
    add('tshark','Wireshark / TShark','connected' if capture['accepted'] and capture['state']=='running' else
        'collecting' if capture['state'] in ('starting','running') else 'error' if capture['state']=='failed' else 'stopped',
        capture['message'],capture['started_at'],[metric('Accepted this session',capture['accepted']),metric('Skipped',capture['skipped'])])
    sensors=configuration.sensors.snapshot()
    for key,name in (('zeek','Zeek'),('suricata','Suricata')):
        add(key,name,**sensors[key])
    add('scapy','Scapy','standby','Alternative capture engine. TShark already supplies live packets, so a second Python capture is unnecessary.')
    add('nftables','nftables','standby','Local containment is available from the IP inspector after preview and OS authorization. Startup and model output do not change firewall rules.')
    data=companions.snapshot() if companions else dict(results={},status={},advisory={})
    for key,name in (('clamav','ClamAV'),('osquery','osquery'),('nmap','Nmap')):
        result=data['results'].get(key)
        message=data['status'].get(key,'Collector unavailable.')
        metrics=[]; stamp=None
        if result:
            if key=='clamav':
                metrics=[metric('Scanned files',result['scanned_files']),metric('Flagged files',result['infected_files']),metric('Scan errors',result['errors'])]
                stamp=result.get('exported_at')
            elif key=='osquery':
                metrics=[metric('Installed packages',result['package_rows'])]; stamp=result.get('collection_completed_at')
            else:
                metrics=[metric('Hosts up',result['hosts'][0]),metric('Hosts down',result['hosts'][1])]; stamp=result.get('finished_at')
        collecting=any(word in message.lower() for word in ('scanning','collecting','queued','waiting'))
        state='collecting' if collecting else 'connected' if result else 'needs_setup'
        add(key,name,state,message[:512],stamp,metrics)
    if hasattr(configuration,'model_telemetry'):
        observed=configuration.model_telemetry.snapshot()
        qwen={k:observed[k] for k in ('state','message','updated_at')};qwen['metrics']=[]
        if observed.get('response_ms') is not None:qwen['metrics'].append(metric('Last request',observed['response_ms'],'ms'))
        if observed.get('memory_bytes') is not None:qwen['metrics'].append(metric('Loaded allocation',observed['memory_bytes']/1024**3,'GiB'))
        if observed.get('vram_bytes') is not None:qwen['metrics'].append(metric('GPU allocation',observed['vram_bytes']/1024**3,'GiB'))
    else:qwen=dict(configuration.qwen_status)
    good=[v for v in data['advisory'].values() if v and not v.startswith(('Qwen unavailable','Local AI unavailable'))]
    if good:
        # A saved answer is evidence of past use, not current provider readiness.
        qwen['metrics']=[*qwen.get('metrics',[]),metric('Saved summaries with advice',len(good))]
    add('qwen','Local AI via Ollama',**qwen)
    return dict(schema='megalodon-support-workflows-v1',observed_at=now(),mode='background',tools=tools)
