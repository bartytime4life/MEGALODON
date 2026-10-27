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
        # A prior result after a rejected or failed run is stale, not available.
        completed=message.endswith(' · completed; saved aggregate')
        state='collecting' if collecting else 'connected' if result and completed else 'error' if result else 'needs_setup'
        if key=='clamav' and result and completed and not collecting and result['infected_files']>0:
            state='needs_review'
            message='Saved scan flagged files. Review the scan summary and original scan evidence before taking action. '+message
        add(key,name,state,message[:512],stamp,metrics)
    if hasattr(configuration,'model_telemetry'):
        observed=configuration.model_telemetry.snapshot()
        qwen={k:observed[k] for k in ('state','message','updated_at')};qwen['metrics']=[]
        if observed.get('response_ms') is not None:qwen['metrics'].append(metric('Last attempt duration',observed['response_ms'],'ms'))
        if observed.get('memory_bytes') is not None:qwen['metrics'].append(metric('Loaded allocation',observed['memory_bytes']/1024**3,'GiB'))
        if observed.get('vram_bytes') is not None:qwen['metrics'].append(metric('GPU allocation',observed['vram_bytes']/1024**3,'GiB'))
    else:qwen=dict(configuration.qwen_status)
    # Count completed answers; availability does not establish persistence.
    good=[v for v in data['advisory'].values() if v and not v.startswith(('Qwen unavailable','Local AI unavailable','Local AI advice queued'))]
    if good:
        # An available answer reflects past use, not current provider readiness.
        qwen['metrics']=[*qwen.get('metrics',[]),metric('Available summaries with advice',len(good))]
    add('qwen','Local AI via Ollama',**qwen)
    security=getattr(configuration,'host_security',None)
    summary=security.snapshot() if security is not None else {}
    for key,label,field in [('lynis','Lynis','audit'),('aide','AIDE','integrity')]:
        saved=summary.get(field)
        unavailable=summary.get(field+'_state')=='unavailable'
        metrics=([metric('Configuration warnings',saved['metrics']['warnings']),metric('Hardening suggestions',saved['metrics']['suggestions'])]
                 if saved and field=='audit' else [])
        add(key,label,'error' if unavailable else 'connected' if saved else 'needs_setup',
            'Saved host evidence is unavailable; review Host findings in Setup.' if unavailable else
            saved['message'] if saved else 'Use Host security in Setup to run an explicit local check.',
            saved['checked_at'] if saved else None,metrics)
    return dict(schema='megalodon-support-workflows-v1',observed_at=now(),mode='background',tools=tools)
