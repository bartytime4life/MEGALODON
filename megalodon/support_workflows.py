"""Current HUD-owned workflow observations; reads never start tools."""
from .managed_capture import now
from .support_sensors import metric


def snapshot(configuration, companions):
    tools=[]
    def add(identifier,name,state,message,updated_at=None,metrics=None):
        tools.append(dict(id=identifier,name=name,state=state,message=message,updated_at=updated_at,metrics=metrics or []))
    add('core','Python and SQLite','connected','The local HUD, data store and resource sampler are running.',now())
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
    qwen=dict(configuration.qwen_status)
    good=[v for v in data['advisory'].values() if v and not v.startswith('Qwen unavailable')]
    if good:
        qwen.update(state='connected',message='Local Qwen returned advice for completed collector summaries. Advice cannot run commands.',metrics=[metric('Summaries with advice',len(good))])
    add('qwen','Qwen via local Ollama',**qwen)
    return dict(schema='megalodon-support-workflows-v1',observed_at=now(),mode='background',tools=tools)
