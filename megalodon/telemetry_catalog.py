"""Shared, non-executing feature/data map. Capability is not runtime availability."""
from html import escape

# id, feature, source, update mode, local workspace target
FEATURES = (
 ('traffic','Traffic charts and findings','Qualified core metadata; up to 500 event and 200 finding candidates','Configured refresh; 5 seconds by default','room-home-title'),
 ('globe','Globe and traffic-volume lanes','Rolling-hour metadata and optional approximate offline IP locations','Configured refresh; selected minute within rolling hour','activity-globe-title'),
 ('evidence','Ingestion evidence','Source-qualified committed ingestion receipts','Startup request; source selection or retry','ingestion-runs-title'),
 ('offline','Offline packet / flow analysis','Explicitly selected TShark or Zeek summary','Startup snapshot; restart to load a different file','offline-title'),
 ('suricata','Suricata alerts','Separately selected durable external-alert store','Startup snapshot; no sensor polling','suricata-title'),
 ('advisory','Legacy Qwen advisory','Explicitly supplied display-only receipt','Startup snapshot; not live AI analysis','analysis-window-title'),
 ('ai','AI questions and provider status','Opt-in token-gated local provider and private receipts','Only on explicit request','deep-analysis-title'),
 ('reference','Service and protocol reference','Verified bundled IANA registrations','On explicit lookup; not network service discovery','reference-title'),
 ('tools','Companion presence and processes','Bounded local executable/process observations','60-second heartbeat while visible; not sensor health','setup-title'),
 ('management','Tool installation / service jobs','Fixed optional installer job status','2 seconds while a job runs; independently observed','tool-management-controls'),
 ('reports','Reports and hosted summary','Validated bounded metadata, held for preview/download','Explicit local export; hosted import remains a saved snapshot','room-reports-title'),
 ('viewer','Companion app viewer','User-selected companion console URL','App-owned UI; does not connect its telemetry','app-viewer-title'),
 ('automation','Action scripts and time preview','Closed command references and recurrence calculation','On explicit preview; no scheduled job or action','action-plane-title'),
 ('exchange','Threat context / SIEM / SOAR','Offline STIX reader, local SIEM exporter; SOAR contract only','Explicit offline operations; no remote feed or delivery','integrations-title'),
)
TOOLS = (
 ('core','Python + SQLite','Qualified core traffic and finding projection','Refreshing stored metadata'),
 ('tshark','TShark / Wireshark','Completed offline capture analysis','Selected startup summary; no live tool feed'),
 ('zeek','Zeek','Completed conn.log analysis','Selected startup summary; flow units stay separate'),
 ('suricata','Suricata','Committed external alert publications','Selected startup snapshot'),
 ('scapy','Scapy','Optional separately operated metadata capture','Core projection after qualified ingestion'),
 ('qwen','Qwen / Ollama','Explicit local AI requests and advisory receipts','On demand; presence is not model readiness'),
 ('nftables','nftables','Deterministic response-plan evidence','No live firewall telemetry or application'),
 ('clamav','ClamAV','Presence/process observation only','Scan-result adapter not implemented'),
 ('osquery','osquery','Presence/process observation only','Inventory adapter not implemented'),
 ('nmap','Nmap','Presence/process observation only','Report adapter not implemented'),
 ('ossec','OSSEC','Presence/process observation only','Alert adapter not implemented'),
 ('greenbone','Greenbone','Presence/process observation only','Vulnerability-report adapter not implemented'),
 ('zabbix','Zabbix','Presence/process observation only','Monitoring-data adapter not implemented'),
 ('nagios','Nagios Core','Presence/process observation only','Monitoring-data adapter not implemented'),
)


def coverage_html(hosted=False):
    prefix = 'http://127.0.0.1:8787/' if hosted else ''
    extra = ' target="_blank" rel="noopener noreferrer"' if hosted else ''
    rows = ''.join(f'<tr><th scope="row"><a href="{prefix}#{escape(target)}"{extra}>{escape(name)}</a></th><td>{escape(source)}</td><td>{escape(mode)}</td></tr>' for _,name,source,mode,target in FEATURES)
    tool_rows = ''.join(f'<tr><th scope="row">{escape(name)}</th><td>{escape(source)}</td><td>{escape(mode)}</td></tr>' for _,name,source,mode in TOOLS)
    note = 'This hosted page receives saved summaries and readiness imports only. Open the local HUD on the same computer for local readings.' if hosted else 'These are supported data paths, not a claim that a source is currently connected. Check each view for its latest observation and scope.'
    return f'''<section class="telemetry-coverage" aria-labelledby="telemetry-coverage-title">
<h3 id="telemetry-coverage-title">Data connections and coverage</h3><p>{note}</p>
<details><summary>Feature data sources and refresh</summary><div class="telemetry-table" tabindex="0" role="region" aria-label="Feature data connections"><table><thead><tr><th>Feature</th><th>Data source</th><th>Update behavior</th></tr></thead><tbody>{rows}</tbody></table></div></details>
<details><summary>All 14 companions: telemetry support</summary><p>Installation, an observed process or a saved console link does not establish a working data adapter.</p><div class="telemetry-table" tabindex="0" role="region" aria-label="Companion telemetry coverage"><table><thead><tr><th>Companion</th><th>Available data path</th><th>Scope / remaining gap</th></tr></thead><tbody>{tool_rows}</tbody></table></div></details>
</section>'''

COVERAGE_CSS = r'''
.telemetry-coverage { margin:20px 0; border:1px solid #385363; padding:18px; border-radius:10px; background:#0b202c; color:#e7f4fa; }
.telemetry-coverage h3 { margin:0 0 12px; }
.telemetry-coverage p { color:#b9ceda; font-size:.875rem; }
.telemetry-coverage summary { cursor:pointer; padding:12px 0; min-height:44px; font-size:1rem; }
.telemetry-table { overflow:auto; max-width:100%; }
.telemetry-table table { width:100%; border-collapse:collapse; font-size:.875rem; }
.telemetry-table td,.telemetry-table th { padding:12px; border-bottom:1px solid #314a5b; text-align:left; vertical-align:top; min-width:160px; }
.telemetry-table th { color:#d5eeef; }
.telemetry-readings { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; }
.telemetry-readings article { border:1px solid #385363; border-radius:8px; padding:14px; min-width:0; }
.telemetry-readings strong,.telemetry-readings span { display:block; overflow-wrap:anywhere; }
.telemetry-readings span { font-size:.875rem; color:#b9ceda; margin-top:8px; }
@media(max-width:650px) { .telemetry-readings { grid-template-columns:1fr; } }
'''
