"""Shared, non-executing feature/data map. Capability is not runtime availability."""
from html import escape

# id, feature, source, update mode, local workspace target
FEATURES = (
 ('host-resources','Live PC resources and interface rates','Read-only Linux CPU, memory, process, interface and socket counters','Every 2 seconds; up to 10 minutes of memory-only history','pc-live-title'),
 ('traffic','Traffic charts and findings','Newest qualified packet window or retained packet detail / compact summaries','5-second latest refresh; bounded historical pages on request','room-home-title'),
 ('globe','Live connection globe','Captured directions and approximate offline IP locations','Live / recently retained conversations; unavailable locations remain unmapped','activity-globe-title'),
 ('evidence','Ingestion evidence','Source-qualified committed ingestion receipts','Startup request; source selection or retry','ingestion-runs-title'),
 ('offline','Offline packet / flow analysis','Explicitly selected TShark or Zeek summary','Startup snapshot; restart to load a different file','offline-title'),
 ('suricata','Suricata','Configured EVE flow and alert intake; separate legacy durable-store view','Managed source checkpoints; permission and source gaps remain explicit'),
 ('advisory','Legacy Qwen advisory','Explicitly supplied display-only receipt','Startup snapshot; not live AI analysis','analysis-window-title'),
 ('ai','AI questions and provider status','Opt-in token-gated local provider and private receipts','Only on explicit request','deep-analysis-title'),
 ('reference','Service and protocol reference','Verified bundled IANA registrations','On explicit lookup; not network service discovery','reference-title'),
 ('tools','Companion presence and processes','Bounded local executable/process observations','60-second heartbeat while visible; not sensor health','setup-title'),
 ('management','Tool installation / service jobs','Fixed optional installer job status','2 seconds while a job runs; independently observed','tool-management-controls'),
 ('inventory','Network inventory','Local fixed Nmap loopback scan or watched completed XML report','Local HUD collects hourly when Nmap is installed; reports checked every 15 seconds','inventory-title'),
 ('clamav-scan','Completed file scan','Local fixed ClamAV Downloads scan or watched completed report','Local HUD scans daily when ClamAV and Downloads exist; reports checked every 15 seconds','clamav-title'),
 ('osquery-count','Package inventory','Local fixed osquery DEB row count or watched completed result','Local HUD collects hourly when osquery is installed; reports checked every 15 seconds','osquery-title'),
 ('topology','Local network topology','This PC, routes, neighbors, captured peers and optional authorized discovery','Passive snapshots; selected host discovery every 15 minutes','network-title'),
 ('storage','Managed storage and compact history','Catalog, SQLite sidecars, managed working files and retained evidence','Automatic age / byte accounting and verified compact-history rotation','storage-evidence-title'),
 ('reports','Visual local reports','Selected dates across retained evidence and verified compact summaries','Daily at 9 AM local by default; on-demand generation and cached downloads','room-reports-title'),
 ('viewer','Companion app viewer','User-selected companion console URL','App-owned UI; does not connect its telemetry','app-viewer-title'),
 ('automation','Action scripts and time preview','Closed command references and recurrence calculation','On explicit preview; no scheduled job or action','action-plane-title'),
 ('exchange','Threat context / SIEM / SOAR','Offline STIX reader, local SIEM exporter; SOAR contract only','Explicit offline operations; no remote feed or delivery','integrations-title'),
)
TOOLS = (
 ('core','Python + SQLite','Qualified core traffic and finding projection','Refreshing stored metadata'),
 ('tshark','TShark / Wireshark','Background header-only packet metadata and optional offline analysis','Configured interface and permissions; capture state and accepted data are separate'),
 ('zeek','Zeek','Managed background conn.log summaries or selected offline log','Source-qualified flow updates; not added to packet counts'),
 ('suricata','Suricata','Configured EVE flow and alert intake; separate legacy durable-store view','Managed source checkpoints; permission and source gaps remain explicit'),
 ('scapy','Scapy','Optional separately operated metadata capture','Core projection after qualified ingestion'),
 ('qwen','Qwen / Ollama','Explicit local AI requests and advisory receipts','On demand; presence is not model readiness'),
 ('nftables','nftables','Operator-reviewed temporary containment and response evidence','Fixed local defense workflow, OS authorization, readback and release'),
 ('clamav','ClamAV','Configured local folder scan and completed-report watcher','Saved scanned / matched counts; signature update in Setup; no automatic quarantine'),
 ('osquery','osquery','Local fixed DEB count and completed-result watcher','Aggregate count only; no daemon or arbitrary query pack'),
 ('nmap','Nmap','Configured inventory scan, report watcher and selected-scope host discovery','Loopback inventory by default; LAN discovery requires selected authorized scope'),
)


def coverage_html(hosted=False):
    if hosted:
        hosted_overrides = {
            'host-resources': ('Live PC resources and interface rates', 'Local HUD only; no hosted PC access'),
            'traffic': ('Traffic charts and findings', 'Local HUD refreshes by configuration; hosted summary updates only when loaded'),
            'reports': ('Reports and local summary export', 'Explicit local export; saved summary can be loaded in this tab'),
            'inventory': ('Network inventory', 'Local HUD only; hosted Site cannot read this PC'),
            'clamav-scan': ('Completed file scan', 'Local HUD only; hosted Site cannot read this PC'),
            'osquery-count': ('Package inventory', 'Local HUD only; hosted Site cannot read this PC'),
        }
        rows = ''.join(
            f'<tr><th scope="row">{escape(hosted_overrides.get(identifier, (name, mode))[0])}</th><td>{escape(source)}</td><td>{escape(hosted_overrides.get(identifier, (name, mode))[1])}</td></tr>'
            for identifier,name,source,mode,_ in FEATURES
        )
    else:
        rows = ''.join(f'<tr><th scope="row"><a href="#{escape(target)}">{escape(name)}</a></th><td>{escape(source)}</td><td>{escape(mode)}</td></tr>' for _,name,source,mode,target in FEATURES)
    tool_rows = ''.join(f'<tr><th scope="row">{escape(name)}</th><td>{escape(source)}</td><td>{escape(mode)}</td></tr>' for _,name,source,mode in TOOLS)
    note = 'This hosted page has no live local telemetry connection. A loaded traffic summary is a saved snapshot; local companion results stay in the local HUD.' if hosted else 'These are supported data paths, not a claim that a source is currently connected. Check each view for its latest observation and scope.'
    return f'''<section class="telemetry-coverage" aria-labelledby="telemetry-coverage-title">
<h3 id="telemetry-coverage-title">Data connections and coverage</h3><p>{note}</p>
<details><summary>Feature data sources and refresh</summary><div class="telemetry-table" tabindex="0" role="region" aria-label="Feature data connections"><table><thead><tr><th>Feature</th><th>Data source</th><th>Update behavior</th></tr></thead><tbody>{rows}</tbody></table></div></details>
<details><summary>All 10 companions: telemetry support</summary><p>These tools run locally without a vendor account. The built-in PC resource collector uses Linux counters and needs no extra install. <a href="https://www.wireshark.org/download.html" target="_blank" rel="noopener noreferrer">Wireshark / TShark</a>, <a href="https://suricata.io/our-story/suricata/" target="_blank" rel="noopener noreferrer">Suricata</a> and <a href="https://www.clamav.net/" target="_blank" rel="noopener noreferrer">ClamAV</a> are free local software; optional commercial services are not required.</p><p>Installation, an observed process or a saved console link does not establish a working data adapter.</p><div class="telemetry-table" tabindex="0" role="region" aria-label="Companion telemetry coverage"><table><thead><tr><th>Companion</th><th>Available data path</th><th>Scope / remaining gap</th></tr></thead><tbody>{tool_rows}</tbody></table></div></details>
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
