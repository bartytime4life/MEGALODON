"""Focused Setup navigation, composed once without moving live controls."""
import re

from .dashboard_operations import _take


def _take_match(html: str, pattern: str) -> tuple[str, str]:
    match = re.search(pattern, html)
    if not match:
        raise AssertionError(f"settings composition missing {pattern}")
    tag = re.match(r"<([a-z][a-z0-9-]*)", match[0])[1]
    depth = 0
    for token in re.finditer(r"</?" + tag + r"\b[^>]*>", html[match.start():]):
        depth += -1 if token[0].startswith("</") else 1
        if depth == 0:
            end = match.start() + token.end()
            return html[:match.start()] + html[end:], html[match.start():end]
    raise AssertionError("unclosed settings control")


def _inside(html: str) -> str:
    return html[html.index(">") + 1:html.rfind("</")]


def _disclosure(title: str, body: str, *, element_id: str = "") -> str:
    identity = f' id="{element_id}"' if element_id else ""
    return f'<details class="settings-disclosure"{identity}><summary>{title}</summary>{body}</details>'


def compose_settings(html: str) -> str:
    """Keep every established handler ID while giving settings one active view."""
    html, workspace = _take(html, "workspace-setup")
    content = _inside(workspace)
    content, support = _take(content, "support-config")
    content, apps = _take(content, "apps-connections")
    content, storage = _take(content, "storage-setup")
    content, knowledge = _take(content, "knowledge-setup")
    content, advanced = _take(content, "ops-advanced-setup")
    content, network = _take_match(content, r'<section class="network-setup"[^>]*>')
    content, geography = _take_match(content, r'<section class="ops-location-setup"[^>]*>')
    content, start = _take_match(content, r'<section class="hud-start"[^>]*>')
    content, _ = _take_match(content, r'<section class="ops-setup-shortcuts"[^>]*>')

    start, health = _take_match(start, r'<section class="setup-health"[^>]*>')
    start, software = _take_match(start, r'<section class="setup-software"[^>]*>')
    software, management = _take(software, "tool-management-controls")
    start, account = _take_match(start, r'<section class="setup-account"[^>]*>')
    start, launch = _take_match(start, r'<details class="setup-launch-help"[^>]*>')
    start, data = _take_match(start, r'<details class="setup-actions-card"[^>]*>')

    support, feedback = _take_match(support, r'<div class="support-config-feedback"[^>]*>')
    support, capture = _take_match(support, r'<section class="support-capture"[^>]*>')
    support, collectors = _take_match(support, r'<details class="support-collector-settings"[^>]*>')
    support, services = _take_match(support, r'<details class="support-service-settings"[^>]*>')
    services, model = _take_match(services, r'<section aria-labelledby="support-model-title"[^>]*>')
    support, security = _take(support, "support-host-security")
    support, directories = _take_match(support, r'<details class="support-config-locations"[^>]*>')
    support, results = _take_match(support, r'<details class="support-config-results"[^>]*>')

    storage, guidance = _take_match(storage, r'<aside class="storage-guidance"[^>]*>')
    storage, disk = _take_match(storage, r'<section class="storage-disk"[^>]*>')
    storage = storage[:storage.rfind('</section>')] + _disclosure('Choosing a history limit', guidance) + _disclosure('Disk activity and measurement limits', disk) + '</section>'
    for control in ('ki-enabled', 'ki-automatic', 'ki-updates'):
        knowledge = knowledge.replace(f'id="{control}" type="checkbox"', f'id="{control}" type="checkbox" class="settings-switch" role="switch"')

    # The ordinary workflow has one app directory. Rare software references and
    # terminal recipes remain reachable without competing with its live actions.
    software = software.replace('Software, without the guesswork', 'Software reference')
    software = re.sub(r'<p class="setup-download-note">.*?</p>', '', software, flags=re.S)
    apps = apps.replace('Apps &amp; connections', 'Installed apps').replace(
        '<p>Install, configure, and check each app here. Their current activity remains in Sensors and the HUD.</p>',
        '<p>Install a missing tool, configure it, or check its availability.</p>',
    )
    management = management.replace('Authorize Install, Start and Open', 'Installation session and terminal options')
    health = health.replace('<p class="setup-step">01 / CHECK YOUR COMPUTER</p>', '').replace(
        'Know what is ready', 'This computer').replace(
        'Read the local service, Python and SQLite versions, selected data store, and tool presence.',
        'Check the service, data store and available tools.',
    ).replace('Check this computer <span aria-hidden="true">→</span>', 'Check now')
    # Observation definitions are important, but do not belong in the default
    # decision path. The live status and check controls remain visible.
    health = re.sub(r'(<p id="setup-source".*?)(<button id="tool-check-now".*?</p>)',
                    lambda match: _disclosure('Observation details', match[1] + match[2]), health, flags=re.S)

    overview = '''<div class="settings-overview" aria-label="Current setup summary">
      <a href="#support-capture-title"><span>Traffic</span><strong id="settings-traffic-summary">Checking…</strong><small>Interface and capture</small><b aria-hidden="true">↗</b></a>
      <a href="#support-model-title"><span>Local AI</span><strong id="settings-model-summary">Checking…</strong><small id="settings-model-name">Saved model</small><b aria-hidden="true">↗</b></a>
      <a href="#apps-connections-title"><span>Apps</span><strong id="settings-apps-summary">Checking…</strong><small>Install and configure</small><b aria-hidden="true">↗</b></a>
    </div>''' + health
    traffic = capture + _disclosure('Background sensors · Zeek and Suricata',
        _inside(services).split('<div class="support-tool-settings">', 1)[1].rsplit('</div>', 1)[0])
    traffic += _disclosure('Device discovery', network) + _disclosure('IP location data', geography)
    app_body = apps + management + collectors + _disclosure('Host security and threat context', security)
    advanced_body = _disclosure('Local sign-in', account) + launch + data + directories + results
    advanced_body += _disclosure('Software reference and publisher guides', software) + advanced
    groups = [
        ('overview', 'Overview', 'Your local setup at a glance', overview),
        ('traffic', 'Traffic', 'Capture and local sensors', traffic),
        ('ai', 'Local AI', 'One saved model. A clear connection state.', model + _disclosure('Knowledge and automatic review', knowledge)),
        ('apps', 'Apps', 'The tools you choose to use', app_body),
        ('storage', 'Storage', 'Evidence and retained history', storage),
        ('advanced', 'Advanced', 'Launch, access and uncommon settings', advanced_body),
    ]
    nav = '<nav class="settings-nav" role="tablist" aria-label="Setup categories">' + ''.join(
        f'<a id="settings-tab-{key}" href="#setup-category-{key}" role="tab" aria-controls="setup-category-{key}" aria-selected="{str(index == 0).lower()}" tabindex="{0 if index == 0 else -1}"><span class="settings-nav-number" aria-hidden="true">{index + 1:02}</span>{title}<span aria-hidden="true">›</span></a>'
        for index, (key, title, _, _) in enumerate(groups)) + '</nav>'
    panels = ''.join(
        f'<section id="setup-category-{key}" class="settings-category" data-setup-category="{key}" role="tabpanel" aria-labelledby="settings-tab-{key}"{ " hidden" if index else ""}><header class="settings-category-heading"><h3 tabindex="-1">{title}</h3><p>{subtitle}</p></header>{body}</section>'
        for index, (key, title, subtitle, body) in enumerate(groups))
    opening = workspace[:workspace.index('>') + 1]
    workspace = opening + '''<section id="support-config" class="support-config settings-console" aria-labelledby="setup-title">
      <header class="settings-heading"><div><p class="eyebrow">MEGALODON / THIS COMPUTER</p><h2 id="setup-title" tabindex="-1">Setup<span class="settings-local">Local</span></h2><h4 id="support-config-title" class="sr-only" tabindex="-1">Configure local tools</h4></div><button type="button" id="support-config-close" class="button-secondary">Return to HUD <span aria-hidden="true">↗</span></button></header>
      ''' + feedback + '<div class="settings-layout">' + nav + '<div class="settings-content">' + panels + '</div></div></section></section>'
    # Preserve the original position of Setup in the workspace stack.
    marker = '<section class="workspace-view" id="workspace-reports"'
    if marker not in html:
        # The source order is stable, but allow a different attribute order.
        match = re.search(r'<section\b[^>]*id="workspace-reports"', html)
        if not match:
            raise AssertionError('settings composition missing next workspace')
        return html[:match.start()] + workspace + html[match.start():]
    return html.replace(marker, workspace + marker, 1)


SETTINGS_CSS = r'''
#workspace-setup { --settings-surface:#0c1b25; --settings-line:#263e4c; --settings-muted:#a9bfcc; --settings-teal:#86e4cf; background:#07141d; color:#ecf5f8; }
#workspace-setup [hidden] { display:none!important; }
#workspace-setup .settings-console { margin:0; padding:26px 30px 48px; border:0; border-radius:0; background:transparent; box-shadow:none; font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }
#workspace-setup .settings-heading { display:flex; justify-content:space-between; align-items:center; gap:20px; margin:0 0 18px; }
#workspace-setup .settings-heading .eyebrow { color:#87a4b4; font-size:.67rem; letter-spacing:.16em; margin:0 0 8px; }
#workspace-setup .settings-heading h2 { font-size:2rem; font-weight:650; letter-spacing:-.04em; line-height:1.1; margin:0; }
#workspace-setup .settings-local { display:inline-block; vertical-align:middle; margin-left:14px; padding:4px 8px; border:1px solid #315c56; border-radius:4px; color:#a7decf; font-size:.65rem; font-weight:600; letter-spacing:.02em; }
#workspace-setup .support-config-feedback { padding:10px 14px; margin:0 0 26px; border:1px solid #284350; border-left:3px solid #5b8b89; border-radius:4px; background:#10232d; align-items:center; min-height:44px; }
#workspace-setup .support-config-feedback p { font-size:.81rem; line-height:1.5; max-width:none; }
#workspace-setup .settings-layout { display:grid; grid-template-columns:174px minmax(0,1fr); gap:32px; align-items:start; }
#workspace-setup .settings-nav { display:flex; flex-direction:column; gap:5px; position:sticky; top:0; padding:4px 0; }
#workspace-setup .settings-nav a { display:flex; align-items:center; gap:10px; padding:12px 10px; min-height:46px; color:#a9bfcc; text-decoration:none; font-size:.88rem; font-weight:550; border-radius:4px; border:1px solid transparent; white-space:nowrap; }
#workspace-setup .settings-nav a>span:last-child { margin-left:auto; opacity:.6; }
#workspace-setup .settings-nav-number { font:10px ui-monospace,SFMono-Regular,Consolas,monospace; opacity:.6; }
#workspace-setup .settings-nav a[aria-selected="true"] { color:#baf4e6; background:#16352f; border-color:#315b50; }
#workspace-setup .settings-nav a:hover { color:#e2fff5; background:#112b35; }
#workspace-setup .settings-content { min-width:0; max-width:1100px; }
#workspace-setup .settings-category { display:block; animation:settings-enter .15s ease-out; }
#workspace-setup .settings-category-heading { margin:0 0 26px; }
#workspace-setup .settings-category-heading h3 { margin:0 0 7px; font-size:1.35rem; font-weight:600; letter-spacing:-.025em; }
#workspace-setup .settings-category-heading p { margin:0; font-size:.85rem; color:var(--settings-muted); }
#workspace-setup :is(button,.companion-button) { font:inherit; font-size:.8rem; font-weight:600; min-height:40px; padding:9px 13px; border:1px solid #3d5c6a; border-radius:4px; background:#132b37; color:#d6e9ef; box-shadow:none; transform:none; text-decoration:none; }
#workspace-setup :is(button,.companion-button):hover:not(:disabled) { border-color:#72b9ad; background:#1b3c43; box-shadow:none; transform:none; }
#workspace-setup :is(.setup-primary,.support-config-primary,.hb-install) { background:#88e0cb; color:#09251f; border-color:#88e0cb; }
#workspace-setup button:disabled { opacity:.5; cursor:not-allowed; }
#workspace-setup :is(input,select,textarea) { max-width:100%; min-height:42px; border:1px solid #3c5867; border-radius:4px; padding:9px 11px; background:#06151e; color:#e1edf2; font:inherit; font-size:.875rem; box-shadow:none; }
#workspace-setup label { font-size:.83rem; font-weight:550; line-height:1.45; }
#workspace-setup :is(a,button,input,select,textarea,summary):focus-visible { outline:3px solid #91e9d6; outline-offset:3px; }
#workspace-setup p { font-size:.85rem; line-height:1.6; color:#bdcfd9; }
#workspace-setup :is(h4,h5,h6) { line-height:1.45; letter-spacing:-.015em; }
#workspace-setup a { color:#9ee7d9; }
#workspace-setup .settings-overview { display:flex; gap:0; margin:0 0 28px; background:#10232d; border:1px solid #294451; border-radius:5px; }
#workspace-setup .settings-overview>a { position:relative; flex:1; min-width:0; display:flex; flex-direction:column; gap:6px; padding:19px 20px; text-decoration:none; color:#e5f3f5; }
#workspace-setup .settings-overview>a+a { border-left:1px solid #294451; }
#workspace-setup .settings-overview span { font-size:.72rem; color:#9bb7c4; }
#workspace-setup .settings-overview strong { font-size:1rem; font-weight:600; overflow-wrap:anywhere; }
#workspace-setup .settings-overview small { font-size:.72rem; color:#98b3c1; overflow-wrap:anywhere; }
#workspace-setup .settings-overview b { position:absolute; right:16px; top:18px; font-size:.85rem; color:#6ca898; }
#workspace-setup .setup-health { border:0; padding:0; background:none; box-shadow:none; }
#workspace-setup .setup-health h3 { font-size:1rem; margin:0 0 5px; }
#workspace-setup .setup-check-actions { margin:15px 0; display:flex; gap:10px; flex-wrap:wrap; }
#workspace-setup .setup-check-status { min-height:1.5em; font-size:.8rem; }
#workspace-setup .setup-check-results { margin:16px 0; }
#workspace-setup .setup-check-row { padding:12px 14px; background:#0c1e29; border:0; margin:0 0 5px; border-radius:3px; }
#workspace-setup .setup-check-row strong { font-size:.85rem; }
#workspace-setup .setup-check-results :is(p,small) { font-size:.79rem; }
#workspace-setup .settings-disclosure,#workspace-setup :is(.support-collector-settings,.support-service-settings,.support-config-locations,.support-config-results,.setup-launch-help,.setup-actions-card,.workflow-advanced) { margin:14px 0 0; padding:0; border:0; background:none; border-radius:0; box-shadow:none; }
#workspace-setup details>summary { min-height:44px; padding:12px 0; font-size:.85rem; color:#b5cdd8; cursor:pointer; }
#workspace-setup details[open]>summary { color:#dff3ef; }
#workspace-setup .settings-disclosure>summary { border-top:1px solid #243b48; }
#workspace-setup :is(.support-capture,.network-setup,.ops-location-setup,.storage-panel,.apps-setup,.setup-account,.setup-software) { border:0; padding:0; margin:0 0 24px; background:none; box-shadow:none; border-radius:0; }
#workspace-setup .support-capture-steps { gap:24px; margin-top:16px; }
#workspace-setup .support-step { display:none; }
#workspace-setup .support-capture-destinations { padding-top:20px; border-top:0; margin-top:0; }
#workspace-setup .support-capture-reading { padding:15px 18px; margin-top:18px; background:#0f2530; border:0; border-radius:4px; }
#workspace-setup .support-capture-reading p { font-size:.8rem; margin:0; }
#workspace-setup .support-capture-reading dd { font-size:1.4rem; }
#workspace-setup .support-capture-reading dl { margin:12px 0; }
#workspace-setup .support-config-note { font-size:.78rem; color:#a9c0cd; }
#workspace-setup .support-tool-settings { grid-template-columns:1fr; gap:24px; }
#workspace-setup .support-tool-settings section+section { border:0; padding:0; }
#workspace-setup .support-config-actions { gap:8px; margin:12px 0; }
#workspace-setup .support-config-section-head h5 { font-size:1rem; }
#workspace-setup .support-config-badge { font-size:.72rem; border-radius:3px; }
#workspace-setup .settings-switch-row { display:flex; align-items:center; gap:14px; justify-content:space-between; padding:17px 18px; background:#102832; border-radius:4px; margin:22px 0; }
#workspace-setup .settings-switch-copy { flex:1; }
#workspace-setup .settings-switch-copy strong { display:block; font-size:.86rem; }
#workspace-setup .settings-switch-copy small { display:block; font-size:.76rem; color:#a5c0cd; margin-top:5px; }
#workspace-setup .settings-switch { appearance:none; -webkit-appearance:none; flex:none; width:44px!important; height:25px; min-height:25px!important; max-width:44px!important; border-radius:20px!important; padding:3px!important; border:1px solid #66818a; background:#263e4a; cursor:pointer; margin:0; }
#workspace-setup .settings-switch:before { content:""; display:block; width:17px; height:17px; border-radius:50%; background:#c0cfd7; transition:transform .15s ease; }
#workspace-setup .settings-switch:checked { background:#67cbb1; border-color:#67cbb1; }
#workspace-setup .settings-switch:checked:before { transform:translateX(18px); background:#072820; }
#workspace-setup .settings-model-state { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin:18px 0 5px; }
#workspace-setup .settings-model-state strong { font-size:.9rem; color:#c8eadf; }
#workspace-setup .settings-model-state[data-state="retrying"] strong,#workspace-setup .settings-model-state[data-state="error"] strong { color:#ecc68d; }
#workspace-setup .settings-model-fields { display:grid; grid-template-columns:minmax(0,1.7fr) minmax(0,1fr); gap:20px; max-width:750px; }
#workspace-setup .settings-model-fields select { width:100%; max-width:none; }
#workspace-setup #support-model-metrics { font-size:.76rem; }
#workspace-setup .apps-setup .panel-head { padding:0; margin:0 0 17px; background:none; border:0; }
#workspace-setup .apps-setup .panel-head :is(.eyebrow,h3,p,a) { display:none; }
#workspace-setup .apps-setup-search { padding:0; margin:0 0 12px; }
#workspace-setup .apps-setup-search>a { display:none; }
#workspace-setup .apps-setup-search label { max-width:440px; }
#workspace-setup .apps-setup .apps-setup-filters { padding:0; margin:0 0 16px; gap:5px; }
#workspace-setup .apps-setup-filters .polish-chip { min-height:34px; font-size:.74rem; padding:6px 9px; border-radius:4px; }
#workspace-setup .apps-setup-cards { padding:0; }
#workspace-setup .apps-setup-card { border:0; margin:0; padding:0; background:none; }
#workspace-setup .apps-setup-card>summary { display:grid; grid-template-columns:20px minmax(0,1fr) auto auto; align-items:center; gap:8px; padding:15px 14px; border-top:1px solid #253e4b; min-height:60px; font-size:.88rem; }
#workspace-setup .apps-setup-card>summary:after { content:"+"; color:#8ab6bb; font-weight:400; }
#workspace-setup .apps-setup-card[open]>summary:after { content:"−"; }
#workspace-setup .apps-setup-card[open] { background:#0c202b; }
#workspace-setup .apps-setup-card[open]>summary { background:#102833; }
#workspace-setup .apps-setup-card .app-inline-status { color:#9dbdc9; font-size:.72rem; font-weight:450; text-align:right; }
#workspace-setup .apps-setup-content { padding:0 16px 20px; }
#workspace-setup .apps-setup-content>p { margin:10px 0 16px; }
#workspace-setup .apps-setup-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
#workspace-setup .apps-setup-actions [data-heartbeat-install] { display:contents; }
#workspace-setup .apps-setup-actions [data-heartbeat-install]>p { flex-basis:100%; }
#workspace-setup .apps-setup-actions .hb-detail { margin:0; }
#workspace-setup .apps-setup-status { padding:12px 0 0; color:#98b5c3; font-size:.75rem; }
#workspace-setup .companion-controls { margin:0; padding:0; }
#workspace-setup .companion-controls :is(details,code,p,a,button) { max-width:100%; }
#workspace-setup .settings-app-advanced { margin-top:10px; }
#workspace-setup .settings-app-advanced>.companion-controls { padding:0; }
#workspace-setup .settings-app-advanced summary { font-size:.78rem; }
#workspace-setup code { overflow-wrap:anywhere; white-space:pre-wrap; font-size:.77rem; }
#workspace-setup .storage-panel .panel-head,#workspace-setup .storage-panel header { padding:0; }
#workspace-setup .storage-policy-layout { grid-template-columns:minmax(0,1fr); }
#workspace-setup .storage-guidance { border:0; padding:0; }
#workspace-setup .ki-settings label { justify-content:space-between; flex-direction:row-reverse; background:#102832; padding:14px 16px; border-radius:4px; font-size:.82rem; gap:20px; }
#workspace-setup .setup-account-actions { margin:12px 0; }
#workspace-setup .polish-presets,#workspace-setup .polish-chips { margin-block:8px; }
@keyframes settings-enter { from { opacity:.65; transform:translateY(3px); } to { opacity:1; transform:none; } }
@media(min-width:1400px) { #workspace-setup .settings-layout { grid-template-columns:190px minmax(0,1fr); gap:46px; } }
@media(max-width:850px) { #workspace-setup .settings-console { padding:20px 18px 36px; } #workspace-setup .settings-layout { grid-template-columns:1fr; gap:24px; } #workspace-setup .settings-nav { flex-direction:row; position:static; gap:5px; overflow-x:auto; padding:3px 3px 9px; max-width:100%; } #workspace-setup .settings-nav a { flex:0 0 auto; padding:9px 11px; min-height:42px; font-size:.8rem; } #workspace-setup .settings-nav-number,#workspace-setup .settings-nav a>span:last-child { display:none; } #workspace-setup .settings-category-heading { margin-bottom:20px; } }
@media(max-width:560px) { #workspace-setup .settings-console { padding:18px 12px 32px; } #workspace-setup .settings-heading h2 { font-size:1.7rem; } #workspace-setup .settings-heading { gap:10px; margin-bottom:16px; } #workspace-setup .settings-heading>button { font-size:.7rem; padding:8px; } #workspace-setup .settings-heading .eyebrow { font-size:.55rem; letter-spacing:.12em; } #workspace-setup .settings-local { margin-left:9px; } #workspace-setup .support-config-feedback { margin-bottom:16px; } #workspace-setup .settings-overview { flex-direction:column; margin-bottom:22px; } #workspace-setup .settings-overview>a { padding:13px 16px; display:grid; grid-template-columns:1fr 1.3fr; gap:5px 15px; } #workspace-setup .settings-overview>a+a { border-left:0; border-top:1px solid #294451; } #workspace-setup .settings-overview strong { font-size:.88rem; grid-column:2; grid-row:1/3; padding-right:15px; align-self:center; } #workspace-setup .settings-overview small { grid-column:1; } #workspace-setup .settings-overview b { right:12px; top:23px; } #workspace-setup .settings-model-fields { grid-template-columns:1fr; gap:3px; } #workspace-setup .support-capture-steps { grid-template-columns:1fr; gap:14px; } #workspace-setup .apps-setup-card>summary { padding-inline:9px; grid-template-columns:18px minmax(0,1fr) auto auto; gap:6px; } #workspace-setup .apps-setup-card .app-inline-status { max-width:95px; } #workspace-setup .apps-setup-content { padding-inline:10px; } #workspace-setup .support-config-actions button { flex:initial; } #workspace-setup .settings-switch-row { padding:14px 12px; } #workspace-setup .support-capture-reading dl { gap:20px; } }
@media(prefers-reduced-motion:reduce) { #workspace-setup * { animation:none!important; transition:none!important; } }
'''

SETTINGS_JS = r'''
(() => {
 const root=document.getElementById('workspace-setup');if(!root||typeof root.querySelectorAll!=='function')return;
 const panels=[...root.querySelectorAll('[data-setup-category]')],tabs=[...root.querySelectorAll('.settings-nav [role="tab"]')];
 let active='overview';
 function select(key,focus=false){
  if(!panels.some(panel=>panel.dataset.setupCategory===key))return;
  active=key;
  panels.forEach(panel=>panel.hidden=panel.dataset.setupCategory!==key);
  tabs.forEach(tab=>{const selected=tab.getAttribute('aria-controls')==='setup-category-'+key;tab.setAttribute('aria-selected',String(selected));tab.tabIndex=selected?0:-1;});
  if(focus)document.getElementById('setup-category-'+key).querySelector('h3').focus({preventScroll:true});
 }
 function reveal(target,focus=false){
  if(!target||!root.contains(target))return false;
  const panel=target.closest('[data-setup-category]');
  if(panel)select(panel.dataset.setupCategory,false);
  else if(target.id==='setup-title'||target.id==='workspace-setup'||target.id==='support-config-title')select('overview',false);
  for(let parent=target;parent&&parent!==root;parent=parent.parentElement)if(parent.tagName==='DETAILS')parent.open=true;
  if(focus){let candidate=target.matches('input,select,button,a,summary,[tabindex]')?target:target.querySelector('summary,h3,h4,h5,input,button');if(candidate){if(!candidate.matches('input,select,button,a,summary,[tabindex]'))candidate.tabIndex=-1;candidate.focus({preventScroll:true});}}
  return true;
 }
 window.megalodonSettings={reveal,select,get active(){return active;}};
 function fromHash(moveFocus=false){const id=(window.location.hash||'').slice(1),target=document.getElementById(id);reveal(target,moveFocus&&!id.startsWith('setup-category-'));if(moveFocus&&id.startsWith('setup-category-'))document.getElementById('settings-tab-'+id.slice('setup-category-'.length))?.focus({preventScroll:true});}
 root.addEventListener('keydown',event=>{
  const index=tabs.indexOf(event.target);if(index<0)return;
  let next=index;if(['ArrowRight','ArrowDown'].includes(event.key))next=(index+1)%tabs.length;
  else if(['ArrowLeft','ArrowUp'].includes(event.key))next=(index+tabs.length-1)%tabs.length;
  else if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;else return;
  event.preventDefault();tabs[next].focus();tabs[next].click();
 });
 document.addEventListener('click',event=>{const link=event.target.closest?.('a[href^="#"]');if(!link||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey)return;const target=document.getElementById(link.getAttribute('href').slice(1));if(tabs.includes(link)){event.preventDefault();if(typeof activateWorkspace==='function')activateWorkspace('setup');reveal(target);if(window.location.hash!==link.getAttribute('href'))window.history.pushState(null,'',link.getAttribute('href'));link.focus({preventScroll:true});return;}reveal(target,false);},true);
 window.addEventListener('hashchange',()=>fromHash(true));window.addEventListener('popstate',()=>fromHash(true));fromHash();
 window.addEventListener('megalodon-support-state',event=>{
  const value=event.detail;if(!value)return;
  document.getElementById('settings-traffic-summary').textContent={idle:'Not capturing',stopped:'Stopped',starting:'Starting',running:'Capturing',failed:'Needs attention'}[value.capture?.state]||'Unavailable';
  const model=value.model,lifecycle=model?.lifecycle;
  document.getElementById('settings-model-summary').textContent=lifecycle?.state==='ready'&&model.loaded===true?'Loaded':lifecycle?.state==='retrying'?'Reconnecting':model?.loaded===true?'Loaded':model?.loaded===false?'Not loaded':'Not checked';
  document.getElementById('settings-model-name').textContent=model?.model||'No saved model';
 });
 function apps(){const count=heartbeatState.report?.tools.filter(tool=>tool.installed==='yes').length;document.getElementById('settings-apps-summary').textContent=heartbeatStale()?'Status unavailable':count===undefined?'Checking…':count+' installed';}
 const original=window.megalodonAppsRefilter;window.megalodonAppsRefilter=()=>{original?.();apps();};apps();
})();
'''
