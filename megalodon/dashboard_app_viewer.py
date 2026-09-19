"""Explicit browser navigation to companion consoles; no server proxy or probes."""

APP_VIEWER_HTML = """
<section class="app-viewer" aria-labelledby="app-viewer-title">
  <h3 id="app-viewer-title" tabindex="-1">App viewer</h3>
  <p id="app-viewer-status" role="status">Choose View in HUD on an app below. No companion console has been loaded.</p>
  <p id="app-viewer-address" class="room-meta"></p>
  <div class="app-viewer-actions">
    <button id="app-viewer-reload" type="button" disabled>Reload console</button>
    <button id="app-viewer-close" type="button" disabled>Close console</button>
    <a id="app-viewer-external" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" hidden>Open outside HUD ↗</a>
  </div>
  <div id="app-viewer-frame"></div>
  <p class="room-meta">The browser contacts only the console you choose; the console can make its own requests. MEGALODON does not send it your traffic or read its contents. A blank or refused frame can mean the app disallows embedding or requires external sign-in. Desktop windows cannot be embedded directly.</p>
</section>
"""

APP_VIEWER_CSS = """
.app-viewer { margin:1rem 22px; padding:1rem; border:1px solid #426173; border-radius:12px; background:#091e2a; }
.app-viewer h3 { margin:0 0 .6rem; }
.app-viewer p { overflow-wrap:anywhere; line-height:1.6; }
.app-viewer-actions { display:flex; flex-wrap:wrap; gap:.5rem; margin:.8rem 0; }
.app-viewer-actions :is(button,a) { min-height:44px; padding:.65rem .8rem; font:inherit; background:#173849; color:#def1f8; border:1px solid #426173; border-radius:7px; text-decoration:none; cursor:pointer; }
.app-viewer-actions button:disabled { opacity:.55; cursor:default; }
.app-viewer iframe { display:block; width:100%; height:65vh; min-height:300px; border:1px solid #426173; border-radius:7px; background:#fff; }
.app-viewer :focus-visible { outline:3px solid #a6f4df; outline-offset:3px; }
@media(max-width:560px) { .app-viewer { margin:1rem 14px; } }
"""

APP_VIEWER_JS = r"""
const appConsole = (() => {
  let selected = null;
  const nativeNotes = {
    core:'The MEGALODON UI is this HUD.',
    tshark:'Wireshark is a desktop GUI; TShark is a command-line tool.',
    zeek:'Zeek produces logs; it has no built-in web console.',
    suricata:'Suricata produces alerts; use your separately configured alert console.',
    scapy:'Scapy is a Python capture library; it has no built-in web console.',
    nftables:'nftables is a command-line tool; its plans are available in Evidence.',
    clamav:'ClamAV is a scanner; a GUI must be provided separately.',
    osquery:'osquery needs a separately configured fleet console.',
    qwen:'Qwen is a model; Ollama is a provider. Configure your own compatible web UI.',
    nmap:'Zenmap is a desktop GUI; Nmap is a command-line tool.',
    ossec:'Use the web console configured for your OSSEC deployment.'
  };
  function clear() {
    byId('app-viewer-frame').replaceChildren();
    byId('app-viewer-reload').disabled=true;
    byId('app-viewer-close').disabled=true;
  }
  function view(id, name, raw) {
    if(!MegalodonControls.ids.includes(id)) throw new Error('Unknown companion tool.');
    clear(); selected={id,name};
    byId('app-viewer-title').textContent=name+' · App viewer';
    const external=byId('app-viewer-external');external.hidden=true;external.removeAttribute('href');
    byId('app-viewer-address').textContent='';
    const status=byId('app-viewer-status');
    if(!raw) {
      status.textContent=(nativeNotes[id]||'This app has a web console when separately installed and configured.')+' Set its console link on the app card, then choose View in HUD. No UI connection has been configured.';
    } else {
      try {
        const url=MegalodonControls.consoleURL(raw);
        external.href=url;external.hidden=false;
        byId('app-viewer-address').textContent='Console destination: '+url;
        if(new URL(url).origin===window.location.origin) throw new Error('This address points back to the HUD. Choose the companion app’s own address.');
        if(window.location.protocol==='https:' && new URL(url).protocol==='http:') throw new Error('An HTTPS HUD cannot embed this HTTP console. Use Open outside HUD.');
        const frame=document.createElement('iframe');
        frame.title=name+' console'; frame.referrerPolicy='no-referrer';
        // Cross-origin consoles keep their own login storage. The HUD refuses
        // same-origin URLs and all HUD responses deny framing, including after
        // redirects. No top navigation, popups, downloads or permission grants.
        frame.setAttribute('sandbox','allow-scripts allow-forms allow-same-origin');
        frame.src=url;byId('app-viewer-frame').append(frame);
        status.textContent='Console requested. Its content and connection health cannot be verified by the HUD. If it stays blank or refuses to load, use Open outside HUD.';
        byId('app-viewer-reload').disabled=false;byId('app-viewer-close').disabled=false;
      } catch(error) {status.textContent=error.message;}
    }
    byId('app-viewer-title').focus();
    byId('app-viewer-title').scrollIntoView({block:'start'});
  }
  function changed(id) {
    if(selected?.id!==id)return;
    clear();byId('app-viewer-external').hidden=true;byId('app-viewer-external').removeAttribute('href');
    byId('app-viewer-address').textContent='';
    byId('app-viewer-status').textContent='Console link changed. Choose View in HUD again to load the saved destination.';
  }
  byId('app-viewer-close').addEventListener('click',()=>{clear();byId('app-viewer-status').textContent='Console closed. No embedded app remains loaded.';byId('app-viewer-title').focus();});
  byId('app-viewer-reload').addEventListener('click',()=>{if(selected)view(selected.id,selected.name,MegalodonControls.links()[selected.id]);});
  return {view,changed};
})();
"""
