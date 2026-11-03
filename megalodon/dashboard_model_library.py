"""Download/staging controls composed into the protected Setup workflow."""

MODEL_LIBRARY_HTML = r'''
      <div class="model-library" aria-labelledby="model-library-title">
        <h5 id="model-library-title">Download and stage a model</h5>
        <p>Already installed in Ollama? Use <strong>Refresh installed models</strong> above. Those files stay in place.</p>
        <p>Or download a pinned GGUF file to this computer. MEGALODON keeps the file and its staging history locally. Staging does not import it into Ollama, select it, or enable responses.</p>
        <label for="model-library-select">Download catalog</label><select id="model-library-select" disabled><option value="">Loading catalog…</option></select>
        <p id="model-library-source" class="support-config-note"></p>
        <p id="model-library-space" class="support-config-note">Available space has not been checked.</p>
        <details class="settings-disclosure"><summary>File verification details</summary><p id="model-library-pin" class="support-config-note"></p><p class="support-config-note">Files: ~/.local/share/megalodon/model-library. SHA-256 checks file identity against the catalog; it does not establish model safety, loaded identity, or acceptance.</p></details>
        <label class="model-library-consent" for="model-library-online"><input id="model-library-online" type="checkbox" disabled> Download this file from Hugging Face to this computer.</label>
        <div class="support-config-actions"><button id="model-library-download" type="button" class="support-config-primary" disabled>Download &amp; stage</button><button id="model-library-check" type="button" disabled>Check staged files and space</button><button id="model-library-cancel" type="button" disabled>Cancel staging</button></div>
        <progress id="model-library-progress" aria-label="Model download progress" max="1" value="0" hidden></progress>
        <p id="model-library-status" role="status" aria-live="polite" class="support-config-note">No staging action has run.</p>
        <ul id="model-library-models" aria-label="Staged model files"></ul>
        <ul id="model-library-history" aria-label="Recent staging jobs"></ul>
        <p class="support-config-note">One transfer at a time. No automatic downloads, resume, or activation. Cancellation removes partial staging bytes after the current bounded read returns. The first catalog entry is a small Qwen model; adding other downloads requires reviewed source and file pins.</p>
      </div>
'''

MODEL_LIBRARY_CSS = r'''
.model-library { margin-top:28px; padding-top:24px; border-top:1px solid #355464; }
.model-library .model-library-consent { display:flex; align-items:center; gap:10px; }
.model-library input[type="checkbox"] { width:20px; max-width:20px; min-height:20px; flex:none; }
.model-library progress { width:100%; max-width:560px; accent-color:#88e0cb; }
.model-library #model-library-pin { overflow-wrap:anywhere; }
.model-library ul { padding-left:20px; font-size:.8rem; color:#b7ccd8; }
'''

# Runs inside SUPPORT_CONFIG_JS, using its checked response, token, action
# queue, textContent rendering and visibility/connection failure controls.
MODEL_LIBRARY_JS = r'''
  const libraryStates=['unchecked','checked','downloading','verifying','staged_verified','failed','cancelled'];
  const libraryJobStates=['downloading','verifying','staged_verified','failed','cancelled','interrupted'];
  const libraryErrors=['UNAVAILABLE','BUSY','JOB_LIMIT','NO_SPACE','NETWORK','SOURCE','SIZE','DIGEST','CANCELLED','DEADLINE','FILE','INTERRUPTED'];
  function libraryChecked(v){
    if(v===undefined)return;
    const id=x=>typeof x==='string'&&/^[a-z0-9-]{1,40}$/.test(x);
    const hex=(x,n)=>typeof x==='string'&&x.length===n&&/^[a-f0-9]+$/.test(x);
    const job=x=>object(x)&&hex(x.job_id,32)&&id(x.catalog_id)&&libraryJobStates.includes(x.state)&&count(x.bytes_received)&&(x.error_code===null||libraryErrors.includes(x.error_code));
    if(!object(v)||v.schema!=='megalodon-model-library-v1'||!libraryStates.includes(v.state)||!text(v.message)||!Array.isArray(v.catalog)||v.catalog.length>8||!v.catalog.every(x=>object(x)&&id(x.id)&&text(x.title,120)&&text(x.source,200)&&text(x.filename,120)&&hex(x.revision,40)&&hex(x.sha256,64)&&text(x.license,40)&&count(x.size_bytes)&&x.size_bytes>0&&x.size_bytes<=4*1024**3)||new Set(v.catalog.map(x=>x.id)).size!==v.catalog.length||!Array.isArray(v.models)||v.models.length>8||!v.models.every(x=>object(x)&&id(x.catalog_id)&&['missing','unverified','staged_verified'].includes(x.state)&&count(x.checked_at))||!Array.isArray(v.jobs)||v.jobs.length>16||!v.jobs.every(x=>job(x)&&count(x.started_at)&&count(x.updated_at))||(v.active!==undefined&&v.active!==null&&!job(v.active))||!(v.free_bytes===null||count(v.free_bytes))||!count(v.reserve_bytes))throw Error('Invalid model library');
    const entries=new Map(v.catalog.map(x=>[x.id,x]));
    if(v.models.some(x=>!entries.has(x.catalog_id))||[...v.jobs,...(v.active?[v.active]:[])].some(x=>!entries.has(x.catalog_id)||x.bytes_received>entries.get(x.catalog_id).size_bytes))throw Error('Invalid model staging reference');
  }
  function libraryDetails(){
    const v=state.payload?.model_library,entry=v?.catalog.find(x=>x.id===el('model-library-select').value);
    el('model-library-source').textContent=entry?entry.source+' · '+entry.license+' · '+(entry.size_bytes/1024**2).toFixed(1)+' MiB':'';
    el('model-library-pin').textContent=entry?'Revision '+entry.revision+' · '+entry.filename+' · SHA-256 '+entry.sha256:'';
    el('model-library-space').textContent=v?.free_bytes===null||v?.free_bytes===undefined?'Available space has not been checked; it is checked before any transfer.':(v.free_bytes/1024**3).toFixed(1)+' GiB available at last check · '+(v.reserve_bytes/1024**2).toFixed(0)+' MiB reserve required.';
  }
  function libraryRender(v){
    const select=el('model-library-select'),catalog=v?.catalog||[],key=JSON.stringify(catalog.map(x=>[x.id,x.title]));
    if(select.dataset.catalog!==key){const chosen=select.value;select.replaceChildren(...catalog.map(x=>{const option=document.createElement('option');option.value=x.id;option.textContent=x.title;return option;}));if(catalog.some(x=>x.id===chosen))select.value=chosen;select.dataset.catalog=key;el('model-library-online').checked=false;}
    libraryDetails();
    el('model-library-status').textContent=v?.message||'Staging status unavailable. Retry the Setup connection.';
    const active=v?.active,entry=catalog.find(x=>x.id===active?.catalog_id),progress=el('model-library-progress');
    progress.hidden=!active||!entry;progress.max=entry?.size_bytes||1;progress.value=active?.bytes_received||0;
    const names={downloading:'Downloading',verifying:'Verifying',staged_verified:'Staged and verified',failed:'Failed',cancelled:'Cancelled',interrupted:'Interrupted'};
    el('model-library-models').replaceChildren(...(v?.models||[]).map(x=>{const row=document.createElement('li');row.textContent=(catalog.find(e=>e.id===x.catalog_id)?.title||'Model')+' · '+({missing:'Not staged',unverified:'Not verified',staged_verified:'Verified at last check'}[x.state]);return row;}));
    el('model-library-history').replaceChildren(...(v?.jobs||[]).map(x=>{const row=document.createElement('li');row.textContent=(catalog.find(e=>e.id===x.catalog_id)?.title||'Model')+' · '+names[x.state]+' · '+(x.bytes_received/1024**2).toFixed(1)+' MiB'+(x.error_code?' · '+x.error_code:'');return row;}));
  }
  function libraryControls(blocked){
    const available=!!state.payload?.model_library;
    const active=working()&&['model_stage_download','model_library_check'].includes(state.payload?.job.action);
    el('model-library-select').disabled=blocked||!available||!!working();
    el('model-library-online').disabled=blocked||!available||!!working();
    el('model-library-download').disabled=blocked||!available||!!working()||!el('model-library-online').checked||!el('model-library-select').value;
    el('model-library-check').disabled=blocked||!available||!!working();
    el('model-library-cancel').disabled=blocked||!available||!active;
  }
  el('model-library-select').addEventListener('change',()=>{el('model-library-online').checked=false;libraryDetails();controls();});
  el('model-library-online').addEventListener('change',()=>controls());
'''
