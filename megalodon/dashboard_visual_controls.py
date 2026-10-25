"""Visual editors over the HUD's authoritative, existing form controls."""

VISUAL_CONTROLS_CSS = r'''
.shell .polish-radio-group { gap:5px; }
.shell label.polish-radio { position:relative; display:inline-flex; flex-direction:row; align-items:center; gap:8px; margin:0; border-radius:4px; padding:8px 11px; min-height:38px; font-size:.8rem; line-height:1.35; }
.shell label.polish-radio input[type="radio"] { appearance:none; -webkit-appearance:none; display:block; position:static; flex:none; width:13px!important; height:13px!important; min-height:13px!important; min-width:13px!important; margin:0; padding:0!important; border:1px solid #8aabb5; border-radius:50%!important; background:#09202a; cursor:pointer; }
.shell label.polish-radio input:checked { background:#91ead2; border-color:#91ead2; box-shadow:inset 0 0 0 3px #153e3b; }
.shell label.polish-radio.is-selected { border-color:#72bcae; background:#173c37; color:#dffcf2; box-shadow:none; }
.shell label.polish-radio.is-disabled { opacity:.5; cursor:not-allowed; }
.shell label.polish-radio:has(input:focus-visible) { outline:3px solid #a6f4df; outline-offset:3px; }
.shell label.polish-radio input:focus-visible { outline:none; }
.shell .vc-range { display:grid; grid-template-columns:minmax(0,1fr) 94px; gap:18px; align-items:center; margin:9px 0 14px; min-width:0; }
.shell .vc-range-main { min-width:0; }
.shell .vc-range-reading { display:flex; align-items:baseline; gap:9px; justify-content:space-between; margin-bottom:7px; }
.shell .vc-range-value { color:#b3f1dd; font:600 1.12rem ui-monospace,SFMono-Regular,Consolas,monospace; font-variant-numeric:tabular-nums; white-space:nowrap; }
.shell .vc-range-note { font-size:.68rem; color:#9ab8c8; }
.shell .vc-range input[type="range"] { display:block; appearance:none; -webkit-appearance:none; width:100%; max-width:none; min-height:28px; height:28px; border:0; padding:0; border-radius:0; background:transparent; cursor:pointer; margin:0; }
.shell .vc-range input[type="range"]::-webkit-slider-runnable-track { height:5px; border-radius:3px; background:linear-gradient(to right,#7bd8be 0 var(--vc-fill,0%),#294854 var(--vc-fill,0%) 100%); }
.shell .vc-range input[type="range"]::-webkit-slider-thumb { appearance:none; -webkit-appearance:none; width:17px; height:17px; margin-top:-6px; border:3px solid #0a2a29; border-radius:50%; background:#a7f2da; box-shadow:0 0 0 1px #80cfb6; }
.shell .vc-range input[type="range"]::-moz-range-track { height:5px; background:#294854; border-radius:3px; }
.shell .vc-range input[type="range"]::-moz-range-progress { height:5px; background:#7bd8be; border-radius:3px; }
.shell .vc-range input[type="range"]::-moz-range-thumb { width:13px; height:13px; border:3px solid #0a2a29; border-radius:50%; background:#a7f2da; }
.shell .vc-range-scale { display:flex; justify-content:space-between; color:#91adbe; font-size:.67rem; }
.shell .vc-range-exact { min-width:0; }
.shell .vc-range-exact>span { display:block; color:#9ab6c4; font-size:.67rem; margin-bottom:6px; }
.shell .vc-range-exact input { width:100%!important; max-width:none!important; min-width:0; margin:0!important; font-variant-numeric:tabular-nums; }
.shell .vc-range[data-invalid="true"] .vc-range-value { font-size:.86rem; color:#efcd95; white-space:normal; }
.shell .vc-range[data-disabled="true"] { opacity:.55; }
.shell .vc-preset-editor { display:grid; grid-template-columns:minmax(0,1fr) minmax(90px,.7fr); gap:12px; align-items:start; max-width:540px; margin:8px 0 12px; }
.shell .vc-preset-editor select,.shell .vc-preset-editor input { width:100%; max-width:none; min-width:0; margin:0!important; }
.shell .vc-preset-custom { display:block; }
.shell .vc-preset-custom>span { display:block; font-size:.67rem; color:#9ab6c4; margin-bottom:6px; }
.shell .vc-preset-editor[data-custom="false"] { grid-template-columns:1fr; }
.shell .vc-preset-editor [hidden] { display:none!important; }
.shell .vc-switch-control { display:inline-flex; align-items:center; flex:none; gap:9px; }
.shell .vc-switch-state { min-width:1.7rem; color:#a0b7c3; font-size:.72rem; font-weight:600; }
.shell .vc-switch-control[data-on="true"] .vc-switch-state { color:#a2ecd4; }
.shell .vc-switch-control input[role="switch"] { appearance:none; -webkit-appearance:none; flex:none; width:44px!important; min-width:44px!important; max-width:44px!important; height:25px!important; min-height:25px!important; border-radius:20px!important; padding:3px!important; border:1px solid #66818a; background:#263e4a; cursor:pointer; margin:0!important; }
.shell .vc-switch-control input[role="switch"]::before { content:""; display:block; width:17px; height:17px; border-radius:50%; background:#c0cfd7; transition:transform .15s ease; }
.shell .vc-switch-control input[role="switch"]:checked { background:#67cbb1; border-color:#67cbb1; }
.shell .vc-switch-control input[role="switch"]:checked::before { transform:translateX(18px); background:#072820; }
.shell .vc-switch-control input[role="switch"]:disabled { opacity:.5; cursor:not-allowed; }
.shell .vc-toggle-button { display:inline-flex; gap:10px; align-items:center; }
.shell .vc-toggle-button::before { content:""; width:31px; height:18px; border:1px solid #688b94; border-radius:12px; background:radial-gradient(circle at 9px 50%,#c3d5de 0 5px,transparent 6px),#29434f; flex:none; }
.shell .vc-toggle-button[aria-pressed="true"]::before { background:radial-gradient(circle at 22px 50%,#0b322c 0 5px,transparent 6px),#87dfc6; border-color:#87dfc6; }
.shell .network-available { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:7px; max-width:750px; }
.shell .network-scope-choice { display:flex!important; gap:12px; align-items:center; margin:0!important; min-height:62px; padding:12px 14px; border:1px solid #365560; border-radius:4px; background:#0c2530; cursor:pointer; }
.shell .network-scope-choice:has(input:checked) { border-color:#78bca7; background:#133930; }
.shell .network-scope-choice input { width:17px!important; height:17px; min-height:17px!important; max-width:17px!important; margin:0; accent-color:#91e3c9; flex:none; }
.shell .network-scope-choice strong { display:block; font:500 .85rem ui-monospace,SFMono-Regular,Consolas,monospace; color:#d9f1ed; overflow-wrap:anywhere; }
.shell .network-scope-choice small { display:block; color:#a9c3cd; font-size:.73rem; margin-top:4px; }
.shell .network-scope-choice:has(input:focus-visible) { outline:3px solid #a6f4df; outline-offset:3px; }
.shell .network-scope-summary { margin:6px 0!important; font-size:.78rem!important; }
.shell .network-manual { max-width:750px; }
.shell .network-manual>summary { font-size:.8rem; }
.shell .network-enable,.shell .reports-check { justify-content:space-between; flex-direction:row-reverse; gap:18px; max-width:750px; }
#workspace-setup .storage-fields { grid-template-columns:repeat(2,minmax(0,1fr)); gap:16px 24px; }
#workspace-setup .storage-fields>label:first-child { grid-column:1/-1; }
#workspace-setup .storage-fields>label { display:block; min-width:0; }
#workspace-setup .storage-fields label span { display:block; margin:5px 0; }
#workspace-setup .vc-range-scale span { margin:0; font-size:.67rem; }
#workspace-setup .vc-switch-control .vc-switch-state { font-size:.72rem; }
#workspace-setup .vc-switch-control input[role="switch"] { background:#263e4a; border:1px solid #66818a; }
#workspace-setup .vc-switch-control input[role="switch"]:checked { background:#67cbb1; border-color:#67cbb1; }
#workspace-setup .vc-switch-control input[role="switch"]:focus-visible { outline:3px solid #91e9d6; outline-offset:3px; }
#workspace-setup .vc-switch-control input[role="switch"]:disabled { opacity:.5; cursor:not-allowed; }
#workspace-setup label.polish-radio { display:inline-flex; flex-direction:row; align-items:center; gap:8px; min-height:38px; padding:8px 11px; }
#workspace-setup label.polish-radio input[type="radio"] { background:#09202a; border:1px solid #8aabb5; }
#workspace-setup label.polish-radio input[type="radio"]:checked { background:#91ead2; border-color:#91ead2; box-shadow:inset 0 0 0 3px #153e3b; }
#workspace-setup .vc-range { grid-template-columns:minmax(0,1fr) 82px; gap:12px; }
#workspace-setup .vc-range input[type="range"] { min-height:28px!important; padding:0!important; }
#workspace-setup .vc-range-exact input { padding-inline:9px; }
#workspace-setup .vc-range-value { font-size:1rem; }
#workspace-setup .settings-model .vc-range { max-width:650px; }
.shell .reports-desk .vc-preset-editor { margin:0; min-width:220px; }
@media(max-width:700px) { #workspace-setup .storage-fields { grid-template-columns:1fr; } .shell .network-available { grid-template-columns:1fr; } .shell .vc-preset-editor { gap:9px; } .shell .vc-range { gap:12px; } .shell #reports-schedule-form>label:has(.vc-preset-editor) { grid-column:1/-1; width:100%; } .shell #reports-schedule-form>.reports-check { grid-column:1/-1; } .shell #reports-schedule-save { grid-column:1/-1; justify-self:start; } .shell #reports-schedule-form .vc-preset-editor { grid-template-columns:minmax(145px,1fr) minmax(110px,.75fr); width:100%; min-width:0; max-width:none; } .shell #reports-schedule-form .vc-preset-editor[data-custom="false"] { grid-template-columns:minmax(0,1fr); } }
@media(max-width:420px) { .shell label.polish-radio { font-size:.75rem; padding:8px 9px; } .shell .vc-range { grid-template-columns:minmax(0,1fr) 80px; } .shell .vc-range-value { font-size:.95rem; } .shell .vc-range-note { display:none; } .shell .reports-desk .vc-preset-editor { min-width:0; } }
@media(prefers-reduced-motion:reduce) { .shell .vc-switch-control input[role="switch"]::before { transition:none; } }
@media(forced-colors:active) { .shell label.polish-radio input[type="radio"] { appearance:auto; } .shell .vc-range input[type="range"] { appearance:auto; } .shell .vc-switch-control input[role="switch"] { appearance:auto; } }
'''

VISUAL_CONTROLS_JS = r'''
(() => {
 if(typeof document==='undefined'||typeof document.querySelectorAll!=='function'||typeof MutationObserver!=='function'||typeof HTMLInputElement==='undefined')return;
 const node=(tag,cls,text)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined)n.textContent=text;return n;};
 const fire=input=>{input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));};
 function watch(input,property,sync){
  const own=Object.getOwnPropertyDescriptor(input,property),native=own||Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input),property)||Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,property);
  if(!native?.get||!native?.set)return;
  try{Object.defineProperty(input,property,{configurable:true,get(){return native.get.call(this);},set(value){native.set.call(this,value);sync();}});}catch(_){}
 }
 function observe(input,sync,properties=['value','disabled','readOnly']){
  properties.forEach(property=>watch(input,property,sync));
  ['input','change'].forEach(event=>input.addEventListener(event,sync));
  new MutationObserver(sync).observe(input,{attributes:true,attributeFilter:['value','disabled','readonly','min','max','step','checked']});
  input.form?.addEventListener('reset',()=>queueMicrotask(sync));
 }
 function rangeEditor(id,{min,max,unit,name,scale}){
  const input=document.getElementById(id);if(!input||input.dataset.visualEditor)return;input.dataset.visualEditor='range';
  const root=node('div','vc-range'),main=node('div','vc-range-main'),reading=node('div','vc-range-reading'),output=node('output','vc-range-value'),hint=node('span','vc-range-note','Drag or enter exactly');
  const range=node('input');range.type='range';range.id=id+'-slider';range.min=String(min);range.max=String(max);range.step='1';range.setAttribute('aria-label',name);output.htmlFor=range.id;
  const ticks=node('div','vc-range-scale');scale.forEach(label=>ticks.append(node('span','',label)));
  const exact=node('div','vc-range-exact');exact.append(node('span','','Exact '+unit));input.setAttribute('aria-label',name+', exact '+unit);
  input.insertAdjacentElement('beforebegin',root);reading.append(output,hint);main.append(reading,range,ticks);root.append(main,exact);exact.append(input);
  function sync(){
   const raw=input.value,value=Number(raw),valid=raw.trim()!==''&&Number.isFinite(value)&&Number.isInteger(value)&&value>=min&&value<=max;
   root.dataset.invalid=String(!valid);root.dataset.disabled=String(input.disabled||input.readOnly);range.disabled=input.disabled||input.readOnly||!valid;range.hidden=!valid;ticks.hidden=!valid;
   output.textContent=valid?raw+' '+unit:'Check exact value';
   if(valid){range.value=raw;range.setAttribute('aria-valuetext',raw+' '+unit);range.style.setProperty('--vc-fill',String((value-min)/(max-min)*100)+'%');}
  }
  range.addEventListener('input',()=>{if(input.disabled||input.readOnly||range.disabled)return;input.value=range.value;fire(input);});
  observe(input,sync);sync();
 }
 function presetEditor(id,{name,options,customLabel='Custom',unit=''}){
  const input=document.getElementById(id);if(!input||input.dataset.visualEditor)return;input.dataset.visualEditor='preset';
  const root=node('div','vc-preset-editor'),select=node('select'),custom=node('div','vc-preset-custom');select.id=id+'-preset';select.setAttribute('aria-label',name+' preset');
  for(const [value,label]of options){const option=node('option','',label);option.value=String(value);select.append(option);}const other=node('option','',customLabel);other.value='custom';select.append(other);
  custom.append(node('span','',unit?'Exact '+unit:'Exact local time'));input.setAttribute('aria-label',name+', exact '+(unit||'local time'));
  input.insertAdjacentElement('beforebegin',root);root.append(select,custom);custom.append(input);
  let customChosen=false,lastRaw=input.value;
  function sync(){
   if(input.value!==lastRaw){if(document.activeElement!==input)customChosen=false;lastRaw=input.value;}
   const match=options.find(([value])=>String(value)===input.value),isCustom=customChosen||!match;
   select.value=isCustom?'custom':String(match[0]);custom.hidden=!isCustom;root.dataset.custom=String(isCustom);select.disabled=input.disabled||input.readOnly;
   if(custom.hidden&&custom.contains(document.activeElement))select.focus({preventScroll:true});
  }
  select.addEventListener('change',()=>{if(input.disabled||input.readOnly)return;if(select.value==='custom'){customChosen=true;custom.hidden=false;root.dataset.custom='true';input.focus({preventScroll:true});return;}customChosen=false;input.value=select.value;fire(input);sync();});
  input.form?.addEventListener('reset',()=>{customChosen=false;queueMicrotask(sync);});
  const label=input.labels?.[0];if(label)label.addEventListener('click',event=>{if(!custom.hidden||event.target.closest?.('input,select,button'))return;event.preventDefault();select.focus();});
  observe(input,sync);sync();
 }
 function switchEditor(id){
  const input=document.getElementById(id);if(!input||input.type!=='checkbox'||input.dataset.visualSwitch)return;input.dataset.visualSwitch='true';input.setAttribute('role','switch');
  const wrap=node('span','vc-switch-control'),state=node('span','vc-switch-state');state.setAttribute('aria-hidden','true');input.insertAdjacentElement('beforebegin',wrap);wrap.append(input,state);
  const sync=()=>{wrap.dataset.on=String(input.checked);state.textContent=input.checked?'On':'Off';};observe(input,sync,['checked','disabled','readOnly']);sync();
 }
 rangeEditor('storage-days',{min:7,max:30,unit:'days',name:'Maximum history',scale:['7 days','30 days']});
 rangeEditor('support-model-timeout',{min:1,max:1800,unit:'seconds',name:'AI response limit',scale:['1 s','15 min','30 min']});
 presetEditor('storage-cap',{name:'Storage budget',unit:'GiB',customLabel:'Custom budget',options:[[1,'1 GiB'],[5,'5 GiB'],[20,'20 GiB · workstation'],[100,'100 GiB · small office'],[500,'500 GiB · busy server'],[1024,'1,024 GiB'],[4096,'4,096 GiB'] ]});
 presetEditor('reports-time',{name:'Report time',customLabel:'Custom time',options:[['07:00','7:00 AM'],['09:00','9:00 AM'],['12:00','Noon'],['18:00','6:00 PM']]});
 ['support-model-ready','network-enabled','reports-schedule-enabled','ki-enabled','ki-automatic','ki-updates'].forEach(switchEditor);
 for(const id of ['live-globe-pause','pc-pause']){const motion=document.getElementById(id);if(motion)motion.classList.add('vc-toggle-button');}
})();
'''
