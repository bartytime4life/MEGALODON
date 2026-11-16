// Exercise real Setup scripts without allowing guide interaction to perform I/O.
const assert = require('node:assert/strict');
const vm = require('node:vm');
let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const {code,guide_code,profiles,modes,default_profile,default_mode} = JSON.parse(input);
  const nodes = new Map(), windowEvents = new Map();
  const forbidden = name => () => { throw Error('Guide attempted '+name); };
  const element = (dataset={}) => ({dataset,hidden:false,value:'',disabled:false,textContent:'',events:{},
    addEventListener(name,fn){this.events[name]=fn;}});
  const profilePanels=profiles.map(id=>element({routerProfile:id}));
  const modePanels=modes.map(id=>element({routerMode:id}));
  const profile=element({default:default_profile}), mode=element({default:default_mode});
  profile.value=default_profile;mode.value=default_mode;
  nodes.set('router-guide-profile',profile);nodes.set('router-guide-mode',mode);
  nodes.set('router-compatibility',{querySelectorAll(selector){
    if(selector==='[data-router-profile]')return profilePanels;
    if(selector==='[data-router-mode]')return modePanels;
    throw Error('Unexpected guide query: '+selector);
  }});
  const setup=element();setup.querySelectorAll=()=>[];setup.contains=()=>false;
  nodes.set('workspace-setup',setup);
  for(const id of ['settings-traffic-summary','settings-model-summary','settings-model-name','settings-apps-summary'])nodes.set(id,element());
  const context={document:{getElementById:id=>nodes.get(id)||null,addEventListener(){}},
    window:{location:{hash:''},addEventListener:(name,fn)=>windowEvents.set(name,fn)},
    heartbeatState:{report:null},heartbeatStale:()=>false,
    fetch:forbidden('fetch'),XMLHttpRequest:forbidden('XMLHttpRequest'),WebSocket:forbidden('WebSocket'),
    setTimeout:forbidden('timer'),setInterval:forbidden('timer'),
    navigator:{sendBeacon:forbidden('sendBeacon')},
  };
  for(const name of ['localStorage','sessionStorage','indexedDB']){
    Object.defineProperty(context,name,{get:forbidden(name)});
    Object.defineProperty(context.window,name,{get:forbidden(name)});
  }
  Object.defineProperty(context.document,'cookie',{get:forbidden('cookie read'),set:forbidden('cookie write')});
  const check=(panels,key,id)=>assert.deepEqual(panels.filter(panel=>!panel.hidden).map(panel=>panel.dataset[key]),[id]);
  const choose=(control,value)=>{control.value=value;control.events.change();};
  vm.runInNewContext(code,context);
  check(profilePanels,'routerProfile',default_profile);check(modePanels,'routerMode',default_mode);
  for(const id of profiles){
    choose(profile,id);check(profilePanels,'routerProfile',id);
    check(modePanels,'routerMode',default_mode);assert.equal(mode.value,default_mode);
  }
  const selectedProfile=profile.value;
  for(const id of modes){
    choose(mode,id);check(modePanels,'routerMode',id);
    check(profilePanels,'routerProfile',selectedProfile);assert.equal(profile.value,selectedProfile);
  }
  const selectedMode=mode.value;
  for(const state of [{capture:{state:'running'},model:{selection_state:'none'}},{status:'unavailable'},null]){
    windowEvents.get('megalodon-support-state')({detail:state});
    context.window.megalodonAppsRefilter();
    check(profilePanels,'routerProfile',selectedProfile);check(modePanels,'routerMode',selectedMode);
    assert.equal(profile.value,selectedProfile);assert.equal(mode.value,selectedMode);
    assert.equal(profile.disabled,false);assert.equal(mode.disabled,false);
  }
  // Invalid selection must not leave an unrelated prior profile appearing selected.
  for(const invalid of ['','unrecognized','__proto__','<img src=x onerror=bad()>']){
    choose(profile,invalid);assert.equal(profile.value,default_profile);check(profilePanels,'routerProfile',default_profile);
    check(modePanels,'routerMode',selectedMode);
    choose(mode,invalid);assert.equal(mode.value,default_mode);check(modePanels,'routerMode',default_mode);
    choose(mode,selectedMode);
  }
  // Rendering a page without Setup is supported; no status/API fallback occurs.
  vm.runInNewContext(guide_code,{document:{getElementById:()=>null},fetch:forbidden('fallback fetch')});
});
