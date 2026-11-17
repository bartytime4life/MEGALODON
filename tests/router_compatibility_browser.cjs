// Exercise real Setup scripts without allowing guide interaction to perform I/O.
const assert = require('node:assert/strict');
const vm = require('node:vm');
let input = '';
process.stdin.on('data', chunk => input += chunk);
process.stdin.on('end', () => {
  const {code,guide_code,profiles,switches,modes,default_profile,default_switch,default_mode} = JSON.parse(input);
  const nodes = new Map(), windowEvents = new Map();
  const forbidden = name => () => { throw Error('Guide attempted '+name); };
  const element = (dataset={}) => ({dataset,hidden:false,value:'',disabled:false,textContent:'',events:{},
    addEventListener(name,fn){this.events[name]=fn;}});
  const profilePanels=profiles.map(id=>element({routerProfile:id}));
  const modePanels=modes.map(id=>element({routerMode:id}));
  const switchPanels=switches.map(id=>element({switchProfile:id}));
  const profile=element({default:default_profile}), mode=element({default:default_mode}), switchProfile=element({default:default_switch});
  profile.value=default_profile;mode.value=default_mode;switchProfile.value=default_switch;
  nodes.set('router-guide-profile',profile);nodes.set('router-guide-mode',mode);
  nodes.set('switch-guide-profile',switchProfile);
  nodes.set('router-compatibility',{querySelectorAll(selector){
    if(selector==='[data-router-profile]')return profilePanels;
    if(selector==='[data-router-mode]')return modePanels;
    if(selector==='[data-switch-profile]')return switchPanels;
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
  const groups=[
    {control:profile,panels:profilePanels,key:'routerProfile',ids:profiles,default:default_profile},
    {control:switchProfile,panels:switchPanels,key:'switchProfile',ids:switches,default:default_switch},
    {control:mode,panels:modePanels,key:'routerMode',ids:modes,default:default_mode},
  ];
  const expected=new Map(groups.map(group=>[group.key,group.default]));
  function checkAll(){
    for(const group of groups){
      check(group.panels,group.key,expected.get(group.key));
      assert.equal(group.control.value,expected.get(group.key));
      assert.equal(group.control.disabled,false);
    }
  }
  vm.runInNewContext(code,context);
  checkAll();
  // Each choice changes only its own panel, including overlapping catalog IDs.
  for(const group of groups){
    for(const id of group.ids){
      choose(group.control,id);expected.set(group.key,id);checkAll();
    }
  }
  const selected=new Map(expected);
  for(const state of [{capture:{state:'running'},model:{selection_state:'none'}},{status:'unavailable'},null]){
    windowEvents.get('megalodon-support-state')({detail:state});
    context.window.megalodonAppsRefilter();
    checkAll();
  }
  // Invalid selection must not leave an unrelated prior profile appearing selected.
  for(const group of groups){
    for(const invalid of ['','unrecognized','__proto__','<img src=x onerror=bad()>']){
      choose(group.control,invalid);expected.set(group.key,group.default);checkAll();
      choose(group.control,selected.get(group.key));expected.set(group.key,selected.get(group.key));checkAll();
    }
  }
  // Rendering a page without Setup is supported; no status/API fallback occurs.
  vm.runInNewContext(guide_code,{document:{getElementById:()=>null},fetch:forbidden('fallback fetch')});
});
