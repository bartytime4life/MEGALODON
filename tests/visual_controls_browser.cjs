const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
(async()=>{
 const {code}=JSON.parse(fs.readFileSync(0,'utf8'));let doc;
 class E{
  constructor(tag='div'){this.tagName=tag.toUpperCase();this.children=[];this.parentElement=null;this.dataset={};this.attrs={};this.events={};this.style={setProperty:(k,v)=>this.style[k]=v};this.hidden=false;this.className='';this.id='';this.textContent='';this._value='';this._checked=false;this._disabled=false;this._readOnly=false;this._observers=[];this.form=null;}
  append(...items){for(const item of items){if(item.parentElement)item.parentElement.children=item.parentElement.children.filter(n=>n!==item);item.parentElement=this;this.children.push(item);}}
  insertAdjacentElement(where,item){const parent=this.parentElement;if(!parent)throw Error('Missing parent');const index=parent.children.indexOf(this)+(where==='afterend'?1:0);item.parentElement=parent;parent.children.splice(index,0,item);}
  setAttribute(k,v){this.attrs[k]=String(v);if(k==='disabled')this.disabled=true;if(k==='readonly')this.readOnly=true;for(const fn of this._observers)fn();}
  getAttribute(k){return this.attrs[k]??null;}
  addEventListener(k,fn){(this.events[k]??=[]).push(fn);}
  dispatchEvent(event){event.target??=this;for(const fn of this.events[event.type]||[])fn(event);return true;}
  contains(item){return item===this||this.children.some(child=>child.contains(item));}
  focus(){doc.activeElement=this;}
  closest(selector){for(let item=this;item;item=item.parentElement)if(item.matches(selector))return item;return null;}
  matches(selector){return selector.split(',').some(s=>{s=s.trim();if(s[0]==='.')return this.className.split(' ').includes(s.slice(1));return this.tagName===s.toUpperCase();});}
  querySelectorAll(selector){const list=[];for(const child of this.children){if(child.matches(selector))list.push(child);list.push(...child.querySelectorAll(selector));}return list;}
  get labels(){return this.parentElement?.tagName==='LABEL'?[this.parentElement]:[];}
 }
 for(const [key,initial]of [['value',''],['checked',false],['disabled',false],['readOnly',false]])Object.defineProperty(E.prototype,key,{configurable:true,get(){return this['_'+key]??initial;},set(value){this['_'+key]=key==='value'?String(value):Boolean(value);}});
 class Input extends E{constructor(){super('input');this.type='text';}}
 for(const key of ['value','checked','disabled','readOnly'])Object.defineProperty(Input.prototype,key,Object.getOwnPropertyDescriptor(E.prototype,key));
 class Select extends E{constructor(){super('select');}}
 const body=new E('body'),forms={storage:new E('form'),reports:new E('form')};body.append(forms.storage,forms.reports);
 doc={body,activeElement:null,createElement:tag=>tag==='input'?new Input():tag==='select'?new Select():new E(tag),querySelectorAll:selector=>body.querySelectorAll(selector),getElementById:id=>[body,...walk(body)].find(n=>n.id===id)||null};
 function walk(root){return root.children.flatMap(n=>[n,...walk(n)]);}
 function source(id,type,value,form){const label=new E('label'),input=new Input();input.id=id;input.type=type;input.value=value;input.form=form;label.append(input);(form||body).append(label);return input;}
 const days=source('storage-days','number','14',forms.storage),timeout=source('support-model-timeout','number','300'),budget=source('storage-cap','number','20.125',forms.storage),time=source('reports-time','time','09:00',forms.reports),enabled=source('network-enabled','checkbox','');
 const events=[];for(const field of [days,timeout,budget,time])for(const name of ['input','change'])field.addEventListener(name,()=>events.push(field.id+':'+name));
 const context={document:doc,HTMLInputElement:Input,MutationObserver:class{constructor(fn){this.fn=fn;}observe(input){input._observers.push(this.fn);}},Event:class{constructor(type){this.type=type;}},queueMicrotask,Number,Object,Math};
 vm.runInNewContext(code,context);const get=doc.getElementById,slider=get('storage-days-slider');
 assert.equal(slider.value,'14');days.value='23';assert.equal(slider.value,'23','programmatic source fills update slider');
 slider.value='24';slider.dispatchEvent(new context.Event('input'));assert.equal(days.value,'24');assert.deepEqual(events.slice(-2),['storage-days:input','storage-days:change'],'slider emits both existing dirty events');
 days.disabled=true;assert.equal(slider.disabled,true);days.value='21';assert.equal(slider.value,'21');days.disabled=false;days.readOnly=true;assert.equal(slider.disabled,true);slider.value='22';slider.dispatchEvent(new context.Event('input'));assert.equal(days.value,'21');days.readOnly=false;assert.equal(slider.disabled,false);
 days.value='';assert.equal(days.value,'');assert.equal(slider.hidden,true,'partial invalid draft stays unchanged and is not falsely represented');days.value='14';assert.equal(slider.hidden,false);
 timeout.value='1201';assert.equal(get('support-model-timeout-slider').value,'1201');timeout.readOnly=true;assert.equal(get('support-model-timeout-slider').disabled,true);timeout.readOnly=false;
 const preset=get('storage-cap-preset');assert.equal(preset.value,'custom');assert.equal(budget.value,'20.125','fractional saved budget is never rounded');assert.equal(budget.parentElement.hidden,false);
 budget.value='500';assert.equal(preset.value,'500');preset.value='custom';preset.dispatchEvent(new context.Event('change'));assert.equal(doc.activeElement,budget);
 for(const value of ['1','100','100.25']){budget.value=value;budget.dispatchEvent(new context.Event('input'));assert.equal(budget.parentElement.hidden,false,'explicit Custom stays open through matching intermediate values');assert.equal(preset.value,'custom');}
 assert.equal(budget.value,'100.25');doc.activeElement=null;budget.value='100';assert.equal(preset.value,'100','external authoritative fill reselects its preset');budget.value='20.125';assert.equal(preset.value,'custom');budget.disabled=true;assert.equal(preset.disabled,true);budget.disabled=false;budget.readOnly=true;assert.equal(preset.disabled,true);budget.readOnly=false;
 const clock=get('reports-time-preset');clock.value='custom';clock.dispatchEvent(new context.Event('change'));for(const value of ['07:00','07:23']){time.value=value;time.dispatchEvent(new context.Event('input'));assert.equal(time.parentElement.hidden,false);assert.equal(clock.value,'custom');}assert.equal(time.value,'07:23');
 doc.activeElement=null;time.value='18:00';assert.equal(clock.value,'18:00');clock.value='custom';clock.dispatchEvent(new context.Event('change'));forms.reports.dispatchEvent(new context.Event('reset'));time._value='09:00';await new Promise(resolve=>queueMicrotask(resolve));assert.equal(clock.value,'09:00');assert.equal(time.parentElement.hidden,true);
 assert.equal(enabled.attrs.role,'switch');enabled.checked=true;assert.equal(enabled.parentElement.dataset.on,'true');assert.equal(enabled.parentElement.children[1].textContent,'On');enabled.checked=false;assert.equal(enabled.parentElement.children[1].textContent,'Off');
 assert.equal(events.filter(e=>e==='storage-days:change').length,1,'passive property synchronization never fires save/draft events');
 console.log('Visual editors: exact values, draft events, external fills, disabled/readOnly, custom typing, switches and reset passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
