const assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const nodes=new Map(),timers=new Map(),requests=[],listeners=new Map();let serial=0;
function node(){return {textContent:'',hidden:false,disabled:false,children:[],events:{},replaceChildren(...children){this.children=children;},append(...children){this.children.push(...children);},addEventListener(type,fn){this.events[type]=fn;}};}
const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
const document={hidden:false,querySelector(){return {};},getElementById:get,createElement:node,addEventListener(type,fn){listeners.set(type,fn);}};
const c={document,TextDecoder,Uint8Array,AbortController,setTimeout(fn,delay){timers.set(++serial,{fn,delay});return serial;},clearTimeout(id){timers.delete(id);},fetch(path,options){return new Promise(resolve=>requests.push({path,options,resolve}));}};
vm.runInNewContext(fs.readFileSync(0,'utf8'),c);
const settle=async()=>{for(let i=0;i<4;i++)await new Promise(resolve=>setImmediate(resolve));};
function respond(index){const value={schema:'megalodon-defense-v1',token:'t'.repeat(32),audit_ready:true,job:{state:'idle'},host_protection:{state:'unknown',verified_at:null,expires_at:null,policy:null,counters:null}};let sent=false;requests[index].resolve({ok:true,body:{getReader(){return {async read(){if(sent)return {done:true};sent=true;return {done:false,value:Buffer.from(JSON.stringify(value))};}};}}});}
(async()=>{
 assert.equal(get('host-protection-preview').disabled,true);
 respond(0);await settle();assert.equal(get('host-protection-preview').disabled,false);
 const timer=[...timers].find(([,t])=>t.delay===10000);timers.delete(timer[0]);const loading=timer[1].fn();
 assert.equal(get('host-protection-preview').disabled,true,'a refresh must visibly disable actions instead of silently ignoring a click');
 assert.equal(get('host-protection-check').disabled,true);respond(1);await loading;
 assert.equal(get('host-protection-preview').disabled,false,'completed refresh re-enables controls');
 document.hidden=true;listeners.get('visibilitychange')();
 assert.equal([...timers.values()].filter(t=>t.delay===10000||t.delay===750).length,0,'hidden document has no status-poll timer');
 document.hidden=false;listeners.get('visibilitychange')();assert.equal(requests.length,3,'foreground triggers a fresh read');
 respond(2);await settle();assert.equal(get('host-protection-check').disabled,false);
 assert.ok(requests.every(r=>r.options.method==='GET'),'visibility changes grant no host-action authority');
 console.log('refresh controls and visibility recovery passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
