const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',chunk=>input+=chunk);process.stdin.on('end',()=>{
 const {code,payload}=JSON.parse(input);
 let mutations=0;
 const document={activeElement:null,getElementById:()=>null};
 class Node {
  constructor(name,type=1,value='') {this.nodeName=name.toUpperCase();this.nodeType=type;this.nodeValue=value;this.childNodes=[];this.parentNode=null;this.ownerDocument=document;this.values=new Map();this.scrollTop=0;
   this.dataset=new Proxy({}, {get:(_,key)=>this.getAttribute('data-'+String(key).replace(/[A-Z]/g,c=>'-'+c.toLowerCase()))||undefined,set:(_,key,value)=>{this.setAttribute('data-'+String(key).replace(/[A-Z]/g,c=>'-'+c.toLowerCase()),value);return true;}});
  }
  get children(){return this.childNodes.filter(n=>n.nodeType===1);}
  get attributes(){return [...this.values].map(([name,value])=>({name,value}));}
  get lastChild(){return this.childNodes.at(-1);}
  get isConnected(){return this===document.body||!!this.parentNode?.isConnected;}
  get id(){return this.getAttribute('id')||'';} set id(value){this.setAttribute('id',value);}
  get open(){return this.hasAttribute('open');} set open(value){if(value)this.setAttribute('open','');else this.removeAttribute('open');}
  get textContent(){return this.nodeType===3?this.nodeValue:this.childNodes.map(n=>n.textContent).join('');}
  set textContent(value){this.replaceChildren();if(value!==undefined&&value!==null&&String(value))this.append(new Node('#text',3,String(value)));}
  hasAttribute(name){return this.values.has(name);}
  getAttribute(name){return this.values.get(name)??null;}
  setAttribute(name,value){if(this.isConnected)mutations++;this.values.set(name,String(value));}
  removeAttribute(name){if(this.hasAttribute(name)&&this.isConnected)mutations++;this.values.delete(name);}
  contains(node){return node===this||this.childNodes.some(child=>child.contains(node));}
  focus(){document.activeElement=this;}
  append(...nodes){for(const node of nodes)this.insertBefore(typeof node==='string'?new Node('#text',3,node):node,null);}
  insertBefore(node,before){if(node.parentNode)node.parentNode.removeChild(node);if(this.isConnected)mutations++;const index=before===null?this.childNodes.length:this.childNodes.indexOf(before);assert.ok(index>=0);this.childNodes.splice(index,0,node);node.parentNode=this;return node;}
  removeChild(node){if(this.isConnected){mutations++;if(node.contains(document.activeElement))document.activeElement=null;}this.childNodes.splice(this.childNodes.indexOf(node),1);node.parentNode=null;return node;}
  replaceChildren(...nodes){for(const node of [...this.childNodes])this.removeChild(node);this.append(...nodes);}
 }
 document.createElement=name=>new Node(name);document.body=new Node('body');
 const context={document,TextEncoder};vm.runInNewContext(code,context);
 const panel=new Node('div');document.body.append(panel);
 context.renderHardening(panel,payload);
 const detail=panel.children.find(n=>n.nodeName==='DETAILS'),summary=detail.children[0];detail.open=true;summary.focus();panel.scrollTop=325;
 mutations=0;context.renderHardening(panel,structuredClone(payload));
 assert.ok(panel.children.find(n=>n.nodeName==='DETAILS')===detail,'unchanged refresh retains the review node');
 assert.equal(detail.open,true,'a review remains expanded');assert.ok(document.activeElement===summary,'keyboard focus stays on the same summary');assert.equal(panel.scrollTop,325);
 assert.equal(mutations,0,'unchanged review causes no live element removals or replacements');
 const changed=structuredClone(payload);changed.reviewed_at='2026-10-18T06:31:00Z';
 changed.checks.find(c=>'check:'+c.id===detail.dataset.refreshKey).observed='Updated observation <b>as plain text</b>';
 context.renderHardening(panel,changed);assert.equal(detail.open,true);assert.ok(document.activeElement===summary);assert.match(detail.textContent,/Updated observation <b>as plain text<\/b>/);
 context.renderHardening(panel,{...changed,action_authority:'apply'});assert.match(panel.textContent,/unavailable/);assert.ok(!panel.textContent.includes('Updated observation'));assert.equal(panel.children.filter(n=>n.nodeName==='DETAILS').length,0,'invalid data clears prior facts');
 const render=context.stableReview((target,keys)=>{for(const key of keys){const item=new Node('details');item.dataset.refreshKey=key;const title=new Node('summary');title.textContent=key;item.append(title);target.append(item);}});
 render(panel,['a','b']);const a=panel.children[0],b=panel.children[1];a.open=true;b.open=true;b.children[0].focus();
 render(panel,['b','__proto__']);assert.ok(panel.children[0]===b);assert.equal(b.open,true);assert.ok(document.activeElement===b.children[0],'moving a retained row restores focus without scrolling');assert.equal(panel.children[1].open,false,'a new finding does not inherit another finding’s expansion');
 const outside=new Node('button');document.body.append(outside);outside.focus();render(panel,['__proto__','b']);assert.ok(document.activeElement===outside,'refresh never steals focus from another control');
 console.log('refresh preserves review identity, expansion, focus and scroll; changed/invalid observations remain truthful');
});
