const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs'), vm = require('node:vm');
function runtime(saved = null, unavailable = false) {
  const writes = [];
  const context = {URL, localStorage: {getItem(){return saved;}, setItem(key, value){if(unavailable) throw new Error('disabled'); writes.push([key,value]);}}};
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(require.resolve('../dist/controls.js'), 'utf8') + '\nglobalThis.controls=MegalodonControls;', context);
  return {controls:context.controls, writes};
}
test('console URLs refuse executable protocols, credentials and secret-bearing queries', () => {
  const {controls} = runtime();
  for (const value of ['javascript:alert(1)', 'file:///tmp/x', 'data:text/html,hi', 'ftp://host', 'https://user:pass@host/', 'https://host/?token=secret', 'https://host/#secret', 'https://ho\\st/', 'https://host/\n', '//host', 'x'.repeat(2049)]) assert.throws(() => controls.consoleURL(value));
  assert.equal(controls.consoleURL('http://127.0.0.1:9392/'), 'http://127.0.0.1:9392/');
  assert.equal(controls.consoleURL('https://monitor.example.org/zabbix'), 'https://monitor.example.org/zabbix');
});
test('only the closed fourteen tool identities persist and malformed saved values are dropped', () => {
  const {controls, writes} = runtime(JSON.stringify({greenbone:'http://127.0.0.1:9392/', qwen:'javascript:alert(1)', other:'https://example.org/'}));
  assert.deepEqual(Object.keys(controls.links()), ['greenbone']);
  assert.throws(() => controls.save('__proto__', 'https://example.org/'));
  controls.save('zabbix', 'https://monitor.example.org/');
  assert.equal(JSON.parse(writes[0][1]).zabbix, 'https://monitor.example.org/');
  controls.save('zabbix', '');
  assert.equal(controls.links().zabbix, undefined);
});
test('storage failures remain usable and explicitly report session-only persistence', () => {
  const {controls} = runtime(null, true);
  assert.equal(controls.save('nagios', 'http://127.0.0.1:8080/'), false);
  assert.equal(controls.links().nagios, 'http://127.0.0.1:8080/');
});
test('shared controls never fetch, embed a console, or execute command text', () => {
  const source = fs.readFileSync(require.resolve('../dist/controls.js'), 'utf8');
  assert.doesNotMatch(source, /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|iframe|innerHTML|\beval\s*\(|new Function/);
  assert.match(source, /navigator.clipboard.writeText/);
  assert.match(source, /noopener noreferrer/);
});

test('companion panel saves an address and copies only the selected Zabbix role', async () => {
  class Element {
    constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.value='';this.textContent='';}
    append(...items){this.children.push(...items);} replaceChildren(...items){this.children=items;}
    setAttribute(){} removeAttribute(key){delete this[key];} focus(){}
    addEventListener(event, action){this.listeners[event]=action;}
    querySelector(tag){return this.children.find(child=>child.tag===tag);}
  }
  const copied=[];
  const context={URL, document:{createElement:tag=>new Element(tag)}, localStorage:{getItem(){return null;},setItem(){}}, navigator:{clipboard:{async writeText(value){copied.push(value);}}}};
  vm.createContext(context);
  for(const file of ['lifecycle.js','controls.js']) vm.runInContext(fs.readFileSync(require.resolve('../dist/'+file),'utf8'),context);
  const parent=new Element('main'); context.parent=parent;
  vm.runInContext("MegalodonControls.mount(parent, 'zabbix', 'Zabbix')",context);
  const all=element=>[element,...element.children.flatMap(all)];
  const find=text=>all(parent).find(element=>element.textContent===text);
  const input=all(parent).find(element=>element.tag==='input');
  input.value='http://127.0.0.1:8080/zabbix'; find('Save link').listeners.click();
  assert.equal(find('Open companion console ↗').href, input.value);
  assert.equal(find('Open companion console ↗').hidden, false);
  assert.deepEqual(copied, []);
  assert.equal(find('Copy reinstall'), undefined);
  const select=all(parent).find(element=>element.tag==='select');
  select.value='agent2'; select.listeners.change();
  await find('Copy reinstall').listeners.click();
  assert.deepEqual(copied, ['sudo apt-get install --reinstall zabbix-agent2']);
  find('Remove link').listeners.click();
  assert.equal(find('Open companion console ↗').hidden, true);
});
