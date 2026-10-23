const assert=require('node:assert/strict'),vm=require('node:vm');
let input='';process.stdin.on('data',x=>input+=x);process.stdin.on('end',()=>{
  const {code,readiness,valid,conflict,missing}=JSON.parse(input);
  function element(tag='div'){
    const n={tagName:tag.toUpperCase(),textContent:'',children:[],open:false,
      append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};
    Object.defineProperty(n,'innerHTML',{set(){throw Error('unsafe HTML sink');}});return n;
  }
  let time=Date.parse(valid.approved_at)+1000;
  class Clock extends Date{static now(){return time;}}
  const context={Date:Clock,document:{createElement:element},fetch(){throw Error('unexpected I/O');}};
  vm.runInNewContext(code,context);
  const panel=element(),text=n=>n.textContent+' '+n.children.map(text).join(' ');
  const render=value=>{context.renderRecoveryReadiness(panel,readiness,value);return text(panel);};
  assert.match(render(valid),/Pinned external backup and restore-test evidence/);
  assert.match(text(panel),/synthetic-backup-001/);
  assert.match(text(panel),/did not inspect this backup or run this restore test/);
  assert.match(text(panel),/Host file restoration unavailable/);
  panel.children.find(n=>n.id==='recovery-backup-details').open=true;
  render(valid);
  assert.equal(panel.children.find(n=>n.id==='recovery-backup-details').open,true);
  assert.equal(panel.children.find(n=>n.id==='recovery-integrity-details').open,false);
  assert.match(render(conflict),/legitimate source changes. Preserve current work/);
  const patch=(key,value)=>({...valid,[key]:value});
  const bad=[null,{},[],patch('state','ready'),patch('reason','trusted'),patch('source_id','<img src=x>'),
    patch('artifact_sha256','G'.repeat(64)),patch('expires_at','2026-02-30T12:00:00Z'),
    patch('approved_at',valid.backup_created_at),patch('conflicts','none'),
    {...valid,restore_eligible:true},{...missing,backup_id:valid.backup_id},
    patch('expires_at','9999-01-01T00:00:00Z')];
  const removed={...valid};delete removed.source_snapshot_sha256;bad.push(removed);
  for(const value of bad){
    render(valid);
    const body=render(value);
    assert.match(body,/External backup evidence unavailable/);
    assert.doesNotMatch(body,/synthetic-backup-001|Pinned external backup and restore-test evidence|<img/);
  }
  render(valid);time=Date.parse(valid.expires_at);
  assert.doesNotMatch(render(valid),/Pinned external backup and restore-test evidence/,'expiry is exclusive');
  time=Date.parse(valid.approved_at)-1;
  assert.doesNotMatch(render(valid),/Pinned external backup and restore-test evidence/,'future approval is refused');
  time=Date.parse(valid.approved_at)+1000;
  render(valid);context.renderRecoveryReadiness(panel,null,valid);
  assert.match(text(panel),/Recovery readiness is unavailable/);
  assert.doesNotMatch(text(panel),/synthetic-backup-001/,'failed Setup read clears external evidence');
  console.log('external backup evidence panel passed');
});
