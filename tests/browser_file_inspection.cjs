/* Opt-in real Chrome acceptance of the shipped inspection component.
 * Read JSON containing html/css/code/report on stdin. Requires Playwright.
 * Synthetic HTTP replies exercise UI only; no analyzer qualification claim.
 */
const assert = require('node:assert/strict'), {chromium} = require('playwright');
let input='';process.stdin.on('data',part=>input+=part);
process.stdin.on('end',async()=>{
  const {html,css,code,report}=JSON.parse(input),origin='http://127.0.0.1:9876';
  const browser=await chromium.launch({channel:'chrome',headless:true,args:['--no-sandbox']});
  try{
    const page=await browser.newPage({viewport:{width:1280,height:1000}}),requests=[],errors=[];
    page.on('pageerror',error=>errors.push(error.message));
    const token='A_z-9'.repeat(6)+'Z_';
    let payload={schema:'megalodon-file-inspection-status-v1',state:'idle',job_id:null,runtime:{state:'ready',message:'The synthetic inspector runtime is ready.'},max_bytes:67108864,report:null,token};
    const bytes=Buffer.alloc(report.size_bytes),job='b'.repeat(32);bytes.write('MZ harmless synthetic UI fixture');
    let slow=false,held=null,denial=null,denialStatus=403;
    await page.route(origin+'/**',async route=>{
      const request=route.request(),path=new URL(request.url()).pathname;
      if(path==='/')return route.fulfill({contentType:'text/html',body:'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Inspection component acceptance</title><link rel="stylesheet" href="/assets/dashboard.css"><script src="/assets/inspection.js" defer></script></head><body><main class="shell"><div class="workspace-scroll"><section class="workspace-view"><section class="companion-section"><div class="companion-grid">'+html+'</div></section></section></div></main></body></html>'});
      if(path==='/assets/dashboard.css')return route.fulfill({contentType:'text/css',body:css});
      if(path==='/assets/inspection.js')return route.fulfill({contentType:'application/javascript',body:'const localHudLaunch={};\n'+code});
      requests.push({path,method:request.method(),body:request.postDataBuffer(),headers:request.headers()});
      if(path.startsWith('/api/file-inspection')&&denial)return route.fulfill({status:denialStatus,contentType:'application/json',body:JSON.stringify(denial)});
      if(path==='/api/file-inspection/run'){
        assert.equal(request.headers()['content-type'],'application/octet-stream');assert.equal(request.headers()['x-megalodon-config-token'],token);
        assert.deepEqual(request.postDataBuffer(),bytes);assert.ok(!Object.keys(request.headers()).some(k=>/file.?name/i.test(k)));
        if(slow){held=route;payload={...payload,state:'receiving',job_id:job,report:null};return;}
        payload={...payload,state:'partial',job_id:job,report};
      }
      if(path==='/api/file-inspection/cancel'){assert.equal(request.postData(),'{}');assert.equal(request.headers()['x-megalodon-config-token'],token);payload={...payload,state:'cancelled',report:null};}
      if(path.startsWith('/api/file-inspection'))return route.fulfill({status:request.method()==='POST'?202:200,contentType:'application/json',body:JSON.stringify(payload)});
      throw Error('Unexpected browser request: '+path);
    });
    await page.goto(origin);await page.getByRole('button',{name:'Check inspector',exact:true}).waitFor();
    await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('Ready.'));
    const input=page.getByLabel('Choose one program to inspect');
    await input.setInputFiles({name:'<img src=x onerror=alert(1)>.exe',mimeType:'application/octet-stream',buffer:bytes});
    assert.equal(requests.filter(r=>r.method==='POST').length,0,'choosing a file sends no POST');
    assert.match(await page.locator('#file-inspection-selection').textContent(),/<img src=x/);
    await page.getByRole('button',{name:'Inspect',exact:true}).focus();assert.equal(await page.evaluate(()=>document.activeElement.id),'file-inspection-run');
    assert.notEqual(await page.locator('#file-inspection-run').evaluate(n=>getComputedStyle(n).outlineStyle),'none');
    await page.keyboard.press('Enter');await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('Partial inspection'));
    assert.equal(requests.filter(r=>r.path.endsWith('/run')).length,1);
    assert.match(await page.locator('#file-inspection-tools').textContent(),/LIEF · structure: Completed/);
    assert.match(await page.locator('#file-inspection-tools').textContent(),/Detect It Easy · identification: Unsupported/);
    const badges=await page.locator('#file-inspection-tools li').evaluateAll(items=>items.map(n=>n.getBoundingClientRect().top));
    assert.ok(Math.abs(badges[0]-badges[1])<=1,'parallel analyzer badges align at desktop width');
    assert.match(await page.locator('#file-inspection-clues').textContent(),/Identification clues are unavailable/);
    const disclosure=page.locator('#file-inspection-clues details').first(),summary=disclosure.locator('summary');
    assert.equal(await disclosure.evaluate(n=>n.open),false);
    const beforeDisclosure=requests.length;await summary.focus();await page.keyboard.press('Enter');
    assert.equal(await disclosure.evaluate(n=>n.open),true);
    assert.match(await disclosure.textContent(),/Slice 1 \(arm64, 64-bit\): 1 writable\/executable region/);
    for(const label of ['Observed fact','Source','Meaning','Limit'])assert.match(await disclosure.textContent(),new RegExp(label));
    assert.equal(requests.length,beforeDisclosure,'opening evidence does not request more data');
    assert.notEqual(await summary.evaluate(n=>getComputedStyle(n).outlineStyle),'none');
    assert.equal(await page.locator('#file-inspection-details').evaluate(n=>n.open),false);
    await page.locator('#file-inspection-details summary').click();
    assert.match(await page.locator('#file-inspection-technical').textContent(),/1 of 1/);
    assert.equal(await page.locator('#file-inspection img').count(),0,'hostile labels remain plain text');
    const downloadEvent=page.waitForEvent('download');await page.getByRole('button',{name:'Export JSON'}).click();const download=await downloadEvent;
    assert.equal(download.suggestedFilename(),'megalodon-file-inspection.json');
    const stream=await download.createReadStream();let output='';for await(const part of stream)output+=part;
    assert.deepEqual(JSON.parse(output),report);assert.doesNotMatch(output,/filename|job_id|token|sha256|raw|harmless synthetic UI fixture/);
    if(process.env.MEGALODON_INSPECTION_SCREENSHOTS)await page.locator('.fi-clues').screenshot({path:process.env.MEGALODON_INSPECTION_SCREENSHOTS+'/desktop.png'});
    await page.setViewportSize({width:390,height:844});
    const dimensions=await page.locator('#file-inspection').evaluate(n=>({left:n.getBoundingClientRect().left,right:n.getBoundingClientRect().right,scroll:n.scrollWidth,width:n.clientWidth}));
    assert.ok(dimensions.left>=0&&dimensions.right<=390,JSON.stringify(dimensions));assert.ok(dimensions.scroll<=dimensions.width+1,'panel fits mobile without horizontal scrolling');
    for(const selector of ['#file-inspection-run','#file-inspection-check','#file-inspection-export']){
      const box=await page.locator(selector).boundingBox();assert.ok(box.height>=44&&box.width>=44);
    }
    if(process.env.MEGALODON_INSPECTION_SCREENSHOTS)await page.locator('#file-inspection').screenshot({path:process.env.MEGALODON_INSPECTION_SCREENSHOTS+'/mobile.png'});
    // A complete report can carry multiple identification labels. Hostile text is
    // injected separately to check rendering; it is not a native-parser claim.
    const complete=JSON.parse(JSON.stringify(report));complete.state='completed';complete.tools[1].state='completed';
    complete.structure.slices_detected=2;complete.structure.slices.push({...complete.structure.slices[0],architecture:'x86_64',writable_executable:2});
    complete.identification=[{kind:'packer',name:'<img src=x onerror=alert(1)>'},{kind:'protector',name:'Example protector'},{kind:'compiler',name:'GCC'},{kind:'linker',name:'GNU ld'}];
    complete.clues.push({code:'packed',title:'Packing or protection identified',meaning:'Packing can make a program harder to inspect.'});
    payload={...payload,state:'completed',report:complete};await page.getByRole('button',{name:'Check inspector',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('Inspection completed'));
    assert.equal(await page.locator('#file-inspection-clues details').count(),4);
    assert.match(await page.locator('#file-inspection-clues').textContent(),/Slice 2 \(x86_64, 64-bit\): 2 writable\/executable regions/);
    assert.match(await page.locator('#file-inspection-clues').textContent(),/<img src=x[\s\S]*Example protector/);
    assert.equal(await page.locator('#file-inspection img').count(),0);
    const expanded=page.locator('#file-inspection-clues summary');
    for(let i=0;i<await expanded.count();i++)await expanded.nth(i).click();
    const wide=await page.locator('#file-inspection').evaluate(n=>n.scrollWidth>n.clientWidth+1);assert.equal(wide,false);
    await input.setInputFiles({name:'another.bin',mimeType:'application/octet-stream',buffer:bytes});
    assert.equal(await page.locator('#file-inspection-result').isVisible(),false);
    await page.getByRole('button',{name:'Check inspector',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-report-scope').textContent.startsWith('Earlier report'));
    slow=true;await page.getByRole('button',{name:'Inspect',exact:true}).click();
    await page.getByRole('button',{name:'Cancel inspection',exact:true}).waitFor();
    await page.getByRole('button',{name:'Cancel inspection',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('Inspection cancelled'));
    if(held)try{await held.fulfill({status:202,contentType:'application/json',body:JSON.stringify({...payload,state:'running'})});}catch(error){if(!/cancel|abort|disposed|closed/i.test(error.message))throw error;}
    assert.equal(requests.filter(r=>r.path.endsWith('/cancel')).length,1);
    assert.match(await page.locator('#file-inspection-status').textContent(),/Inspection cancelled/);
    const denied={error:'SERVER_ERROR_STRING_MUST_NOT_RENDER <img src=x>',code:'file_inspection_sign_in_required'};
    denial=denied;await page.getByRole('button',{name:'Check inspector',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('File inspection requires local HUD sign-in.'));
    assert.equal(await page.getByRole('button',{name:'Inspect',exact:true}).isDisabled(),true);
    const signIn=page.locator('#file-inspection-sign-in'),link=signIn.getByRole('link',{name:'Open Local sign-in in Setup →'});
    assert.equal(await signIn.isVisible(),true);assert.equal(await link.getAttribute('href'),'#setup-account-title');
    assert.doesNotMatch(await page.locator('#file-inspection-status').textContent(),/SERVER_ERROR_STRING/);
    assert.equal(await page.locator('#file-inspection-runtime').isVisible(),false);
    const deniedPosts=requests.filter(r=>r.method==='POST').length;
    await input.setInputFiles({name:'selected-only.exe',mimeType:'application/octet-stream',buffer:bytes});
    assert.match(await page.locator('#file-inspection-status').textContent(),/requires local HUD sign-in/);
    await page.getByRole('button',{name:'Check inspector',exact:true}).focus();await page.keyboard.press('Tab');
    assert.equal(await page.evaluate(()=>document.activeElement.getAttribute('href')),'#setup-account-title');
    assert.notEqual(await link.evaluate(n=>getComputedStyle(n).outlineStyle),'none');
    await page.keyboard.press('Enter');assert.ok(page.url().endsWith('#setup-account-title'));
    assert.equal(requests.filter(r=>r.method==='POST').length,deniedPosts,'sign-in hint only navigates; it never enables sign-in or launches a HUD');
    for(const width of [1280,390]){
      await page.setViewportSize({width,height:844});
      const size=await signIn.evaluate(n=>({scroll:n.scrollWidth,width:n.clientWidth,right:n.getBoundingClientRect().right}));
      assert.ok(size.scroll<=size.width+1&&size.right<=width,'sign-in hint fits desktop and mobile');
      if(process.env.MEGALODON_UI_SCREENSHOT_DIR){const fs=require('node:fs'),path=require('node:path');fs.mkdirSync(process.env.MEGALODON_UI_SCREENSHOT_DIR,{recursive:true});await page.locator('#file-inspection').screenshot({path:path.join(process.env.MEGALODON_UI_SCREENSHOT_DIR,'sign-in-required-'+width+'.png')});}
    }
    denial=null;await page.getByRole('button',{name:'Check inspector',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-sign-in').hidden&& !document.getElementById('file-inspection-run').disabled);
    assert.equal(requests.filter(r=>r.method==='POST').length,deniedPosts,'recovery never auto-submits the selected file');
    for(const [body,status] of [[{...denied,code:'different_error'},403],[denied,401]]){
      denial=body;denialStatus=status;await page.getByRole('button',{name:'Check inspector',exact:true}).click();
      await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('Inspector status is unavailable.'));
      assert.equal(await signIn.isVisible(),false);assert.doesNotMatch(await page.locator('#file-inspection-status').textContent(),/SERVER_ERROR_STRING|requires local HUD sign-in/);
      denial=null;await page.getByRole('button',{name:'Check inspector',exact:true}).click();
      await page.waitForFunction(()=>!document.getElementById('file-inspection-run').disabled);
    }
    denial=denied;denialStatus=403;await page.getByRole('button',{name:'Inspect',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('File inspection requires local HUD sign-in.'));
    assert.equal(await signIn.isVisible(),true);assert.equal(await page.getByRole('button',{name:'Inspect',exact:true}).isDisabled(),true);
    denial=null;await page.getByRole('button',{name:'Check inspector',exact:true}).click();await page.waitForFunction(()=>!document.getElementById('file-inspection-run').disabled);
    await page.getByRole('button',{name:'Inspect',exact:true}).click();await page.getByRole('button',{name:'Cancel inspection',exact:true}).waitFor();
    denial=denied;await page.getByRole('button',{name:'Cancel inspection',exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('file-inspection-status').textContent.startsWith('File inspection requires local HUD sign-in.'));
    if(held)try{await held.fulfill({status:202,contentType:'application/json',body:JSON.stringify({...payload,state:'running'})});}catch(error){if(!/cancel|abort|disposed|closed/i.test(error.message))throw error;}
    assert.equal(await signIn.isVisible(),true);assert.doesNotMatch(await page.locator('#file-inspection-status').textContent(),/cancelled/i);
    assert.deepEqual(errors,[]);
    console.log('PASS real Chrome: explicit File bytes, no selection upload, keyboard activation/focus, plain-text hostile labels, partial coverage, collapsed details, export, stale association, cancel, 390px fit, sign-in denial/recovery, setup-only navigation and generic error fallback');
  }finally{await browser.close();}
}).on('error',error=>{console.error(error);process.exitCode=1;});
process.on('unhandledRejection',error=>{console.error(error);process.exitCode=1;});
