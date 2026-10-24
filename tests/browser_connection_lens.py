"""Real-browser Connection lens acceptance using documentation-address fixtures.

Runs only in the existing opt-in Linux acceptance driver. Every host-action POST
is refused, and no browser request may leave the disposable dashboard origin.
"""
import asyncio
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

from test_dashboard_operations_ui import connection_lens_fixture
from megalodon.dashboard_assets import INDEX_HTML


async def exercise_connection_lens(browser, port, password, passed):
    from playwright.async_api import expect

    origin = f'http://127.0.0.1:{port}'
    context = await browser.new_context(viewport=dict(width=1440, height=1000),
        reduced_motion='reduce', service_workers='block')
    fixture = connection_lens_fixture()
    scenario = dict(signed_in=False, mode='ready', reads=0)
    requested, release, answered = asyncio.Event(), asyncio.Event(), asyncio.Event()
    requests, violations, errors, captures = [], [], [], []
    output = Path(__file__).resolve().parents[1] / 'artifacts' / 'connection-lens'

    async def local_only(route):
        target, method = urlsplit(route.request.url), route.request.method
        requests.append((target.path, method))
        if target.scheme != 'http' or target.netloc != f'127.0.0.1:{port}':
            violations.append('nonlocal connection-lens request');await route.abort();return
        if method not in ('GET', 'HEAD'):
            if method == 'POST' and target.path == '/sign-in' and not scenario['signed_in']:
                scenario['signed_in'] = True;await route.continue_();return
            violations.append('unexpected connection-lens host action');await route.abort();return
        if target.path == '/api/defense':
            await route.fulfill(status=503, content_type='application/json', body='{}');return
        if target.path == '/api/operations':
            scenario['reads'] += 1
            if scenario['mode'] == 'hold':
                requested.set();await release.wait()
            if scenario['mode'] == 'failed':
                await route.fulfill(status=503, content_type='application/json', body='{}');return
            value = deepcopy(fixture)
            value['observed_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            if scenario['mode'] == 'empty':value['endpoints'] = []
            if scenario['mode'] == 'dense':
                base = deepcopy(value['endpoints'][1])
                value['endpoints'] = [value['endpoints'][0]]
                for index in range(24):
                    row = deepcopy(base);row['ip'] = f'198.51.100.{index+1}'
                    row['names'][0]['name'] = f'long-observed-name-{index+1:02d}.example.test'
                    value['endpoints'].append(row)
            await route.fulfill(status=200, content_type='application/json', body=json.dumps(value))
            if requested.is_set():answered.set()
            return
        await route.continue_()

    await context.route('**/*', local_only)
    page = await context.new_page();page.set_default_timeout(10000)
    page.on('pageerror', lambda _: errors.append('uncaught connection-lens page error'))

    async def capture(name, target_id, width, height):
        output.mkdir(parents=True, exist_ok=True)
        scroll = await page.evaluate('''targetId => {
            const target=document.getElementById(targetId);
            const usePage=matchMedia('(max-width: 560px), (max-height: 500px)').matches;
            const surface=usePage?document.scrollingElement:document.getElementById('workspace-content');
            const top=usePage?0:surface.getBoundingClientRect().top;
            surface.scrollTop=Math.max(0,surface.scrollTop+target.getBoundingClientRect().top-top-12);
            return {surface:usePage?'document':'workspace-content',top:surface.scrollTop};
        }''', target_id)
        path=output/name
        await page.screenshot(path=str(path), full_page=False, animations='disabled')
        data=path.read_bytes()
        assert [int.from_bytes(data[16:20],'big'),int.from_bytes(data[20:24],'big')]==[width,height]
        captures.append(dict(file=name,sha256=hashlib.sha256(data).hexdigest(),
            viewport=dict(width=width,height=height),scroll=scroll,scenario=scenario['mode'],
            scope='Synthetic Connection lens; no installed-PC or live sensor acceptance'))

    async def refresh(mode):
        scenario['mode']=mode
        await page.locator('#ops-refresh').click()

    try:
        await page.goto(origin+'/')
        await page.locator('#password').fill(password);await page.locator('#submit').click()
        lens=page.locator('#ops-lens');nodes=lens.get_by_role('button')
        await expect(nodes).to_have_count(6)
        await expect(lens.locator('.ops-lens-link')).to_have_count(4)
        await expect(nodes.last).to_have_accessible_name(re.compile('Local relationship not established'))
        accessible=await lens.aria_snapshot()
        assert 'button "203.0.113.8' in accessible and 'Synthetic TLS SNI' in accessible
        passed('native lens exposes named endpoint buttons and only evidence-supported local links')
        await page.locator('#ops-pause').press('Tab')
        await expect(page.locator('#ops-filter-all')).to_be_focused()
        for target in ('observed','review','unknown'):
            await page.keyboard.press('Tab');await expect(page.locator('#ops-filter-'+target)).to_be_focused()
        await page.keyboard.press('Tab');await expect(nodes.first).to_be_focused()
        await page.keyboard.press('Enter');await expect(page.locator('#ops-inspector-title')).to_be_focused()
        await expect(page.locator('#ops-inspector-title')).to_have_text('203.0.113.8')
        await expect(page.locator('#ops-endpoint-detail')).to_contain_text('Synthetic TLS SNI')
        await nodes.nth(1).press('Space');await expect(page.locator('#ops-inspector-title')).to_have_text('203.0.113.9')
        passed('native Tab Enter Space selection updates and focuses the same inspector')
        await nodes.nth(2).focus()
        before=scenario['reads']
        # Predicate wait for an actual scheduled refresh, never a fixed delay-as-proof.
        for _ in range(60):
            if scenario['reads']>before:break
            await asyncio.sleep(.1)
        assert scenario['reads']>before
        await expect(nodes.nth(2)).to_be_focused()
        passed('native automatic refresh preserves lens keyboard focus')
        for state,count in (('observed',3),('review',1),('unknown',2),('all',6)):
            await page.locator('#ops-filter-'+state).click();await expect(nodes).to_have_count(count)
            await expect(page.locator('#ops-filter-'+state)).to_have_attribute('aria-pressed','true')
        for term in ('api.example.test','443','UDP','Synthetic review','regional','offline geography'):
            await page.locator('#ops-search').fill(term)
            await expect(page.locator('#ops-endpoint-list .ops-endpoint')).to_have_count(1)
        await page.locator('#ops-search').fill('regional')
        await page.locator('#ops-endpoint-list .ops-endpoint').click()
        await expect(page.locator('#ops-endpoint-detail')).to_contain_text('Identity not observed')
        await expect(page.locator('#ops-endpoint-detail')).to_contain_text('Synthetic regional network location')
        await page.locator('#ops-search').fill('no-such-evidence');await expect(lens).to_contain_text('No retained endpoints match')
        await page.locator('#ops-search').fill('internet exit anchor')
        await page.locator('#ops-endpoint-list .ops-endpoint').click()
        await expect(page.locator('#ops-endpoint-detail')).to_contain_text('Shared routing geometry only; not a location for this address')
        await page.locator('#ops-search').fill('')
        passed('native filters broad searches and local-anchor qualification remain truthful')
        scenario['mode']='hold';await page.locator('#ops-refresh').click()
        await asyncio.wait_for(requested.wait(),timeout=5)
        await page.locator('#ops-pause').click();scenario['mode']='empty';release.set()
        await asyncio.wait_for(answered.wait(),timeout=5)
        await expect(nodes).to_have_count(6);await expect(page.locator('#ops-pause')).to_have_text('Resume view')
        await page.locator('#ops-pause').click();await expect(lens).to_contain_text('No external endpoint')
        await refresh('ready');await expect(nodes).to_have_count(6)
        passed('native pause discards in-flight refresh and resume reads the new snapshot')
        await nodes.first.click()
        for width,height in ((1440,1000),(390,844),(320,740)):
            await page.set_viewport_size(dict(width=width,height=height))
            await capture(f'{width}-lens.png','ops-lens-title',width,height)
            await capture(f'{width}-inspector.png','ops-inspector-title',width,height)
            for selector in ('#ops-lens','.ops-inspector','#ops-endpoint-list'):
                assert await page.locator(selector).evaluate('(n)=>n.scrollWidth<=n.clientWidth+1'),selector
            assert await page.evaluate('document.documentElement.scrollWidth<=document.documentElement.clientWidth+1')
            # Native focus must bring the inspector into its actual scrollport.
            await nodes.first.press('Enter')
            assert await page.locator('#ops-inspector-title').evaluate('''n=>{
                const r=n.getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight;
            }''')
            passed('native lens inspector scrolling and reflow '+str(width))
        assert await lens.evaluate("n=>n.getAnimations({subtree:true}).filter(a=>a.playState==='running').length===0")
        await expect(page.locator('#live-motion-status')).to_contain_text('Reduced motion')
        passed('native reduced-motion preference leaves lens and globe static')
        for width,height in ((1440,1000),(390,844)):
            await page.set_viewport_size(dict(width=width,height=height))
            await refresh('dense');await expect(nodes).to_have_count(24)
            await capture(f'{width}-dense-lens.png','ops-lens-title',width,height)
        await refresh('failed');await expect(page.locator('#ops-lens-summary')).to_contain_text('refresh unavailable')
        passed('native failed refresh labels retained evidence unavailable')
        assert not violations and not errors
        assert not any(method=='POST' and path!='/sign-in' for path,method in requests)
        passed('native Connection lens requests no host action or nonlocal resource and has no page errors')
        manifest=dict(schema='connection-lens-browser-captures-v1',status='passed',browser=browser.version,
            candidate_sha=os.environ.get('GITHUB_SHA'),run_id=os.environ.get('GITHUB_RUN_ID'),
            dashboard_html_sha256=hashlib.sha256(INDEX_HTML.encode()).hexdigest(),captures=captures,
            limits=['Synthetic test server; installed-PC sensor coverage unverified',
                    'Accessible-tree and keyboard checks do not constitute human screen-reader acceptance',
                    'Viewport reflow does not establish native browser zoom or actual phone hardware acceptance',
                    'Screenshots require visual inspection; assertions do not establish label legibility',
                    'Request monitoring does not establish OS-level no-egress'])
        (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    finally:
        release.set();await context.close()
