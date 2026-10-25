"""Native active-Findings journey; synthetic same-origin evidence and no host actions."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from test_dashboard_findings_ui import findings_fixture


async def exercise_findings_workbench(browser, port, password, passed):
    from playwright.async_api import expect

    origin = f'http://127.0.0.1:{port}'
    base = findings_fixture()
    base['selected']['facts'].update(src_ip='192.0.2.10', dst_ip='1.1.1.1',
        protocol='TCP', recorded_evidence=dict(count=100, window_seconds=10))
    scenario = dict(mode='available', signed_in=False, analyzed=False)
    context = await browser.new_context(viewport=dict(width=1440, height=1000),
        reduced_motion='reduce', service_workers='block')
    requests, violations, errors, captures = [], [], [], []
    output = Path(__file__).resolve().parents[1] / 'artifacts/finding-inspector'

    async def local_only(route):
        target, method = urlsplit(route.request.url), route.request.method
        if target.scheme != 'http' or target.netloc != f'127.0.0.1:{port}':
            violations.append('nonlocal Findings request');await route.abort();return
        if method not in ('GET', 'HEAD'):
            if target.path == '/sign-in' and method == 'POST' and not scenario['signed_in']:
                scenario['signed_in'] = True;await route.continue_();return
            if target.path == '/api/findings' and method == 'POST':
                body = route.request.post_data_json
                requests.append((target.path, method, body.get('action')))
                if body.get('action') == 'analyze':
                    assert body['finding_id'] == base['items'][0]['id']
                    assert body['context_sha256'] == base['selected']['context_sha256']
                    scenario['analyzed'] = True
                    await route.fulfill(status=202, content_type='application/json',
                        body=json.dumps(dict(schema='megalodon-findings-action-v1', defense=base['defense'])));return
            violations.append('unexpected Findings host action');await route.abort();return
        requests.append((target.path, method, None))
        if target.path != '/api/findings':
            await route.continue_();return
        if scenario['mode'] == 'failed':
            await route.fulfill(status=503, content_type='application/json', body='{}');return
        value, query = deepcopy(base), parse_qs(target.query)
        value['generated_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        for key in ('start', 'end', 'source', 'severity'):
            if key in query:value['scope'][key] = query[key][0]
        if scenario['mode'] == 'empty':
            value.update(state='empty', items=[], selected=None)
            value['page'].update(returned=0, next_cursor=None, candidate_count=0, truncated=False)
        elif query.get('selected'):
            selected = next((row for row in value['items'] if row['id'] == query['selected'][0]), None)
            value['selected']['finding'] = selected
            if scenario['analyzed']:
                value['selected']['analysis'].update(state='ready',
                    explanation='The recorded observation contains 100 TCP packets; intent is unknown.',
                    alternative='Ordinary connection retries could produce similar observations.',
                    missing='The complete detector evaluation context is unavailable.',
                    citations=['E1'], model=value['model']['name'], model_digest=value['model']['digest'])
        else:value['selected'] = None
        await route.fulfill(status=200, content_type='application/json', body=json.dumps(value))

    await context.route('**/*', local_only)
    page = await context.new_page();page.set_default_timeout(10000)
    page.on('pageerror', lambda _: errors.append('uncaught Findings page error'))

    async def refresh(mode):
        scenario['mode'] = mode
        # Public user navigation restarts a read without inventing a test-only API.
        await page.locator('#workspace-tab-live').click()
        await page.locator('#workspace-tab-findings').click()

    try:
        await page.goto(origin+'/')
        await page.locator('#password').fill(password)
        await page.locator('#submit').click()
        await page.locator('#workspace-tab-findings').click()
        rows = page.locator('#fw-list button')
        await expect(rows).to_have_count(2)
        await expect(page.locator('#room-findings-table')).to_be_hidden()
        await rows.first.focus();await page.keyboard.press('Enter')
        await expect(page.locator('#fw-case-title')).to_have_text(base['items'][0]['title'])
        await expect(page.locator('#fw-story')).to_contain_text('192.0.2.10')
        await expect(page.locator('#fw-story')).to_contain_text('1.1.1.1')
        await expect(page.locator('#fw-metrics')).to_contain_text('100')
        await page.locator('.fw-trace > summary').click()
        await expect(page.locator('#fw-refs')).to_contain_text(base['selected']['evidence_refs'][0])
        passed('native active Findings selects retained facts and qualified references with keyboard input')

        await page.locator('#fw-search').fill('no-synthetic-match')
        await expect(rows).to_have_count(0)
        await page.locator('#fw-search').fill('')
        await expect(rows).to_have_count(2)
        passed('native Findings search preserves the selected case and changes no evidence')

        await page.locator('#fw-analyze').click()
        await expect(page.locator('#fw-ai-result')).to_contain_text('100 TCP packets')
        await expect(page.locator('#fw-ai-result')).to_contain_text('Ordinary connection retries')
        await expect(page.locator('#fw-action-status')).to_be_empty()
        passed('native selected-fact AI result stays in its own status lane')

        for width in (1440, 390, 375):
            await page.set_viewport_size(dict(width=width, height=1000))
            await page.locator('#fw-case-title').scroll_into_view_if_needed()
            fits = await page.locator('#findings-workbench').evaluate('''n =>
                n.scrollWidth<=n.clientWidth+1 && document.documentElement.scrollWidth<=innerWidth+1''')
            passed('native active Findings reflow '+str(width), fits)
            geometry = await page.locator('#fw-timeline').evaluate('''n => {
                const a=[...n.querySelectorAll('button')].map(x=>x.getBoundingClientRect());
                return a.every((r,i)=>a.slice(i+1).every(s=>r.right<=s.left+1||s.right<=r.left+1||r.bottom<=s.top+1||s.bottom<=r.top+1));
            }''')
            passed('native activity groups do not overlap '+str(width), geometry)
            output.mkdir(parents=True, exist_ok=True)
            path = output/f'active-findings-{width}.png'
            await page.screenshot(path=str(path), full_page=False, animations='disabled')
            captures.append(dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), viewport=width))

        await page.evaluate('''() => {window.__findingCaution=window.MegalodonCaution.open({
            owner:'synthetic-native-check',ip:'198.51.100.10',planId:'a'.repeat(32),
            expiresAt:new Date(Date.now()+60000).toISOString(),validate:()=>true});}''')
        await expect(page.locator('#containment-caution')).to_be_visible()
        await expect(page.locator('#caution-title')).to_be_focused()
        await expect(page.locator('#caution-ack')).not_to_be_checked()
        await expect(page.locator('#caution-confirm')).to_be_disabled()
        await page.keyboard.press('Escape')
        assert await page.evaluate('window.__findingCaution') is False
        passed('native phone caution begins at its heading unchecked and Escape never confirms')

        await refresh('failed')
        await expect(page.locator('#fw-status')).to_have_attribute('data-state', 'unavailable')
        await expect(page.locator('#fw-analyze')).to_be_disabled()
        await refresh('empty')
        await expect(rows).to_have_count(0)
        await expect(page.locator('#fw-analyze')).to_be_disabled()
        await refresh('available')
        # The observation feed is intentionally collapsed at phone widths.
        if await page.locator('#fw-feed').get_attribute('open') is None:
            await page.locator('#fw-feed > summary').click()
        await expect(rows).to_have_count(2)
        passed('native failed and empty Findings stay explicit and recover through navigation')
        passed('native Findings has no uncaught error or unintended host/network action',
            not errors and not violations and all(method != 'POST' or action == 'analyze' for _, method, action in requests))
        (output/'manifest.json').write_text(json.dumps(dict(schema='active-findings-browser-v1',
            status='passed', fixture='synthetic-documentation-addresses', captures=captures,
            scope='Native candidate UI with synthetic local responses; no real containment or installed-host acceptance'), indent=2)+'\n')
    finally:
        await context.close()
