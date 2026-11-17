"""Opt-in installed-Chrome acceptance for the shipped host-protection component.

All HTTP replies and firewall outcomes are synthetic and intercepted locally.
No helper, sensor, collector or live firewall action is invoked.
"""
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.dashboard_assets import DASHBOARD_CSS, DASHBOARD_JS, INDEX_HTML
from megalodon.dashboard_host_protection import HOST_PROTECTION_HTML, HOST_PROTECTION_JS


def stamp(seconds=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')


async def main(destination):
    from playwright.async_api import async_playwright, expect
    destination.mkdir(parents=True, exist_ok=True)
    value = dict(schema='megalodon-defense-v1', token='t'*32, audit_ready=True,
                 job=dict(state='idle', request_id=None, action=None, message='Synthetic response fixture', result=None),
                 host_protection=dict(state='unknown', verified_at=None, expires_at=None, policy=None, counters=None))
    calls, checks, errors = [], [], []
    pending_preview = None
    fail_reads = False
    full_shell = False
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path='/usr/bin/google-chrome', headless=True)
        context = await browser.new_context(viewport={'width': 1440, 'height': 1100}, reduced_motion='reduce', service_workers='block')
        async def route(request):
            nonlocal pending_preview
            url = request.request.url
            assert url.startswith('http://127.0.0.1:18789/'), 'unexpected egress'
            if url.endswith('/api/defense'):
                if request.request.method == 'GET':
                    if fail_reads:
                        await request.fulfill(status=503, json={'error': 'synthetic unavailable'})
                    else:
                        await request.fulfill(json=deepcopy(value))
                    return
                body = request.request.post_data_json
                assert request.request.headers['x-megalodon-defense-token'] == 't'*32
                calls.append(body)
                action = body['action']
                job = dict(state='finished', request_id=f'{len(calls):032x}', action=action, message='Synthetic workflow finished.', result=None)
                if action == 'plan_host_protection':
                    plan = dict(kind='host_protection', id=f'{len(calls):032x}', expires_at=stamp(60), policy=body['policy'])
                    job.update(state='running')
                    pending_preview = dict(job, state='finished', result=plan)
                elif action == 'apply_host_protection':
                    assert body == {'action': action, 'plan_id': pending_preview['result']['id']}
                    value['host_protection'] = dict(state='last_verified_active', verified=True, active=True, present=True,
                        verified_at=stamp(), expires_at=stamp(900), remaining_seconds=899,
                        policy=deepcopy(pending_preview['result']['policy']), counters={'invalid': 2, 'unsolicited': 37, 'allowed_service': 5})
                elif action == 'remove_host_protection':
                    value['host_protection'] = dict(state='last_verified_inactive', verified=True, active=False, present=False,
                        verified_at=stamp(), expires_at=None, remaining_seconds=0, policy=None,
                        counters={'invalid': 0, 'unsolicited': 0, 'allowed_service': 0})
                elif action != 'check_host_protection':
                    raise AssertionError(action)
                value['job'] = job
                await request.fulfill(status=202, json=deepcopy(value))
            elif url.endswith('/assets/dashboard.js'):
                await request.fulfill(content_type='application/javascript; charset=utf-8', body=DASHBOARD_JS)
            elif url.endswith('/assets/dashboard.css'):
                await request.fulfill(content_type='text/css; charset=utf-8', body=DASHBOARD_CSS)
            elif '/api/' in url or '/assets/' in url:
                await request.fulfill(status=503, json={'error': 'synthetic unavailable'})
            elif full_shell:
                await request.fulfill(content_type='text/html; charset=utf-8', body=INDEX_HTML)
            elif url.endswith('/host.js'):
                await request.fulfill(content_type='application/javascript', body=HOST_PROTECTION_JS)
            elif url.endswith('/host.css'):
                await request.fulfill(content_type='text/css; charset=utf-8', body=DASHBOARD_CSS+'\nhtml,body{height:auto!important;overflow:auto!important}.shell{height:auto!important;max-height:none!important;overflow:visible!important;display:block!important}')
            else:
                await request.fulfill(content_type='text/html; charset=utf-8', body='<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/host.css"><script defer src="/host.js"></script></head><body><main class="shell"><p>SYNTHETIC ACCEPTANCE FIXTURE · no host actions</p>'+HOST_PROTECTION_HTML+'</main></body></html>')
        await context.route('**/*', route)
        page = await context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.set_default_timeout(10000)
        await page.goto('http://127.0.0.1:18789/')
        await expect(page.locator('#host-protection-preview')).to_be_enabled()
        assert calls == []
        checks.append('initial read never applies policy or asks for privileged status')
        await page.locator('#host-protection-config > summary').click()
        await page.locator('#host-protection-add').click()
        await page.locator('[data-field="port"]').fill('22')
        await page.locator('[data-field="source"]').fill('192.168.1.0/24')
        await page.locator('#host-protection-preview').click()
        await expect(page.locator('#host-protection-preview')).to_be_disabled()
        await page.locator('[data-field="port"]').fill('443')
        value['job'] = pending_preview
        await expect(page.locator('#host-protection-preview')).to_be_enabled()
        await expect(page.locator('#host-protection-apply')).to_be_hidden()
        checks.append('editing while preview runs rejects its stale result')
        await page.locator('#host-protection-preview').click()
        await expect(page.locator('#host-protection-preview')).to_be_disabled()
        value['job'] = pending_preview
        await expect(page.locator('#host-protection-apply')).to_be_visible()
        await expect(page.locator('#host-protection-plan')).to_contain_text('TCP port 443 from 192.168.1.0/24')
        await page.screenshot(path=str(destination/'host-protection-desktop.png'), full_page=True)
        await page.locator('[data-field="source"]').fill('192.168.1.25/32')
        await expect(page.locator('#host-protection-apply')).to_be_hidden()
        checks.append('editing a completed preview revokes apply authority')
        await page.locator('#host-protection-preview').click()
        await expect(page.locator('#host-protection-preview')).to_be_disabled()
        value['job'] = pending_preview
        await expect(page.locator('#host-protection-apply')).to_be_enabled()
        await page.locator('#host-protection-apply').focus()
        await page.keyboard.press('Enter')
        await expect(page.locator('#host-protection-badge')).to_have_text('Last verified active')
        await expect(page.locator('#host-protection-counts')).to_contain_text('37 unsolicited dropped')
        checks.append('keyboard confirmation sends only the exact preview id and shows verified counters')
        await expect(page.locator('#host-protection-current-services')).to_contain_text('192.168.1.25/32')
        await page.locator('[data-field="port"]').fill('9999')
        await page.locator('#host-protection-reuse').click()
        await expect(page.locator('[data-field="port"]')).to_have_value('443')
        await expect(page.locator('#host-protection-apply')).to_be_hidden()
        checks.append('last verified policy is visible and explicit reuse still needs a new preview')
        for width in (390, 320):
            await page.set_viewport_size({'width': width, 'height': 1000})
            assert await page.locator('.host-protection').evaluate('n => n.scrollWidth <= n.clientWidth + 1')
            assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth + 1')
            checks.append('no horizontal overflow at '+str(width)+' pixels')
        await page.set_viewport_size({'width': 390, 'height': 1000})
        await page.screenshot(path=str(destination/'host-protection-mobile.png'), full_page=True)
        # Expiry is visible without a new privileged kernel read.
        await page.clock.install()
        await page.clock.fast_forward(901000)
        await expect(page.locator('#host-protection-badge')).to_have_text('Lease elapsed')
        assert len(calls) == 4
        checks.append('elapsed lease is never shown as current protection')
        await page.locator('#host-protection-remove').click()
        await expect(page.locator('#host-protection-badge')).to_have_text('Last verified inactive')
        checks.append('explicit removal shows verified inactive readback')
        fail_reads = True
        await page.clock.fast_forward(11000)
        await expect(page.locator('#host-protection-badge')).to_have_text('Unknown')
        await expect(page.locator('#host-protection-preview')).to_be_disabled()
        await expect(page.locator('#host-protection-counts')).to_be_empty()
        checks.append('failed refresh clears stale status, counters and action authority')
        fail_reads = False
        full_shell = True
        await page.close()
        page = await context.new_page()
        await page.set_viewport_size({'width': 390, 'height': 1000})
        page.on('pageerror', lambda error: errors.append(str(error)))
        await page.goto('http://127.0.0.1:18789/')
        await expect(page.locator('#workspace-live #host-protection-title')).to_be_visible()
        await expect(page.locator('#host-protection-preview')).to_be_enabled()
        await page.locator('#host-protection-config > summary').click()
        await page.locator('#host-protection-add').click()
        await expect(page.locator('[data-field="port"]')).to_be_focused()
        assert await page.locator('.host-protection').evaluate('n => n.scrollWidth <= n.clientWidth + 1')
        await page.screenshot(path=str(destination/'host-protection-in-hud.png'))
        checks.append('full assembled HUD loads the component and preserves editable controls at phone width')
        assert errors == [], errors
        checks.append('no browser JavaScript errors')
        report = {'passed': len(checks), 'checks': checks, 'browser': browser.version,
                  'scope': 'Shipped component with synthetic HTTP responses; no host protection was applied.'}
        (destination/'host-protection-browser.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
        await context.close()
        await browser.close()


if __name__ == '__main__':
    asyncio.run(main(Path(sys.argv[1])))
