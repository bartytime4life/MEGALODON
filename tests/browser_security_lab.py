"""Exercise the assembled HUD's offline lab with synthetic unavailable APIs.

No live service, capture, model, reference download or firewall action is used.
"""
import asyncio
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.dashboard_assets import DASHBOARD_CSS, DASHBOARD_JS, INDEX_HTML


async def main(destination):
    from playwright.async_api import async_playwright, expect
    destination.mkdir(parents=True, exist_ok=True)
    checks, errors, actions = [], [], []
    origin = 'http://127.0.0.1:18791'
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path='/usr/bin/google-chrome', headless=True, chromium_sandbox=True)
        context = await browser.new_context(viewport={'width':1440,'height':1000}, locale='en-US', reduced_motion='reduce', service_workers='block')
        async def route(request):
            url = request.request.url
            assert url.startswith(origin+'/'), 'unexpected external request'
            assert request.request.method == 'GET', 'the learning journey must never start an action'
            if '/api/' in url:
                actions.append(url)
                await request.fulfill(status=503, json={'error':'Synthetic unavailable API'})
            elif url.endswith('/assets/dashboard.js'):
                await request.fulfill(content_type='application/javascript; charset=utf-8', body=DASHBOARD_JS)
            elif url.endswith('/assets/dashboard.css'):
                await request.fulfill(content_type='text/css; charset=utf-8', body=DASHBOARD_CSS)
            else:
                await request.fulfill(content_type='text/html; charset=utf-8', body=INDEX_HTML)
        await context.route('**/*', route)
        page = await context.new_page()
        page.on('pageerror', lambda error: errors.append(str(error)))
        await page.goto(origin+'/#security-lab-title')
        await expect(page.locator('#workspace-tab-help')).to_have_attribute('aria-selected','true')
        await expect(page.locator('#security-lab-precision')).to_have_text('8.26%')
        checks.append('cold fragment opens Help; mathematics works independently of unavailable APIs')
        await page.get_by_role('button',name='More common condition',exact=True).focus()
        await page.keyboard.press('Enter')
        await expect(page.locator('#security-lab-precision')).to_have_text('90.91%')
        await expect(page.locator('#security-lab-recall')).to_have_text('90.00%')
        await expect(page.locator('#security-lab-fpr')).to_have_text('1.00%')
        await expect(page.locator('#security-lab-status')).to_contain_text('90.91%')
        checks.append('keyboard preset changes base rate while preserving recall and false-positive rate; status announces results')
        await page.get_by_role('button',name='Only one alert',exact=True).click()
        await expect(page.locator('#security-lab-interval')).to_contain_text('20.65% to 100.00%')
        checks.append('one observed success retains a wide hypothetical Wilson interval')
        await page.locator('#security-lab-tp').fill('')
        await expect(page.locator('#security-lab-results')).to_be_hidden()
        await expect(page.locator('#security-lab-tp')).to_have_attribute('aria-invalid','true')
        for key in ('tp','fp','fn','tn'):
            await page.locator('#security-lab-'+key).fill('0')
        await expect(page.locator('#security-lab-precision')).to_contain_text('Undefined')
        await expect(page.locator('#security-lab-accuracy')).to_contain_text('Undefined')
        checks.append('invalid input hides stale results; zero denominators stay undefined')
        await page.get_by_role('button',name='Rare condition',exact=True).click()
        await page.locator('.security-lab').screenshot(path=str(destination/'security-lab-desktop.png'))
        for width in (390,320):
            await page.set_viewport_size({'width':width,'height':900})
            assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth+1')
            assert await page.locator('.security-lab').evaluate('n=>n.scrollWidth<=n.clientWidth+1')
            await expect(page.locator('#security-lab-tp')).to_be_visible()
            checks.append('assembled HUD lab reflows without horizontal clipping at '+str(width))
        await page.locator('.security-lab').screenshot(path=str(destination/'security-lab-phone.png'))
        await page.get_by_text('Recognize attack patterns and choose the evidence to inspect',exact=True).click()
        await page.get_by_role('link',name='Review incoming access',exact=True).click()
        await expect(page.locator('#workspace-tab-live')).to_have_attribute('aria-selected','true')
        await expect(page.locator('#host-protection-title')).to_be_focused()
        checks.append('defensive lesson navigates to and focuses existing host controls without applying policy')
        assert errors == [], errors
        checks.append('no browser JavaScript errors or action requests')
        report=dict(passed=len(checks),checks=checks,browser=browser.version,
                    scope='Assembled HUD, hypothetical lab counts and synthetic unavailable APIs; no host actions')
        (destination/'security-lab-browser.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
        await context.close()
        await browser.close()


if __name__ == '__main__':
    asyncio.run(main(Path(sys.argv[1])))
