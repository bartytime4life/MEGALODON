"""Synthetic findings journey over the shipped HUD, with all action routes refused."""
from datetime import datetime, timedelta, timezone
import json
from urllib.parse import urlsplit

from test_host_findings_ui import host_findings_fixture


def configuration_fixture(mode, observed):
    host = host_findings_fixture(observed.strftime('%Y-%m-%dT%H:%M:%SZ'))
    host.update(feeds=[], message='Synthetic host observations; no host audit was run.', baseline_present=True)
    if mode in ('missing', 'unavailable'):
        host.update(audit_state=mode, integrity_state=mode, audit=None, integrity=None)
    elif mode == 'legacy':
        host['audit_state'] = 'legacy'
        del host['audit']['review']
    elif mode == 'stale':
        host['audit']['checked_at'] = (observed-timedelta(days=8)).strftime('%Y-%m-%dT%H:%M:%SZ')
    elif mode == 'baseline':
        host['integrity']['review'].update(operation='baseline', exit_code=0)
        host['integrity']['metrics'] = dict.fromkeys(host['integrity']['metrics'], 0)
    elif mode == 'malformed':
        host['audit']['review']['items'][0]['kind'] = 'verified_incident'
    elif mode != 'available':
        raise ValueError('Unknown synthetic findings scenario.')
    return dict(schema='megalodon-support-config-v1', token='b'*32,
        interfaces=[dict(name='eth0', default=True, up=True)],
        settings=dict(interface='eth0', nmap_target='127.0.0.1/32', scan_folder='Downloads'),
        tool_directories={}, tool_directories_status='ready',
        job=dict(state='idle', action=None, message='Synthetic fixture only.', started_at=None, finished_at=None),
        capture=dict(state='idle', interface='', received=0, accepted=0, skipped=0,
                     started_at=None, finished_at=None, message='No capture in this rehearsal.'),
        tools=[], background=dict(enabled=False, state='stopped', message='Off.', session_count=0),
        geography_enabled=False, command='python -m megalodon.support_config', host_security=host)


async def exercise_host_findings(browser, port, password, passed):
    """Use real navigation/DOM/CSS and a synthetic configuration GET, never tools."""
    from playwright.async_api import expect

    origin = f'http://127.0.0.1:{port}'
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    context = await browser.new_context(viewport=dict(width=1440, height=1000),
        reduced_motion='reduce', service_workers='block')
    scenario = dict(mode='available', signed_in=False)
    requests, violations, errors = [], [], []

    async def local_only(route):
        target = urlsplit(route.request.url)
        method = route.request.method
        requests.append((target.path, method))
        if target.scheme != 'http' or target.netloc != f'127.0.0.1:{port}':
            violations.append('nonlocal request')
            await route.abort()
        elif method not in ('GET', 'HEAD') and scenario['signed_in']:
            # Do not let a regression reach a real host/model/configuration POST.
            violations.append('unexpected action request')
            await route.abort()
        elif target.path == '/api/support-config':
            if method != 'GET':
                violations.append('configuration action request')
                await route.abort()
            elif scenario['mode'] == 'http_failure':
                await route.fulfill(status=503, content_type='application/json', body='{}')
            else:
                await route.fulfill(status=200, content_type='application/json',
                    body=json.dumps(configuration_fixture(scenario['mode'], observed)))
        else:
            await route.continue_()

    await context.route('**/*', local_only)
    page = await context.new_page()
    page.set_default_timeout(10000)
    page.on('pageerror', lambda _: errors.append('uncaught page error'))
    try:
        await page.goto(origin+'/')
        await page.locator('#password').fill(password)
        await page.locator('#submit').click()
        await expect(page.locator('#workspace-tab-setup')).to_be_visible()
        scenario['signed_in'] = True
        requests.clear()  # The explicit sign-in is not a host-action request.
        await page.locator('#workspace-tab-setup').click()
        panel = page.locator('#host-findings')
        audit = panel.locator('details[data-source="audit"]')
        integrity = panel.locator('details[data-source="integrity"]')
        await expect(audit.locator('summary')).to_contain_text('1 configuration warnings')
        await audit.locator('summary').focus()
        await page.keyboard.press('Enter')
        await expect(audit.locator('a')).to_be_visible()
        await expect(audit).to_contain_text('SSH-7408')
        await expect(audit).to_contain_text('lynis-report.dat line 5')
        await expect(audit.locator('code')).to_contain_text('Report SHA-256:')
        await integrity.locator('summary').click()
        await expect(integrity).to_contain_text('AIDE exit status 5')
        await expect(integrity).to_contain_text('not file counts')
        passed('native host findings render rule evidence and AIDE flags from a synthetic configuration GET')

        async def refresh(mode):
            await expect(page.locator('#support-config')).to_have_attribute('aria-busy', 'false')
            scenario['mode'] = mode
            # The existing public read helper issues only GET. It avoids waiting
            # for a timer or changing document visibility/configuration state.
            await page.evaluate('window.megalodonSupportConfiguration.refresh(true)')
            await expect(page.locator('#support-config')).to_have_attribute('aria-busy', 'false')

        await refresh('available')
        await expect(audit).to_have_attribute('open', '')
        await audit.locator('a').click()
        await expect(page).to_have_url(origin+'/#host-security-audit')
        passed('native findings keyboard disclosure survives refresh and follow-up only navigates')

        for width in (1440, 390):
            await page.set_viewport_size(dict(width=width, height=1000))
            await panel.scroll_into_view_if_needed()
            fits = await panel.evaluate('(n)=>n.scrollWidth<=n.clientWidth+1')
            passed('native host findings reflow '+str(width), fits)

        for mode, expected in (('stale', 'older than 7 days'), ('legacy', 'legacy aggregate only'),
                               ('baseline', 'initial baseline recorded'), ('missing', 'no saved observation'),
                               ('unavailable', 'evidence unavailable'), ('malformed', 'Malformed or contradictory')):
            await refresh(mode)
            await expect(panel).to_contain_text(expected)
        passed('native host findings distinguish stale legacy baseline missing invalid and unavailable observations')

        await refresh('available')
        await expect(panel).to_contain_text('SSH-7408')
        await refresh('http_failure')
        await expect(panel).to_contain_text('Host findings unavailable')
        await expect(panel).not_to_contain_text('SSH-7408')
        await expect(page.locator('#host-security-results')).to_be_empty()
        await expect(page.locator('#host-security-audit')).to_be_disabled()
        passed('native failed configuration GET clears prior findings and disables action controls')
        await refresh('available')
        await expect(panel).to_contain_text('SSH-7408')
        await expect(panel).not_to_contain_text('private-detail')
        await expect(panel).not_to_contain_text('never run me')
        passed('native host findings recover with bounded evidence and exclude tool solution text')
        passed('native host findings journey makes no action request',
               not any(method not in ('GET', 'HEAD') for _, method in requests))
        passed('native host findings journey has no page errors or nonlocal requests', not errors and not violations)
    finally:
        await context.close()
