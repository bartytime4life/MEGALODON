"""Synthetic Setup journey; every configuration write is intercepted, never applied."""
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit

from browser_host_findings import configuration_fixture
from megalodon.config import AISettings
from megalodon.model_lifecycle import ModelLifecycle
from megalodon.model_telemetry import ModelTelemetry
from megalodon.model_test import ModelTest


async def exercise_startup_ux(browser, port, password, passed):
    from playwright.async_api import expect
    origin=f'http://127.0.0.1:{port}'
    now=datetime.now(timezone.utc)
    settings=AISettings(enabled=True,model='nemotron:120b',model_digest='b'*64,compute_mode='auto')
    value=configuration_fixture('available',now)
    value['model']=ModelTelemetry(lambda:settings).snapshot()
    value['model'].update(selection_state='restored',keep_ready=True,
        lifecycle=ModelLifecycle(lambda:settings).snapshot(),response_test=ModelTest(lambda:settings).snapshot())
    value.update(configured_collectors=['clamav','osquery'],startup=dict(checked_at=None,login='unchecked',services=[],message='Check startup.'))
    context=await browser.new_context(viewport=dict(width=1440,height=1000),service_workers='block')
    errors,actions,violations=[],[],[]
    signed_in=False
    async def route_handler(route):
        nonlocal signed_in
        req=route.request;url=urlsplit(req.url)
        if url.scheme!='http' or url.hostname!='127.0.0.1' or url.port!=port:
            violations.append('nonlocal');await route.abort();return
        if url.path=='/api/support-config':
            if req.method=='POST':
                body=req.post_data_json
                if body not in [dict(action='startup_check'),dict(action='startup_enable')]:
                    violations.append('unexpected action');await route.abort();return
                actions.append(body)
                if body['action']=='startup_check':
                    value['startup'].update(checked_at=now.isoformat().replace('+00:00','Z'),login='disabled',
                        services=[dict(id='qwen',name='Ollama',unit='snap.ollama.listener',active='running',enabled='enabled',message='Synthetic observation.')])
                else:value['startup']['login']='enabled'
            await route.fulfill(status=200,content_type='application/json',body=json.dumps(value));return
        if req.method not in ('GET','HEAD'):
            if req.method=='POST' and url.path=='/sign-in' and not signed_in:signed_in=True
            else:violations.append('unexpected write');await route.abort();return
        await route.continue_()
    await context.route('**/*',route_handler)
    page=await context.new_page();page.set_default_timeout(10000)
    page.on('pageerror',lambda e:errors.append(str(e)))
    artifacts=Path('artifacts/startup-ux');artifacts.mkdir(parents=True,exist_ok=True)
    try:
        await page.goto(origin+'/')
        await page.locator('#password').fill(password);await page.locator('#submit').click()
        await expect(page.locator('#workspace-tab-setup')).to_be_visible()
        await page.goto(origin+'/#support-model-title')
        await expect(page.locator('#support-model-select')).to_have_value('nemotron:120b')
        await expect(page.locator('#support-model-persistence')).to_contain_text('Restored from this computer')
        await expect(page.locator('#support-model-save')).to_be_disabled()
        assert actions==[]
        await page.locator('#settings-tab-overview').click()
        await page.locator('#startup-check').focus();await page.keyboard.press('Enter')
        await expect(page.locator('#startup-login-state')).to_contain_text('Off')
        await expect(page.locator('#startup-service-list')).to_contain_text('Enabled at boot · running')
        await page.locator('#startup-enable').click()
        await expect(page.locator('#startup-login-state')).to_contain_text('On')
        await expect(page.locator('#startup-enable')).to_be_disabled()
        assert actions==[dict(action='startup_check'),dict(action='startup_enable')]
        for width in (1440,390):
            await page.set_viewport_size(dict(width=width,height=1000))
            for tab,target,label in [('overview','startup-settings','startup'),('ai','support-model-title','model')]:
                await page.locator('#settings-tab-'+tab).click()
                await page.locator('#'+target).scroll_into_view_if_needed()
                assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth')
                await page.screenshot(path=str(artifacts/f'{label}-{width}.png'))
        await page.reload()
        await expect(page.locator('#support-model-select')).to_have_value('nemotron:120b')
        assert len(actions)==2 and not errors and not violations
        passed('startup/model UX: saved offline choice, explicit protected actions, keyboard, reload, 390/1440px reflow; synthetic only')
    finally:
        await context.close()
