"""Real browser journey with inert region data and shipped local map assets."""
import json
from urllib.parse import urlsplit


async def exercise_address_map(browser, port, password, passed):
    from playwright.async_api import expect
    from megalodon.address_location import project
    from test_dashboard_operations_ui import operations_fixture

    origin=f'http://127.0.0.1:{port}'
    context=await browser.new_context(viewport={'width':1440,'height':1000},reduced_motion='reduce')
    seen=[];errors=[];foreign=[]
    def stamp():
        from datetime import datetime,timezone
        return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    async def fixture(route):
        target=urlsplit(route.request.url)
        if target.path=='/api/operations':
            value=operations_fixture();value['observed_at']=stamp();value['capture']['state']='failed'
            value['endpoints'][1]['ip']='8.8.8.8'
        elif target.path=='/api/address-map':
            seen.append(target.query)
            ip=target.query.removeprefix('ip=')
            point=dict(latitude=37.5,longitude=-97.5,label='Synthetic map-test region',source='Synthetic offline fixture',
                       country='US',approximate=True,accuracy_radius_km=50)
            value=project(dict(ip=ip,location=point if ip=='8.8.8.8' else None),snapshot_at=stamp(),capture_state='failed')
        else:
            await route.continue_();return
        await route.fulfill(status=200,content_type='application/json',body=json.dumps(value))
    context.on('request',lambda request:foreign.append(request.url) if not request.url.startswith(origin+'/') else None)
    await context.route('**/*',fixture)
    page=await context.new_page();page.set_default_timeout(15000);page.on('pageerror',lambda error:errors.append(str(error)))
    try:
        await page.goto(origin+'/');await page.locator('#password').fill(password);await page.locator('#submit').click()
        await expect(page.locator('#ops-endpoint-list .ops-endpoint')).to_have_count(2)
        await page.locator('#ops-endpoint-list .ops-endpoint').nth(1).click()
        passed('map selection alone performs no location read or renderer load',not seen and await page.locator('#address-map-frame').get_attribute('src') is None)
        await page.locator('#address-map-read').click()
        await expect(page.locator('#address-map-evidence')).to_contain_text('Reported accuracy radius: 50 km')
        await expect(page.locator('#address-map-evidence')).to_contain_text('not a street address or a person')
        frame=page.frame_locator('#address-map-frame')
        await expect(frame.locator('#map-status')).to_contain_text('Snapshot')
        await expect(frame.locator('#zoom-in')).to_be_enabled()
        await expect(frame.locator('canvas')).to_be_visible()
        await frame.locator('#zoom-out').click();await frame.locator('#zoom-in').click();await frame.locator('#reset').click()
        passed('local MapLibre renders bundled outlines and reported radius with zoom controls')
        for width in (1440,390):
            await page.set_viewport_size({'width':width,'height':1000})
            fits=await page.locator('.ops-address-map').evaluate('(n)=>n.scrollWidth<=n.clientWidth+1')
            passed('local address map reflows '+str(width),fits)
        async with page.expect_download() as download:
            await page.locator('#address-map-save').click()
        path=await (await download.value).path()
        from pathlib import Path
        note=json.loads(Path(path).read_text())
        passed('map export preserves source radius failed capture and unknown physical address',note['location']['accuracy_radius_km']==50 and note['capture_state']=='failed' and note['physical_address'] is None and note['network_access_performed'] is False)
        await page.locator('#ops-endpoint-list .ops-endpoint').nth(0).click()
        await expect(page.locator('#address-map-frame')).to_be_hidden()
        await expect(page.locator('#address-map-save')).to_be_disabled()
        passed('map selection change discards the old position and export',await page.locator('#address-map-frame').get_attribute('src') is None)
        await page.locator('#address-map-read').click();await expect(page.locator('#address-map-evidence')).to_contain_text('Location unknown')
        await expect(page.locator('#address-map-save')).to_be_enabled()
        passed('unmapped address retains an exportable unknown location context')
        passed('map browser journey has no uncaught script errors or nonlocal page requests',not errors and not foreign)
    finally:
        await context.close()
