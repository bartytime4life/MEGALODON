"""Real browser journey over inert workflow responses; no tool starts."""
import json
import secrets
import time
from urllib.parse import urlsplit


async def exercise_workflow_overview(browser, port, password, passed):
    from playwright.async_api import expect
    from test_dashboard_workflows_ui import workflow_fixture

    context = await browser.new_context(
        viewport={"width": 320, "height": 812}, reduced_motion="reduce",
        service_workers="block")
    unavailable = False
    flagged_scan = False
    collecting_scan = False
    suricata_activity = None
    requests, errors, violations = [], [], []
    scanner = {'state':'idle', 'message':'No check has run.', 'finished_at':None, 'run_id':None}
    scanner_runs = []
    scanner_token = secrets.token_urlsafe(24)

    async def fixture(route):
        target = urlsplit(route.request.url)
        requests.append((target.path, route.request.method))
        if target.scheme != "http" or target.netloc != f"127.0.0.1:{port}":
            violations.append("nonlocal workflow request")
            await route.abort()
        elif target.path == "/api/support-config" and route.request.method == "POST":
            assert route.request.post_data_json == {"action":"clamav_self_check"}
            assert route.request.headers["x-megalodon-config-token"] == scanner_token
            identifier = f"{len(scanner_runs)+1:016x}"
            scanner_runs.append(identifier)
            scanner.clear()
            scanner.update(state="running", message="Checking both files…", finished_at=None, run_id=identifier)
            await route.fulfill(status=202,json={"scanner_check_id":identifier})
        elif target.path == "/api/support-config" and route.request.headers.get("x-megalodon-check")=="1" and scanner.get("testing"):
            await route.fulfill(json={"token":scanner_token})
        elif target.path == "/api/support-workflows":
            if unavailable:
                await route.fulfill(status=503, content_type="application/json", body="{}")
                return
            value = workflow_fixture()
            value["scanner_check"] = dict(scanner)
            value["observed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            for row in value["tools"]:
                row["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 90))
                if row["id"] in {"clamav", "osquery", "nmap"}:
                    row["state"] = "connected"
                if row["id"] == "clamav" and flagged_scan:
                    row.update(state="collecting" if collecting_scan else "needs_review", review_required=True,
                               message="Synthetic saved scan flagged files; review original evidence.",
                               metrics=[dict(label="Flagged files", value=2, unit="")])
                if row['id'] == 'suricata' and suricata_activity is not None:
                    row.update(state=suricata_activity, review_required=True,
                               message='Synthetic managed intake warning; source activity remains separate.')
            await route.fulfill(status=200, content_type="application/json", body=json.dumps(value))
        else:
            await route.continue_()

    await context.route("**/*", fixture)
    page = await context.new_page()
    page.set_default_timeout(10000)
    page.on("pageerror", lambda _: errors.append("page error"))
    try:
        await page.goto(f"http://127.0.0.1:{port}/")
        await page.locator("#password").fill(password)
        await page.locator("#submit").click()
        requests.clear()
        await page.locator("#workspace-tab-interfaces").click()
        await expect(page.locator("#workflows-count-ALL")).to_have_text("10")
        await expect(page.locator("#workflows-count-attention")).to_have_text("2")
        await expect(page.locator("#workflows-count-saved_result")).to_have_text("3")
        passed("native Sensors overview loads on a cold 320px view before scrolling to cards")
        await page.locator("#workflows-show-attention").click()
        await expect(page.locator("#integrations-cards .workflow-card")).to_have_count(2)
        await page.locator("#workflows-show-saved_result").focus()
        await page.keyboard.press("Enter")
        await expect(page.locator("#integrations-cards .workflow-card")).to_have_count(3)
        await expect(page.locator("#workflows-show-saved_result")).to_be_focused()
        await expect(page.locator("#workflows-show-saved_result")).to_have_attribute("aria-pressed", "true")
        await expect(page.locator("#integrations-cards")).to_contain_text("1m ago")
        passed("native Sensors overview filters with keyboard and retains focus")
        for width in (1440, 390, 320):
            await page.set_viewport_size({"width": width, "height": 1000})
            fits = await page.locator(".workflow-overview").evaluate("n => n.scrollWidth <= n.clientWidth + 1")
            passed("native Sensors overview reflow " + str(width), fits)
        await page.set_viewport_size({"width": 1440, "height": 1000})
        result = page.locator("#integrations-cards .workflow-card").filter(has_text="Nmap")
        await result.locator(":scope > summary").click()
        await result.locator('a[href="#inventory-title"]').click()
        await expect(page.locator("#workspace-live")).to_be_visible()
        await expect(page.locator("#inventory-title")).to_be_visible()
        passed("native Sensors result link reveals the existing saved inventory view")
        flagged_scan = True
        await page.locator("#workspace-tab-interfaces").click()
        await page.locator("#workflows-refresh").click()
        await expect(page.locator("#workflows-count-attention")).to_have_text("3")
        await page.locator("#workflows-show-attention").click()
        scan = page.locator("#integrations-cards .workflow-card").filter(has_text="ClamAV")
        await expect(scan).to_contain_text("Review required")
        await expect(scan).to_contain_text("Flagged files 2")
        await scan.locator(":scope > summary").click()
        await scan.locator('a[href="#clamav-title"]').click()
        await expect(page.locator("#clamav-title")).to_be_visible()
        passed("native positive file-scan review reaches the saved scan evidence without starting work")
        collecting_scan = True
        await page.locator("#workspace-tab-interfaces").click()
        await page.locator("#workflows-refresh").click()
        await expect(page.locator("#workflows-count-attention")).to_have_text("3")
        await expect(page.locator("#workflows-count-collecting")).to_have_text("2")
        await expect(scan).to_contain_text("Collecting · review required")
        await page.locator("#workflows-show-collecting").click()
        await expect(scan).to_contain_text("Flagged files 2")
        passed("native collecting scan retains its prior positive in both activity and review filters")
        await page.locator('#integrations-clear').click()
        await page.locator('#integrations-query').fill('Suricata')
        sensor = page.locator('#integrations-cards .workflow-card').filter(has_text='Suricata')
        await sensor.locator(':scope > summary').click()
        await sensor.get_by_role('link', name='Review saved findings').click()
        await expect(page.locator('#workspace-tab-findings')).to_have_attribute('aria-selected', 'true')
        passed('native managed sensor review opens Findings rather than the optional external store')
        for activity, label in [('collecting', 'Collecting'), ('connected', 'Data connected'),
                                ('stopped', 'Configured · stopped')]:
            suricata_activity = activity
            await page.locator('#workspace-tab-interfaces').click()
            await page.locator('#integrations-clear').click()
            await page.locator('#workflows-refresh').click()
            await expect(sensor).to_contain_text(label+' · review required')
            await page.locator('#workflows-show-attention').click()
            await expect(sensor).to_be_visible()
            if activity == 'collecting':
                await page.locator('#workflows-show-collecting').click()
                await expect(sensor).to_be_visible()
        passed('native managed intake warnings preserve sensor activity and both review/activity filters')
        unavailable = True
        await page.locator("#workspace-tab-interfaces").click()
        await page.locator('#integrations-clear').click()
        await page.locator("#workflows-refresh").click()
        for key in ("ALL", "attention", "collecting", "saved_result"):
            await expect(page.locator("#workflows-count-" + key)).to_have_text("—")
        await expect(page.locator("#workflows-show-saved_result")).to_be_disabled()
        await expect(page.locator("#integrations-cards .workflow-metrics")).to_have_count(0)
        await expect(page.locator("#workflows-overview-note")).to_contain_text("unavailable")
        passed("native Sensors failed refresh removes current counts and metrics")
        passed("native Sensors navigation starts no tools, scans, model or response", not any(
            method == "POST" for _, method in requests))
        unavailable=False
        for state,message,matches in [
                ("recognized","ClamAV recognized the test file and left the ordinary file alone.",1),
                ("missed","ClamAV scanned both files and missed the EICAR test file.",0),
                ("unavailable","Save the official 68-byte EICAR file in Downloads.",None)]:
            scanner["testing"]=True
            await page.locator("#workflows-refresh").click()
            button=page.get_by_role("button",name="Check my file scanner")
            await expect(button).to_be_enabled()
            await button.click()
            await expect(page.locator("#scanner-check-status")).to_have_text("Checking both files…")
            await expect(button).to_be_disabled()
            assert len(scanner_runs)=={"recognized":1,"missed":2,"unavailable":3}[state]
            scanner.update(state=state,message=message,finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
                           clean={"scanned":1,"matched":0} if matches is not None else None,
                           test={"scanned":1,"matched":matches} if matches is not None else None,
                           engine="1.5.4" if matches is not None else None,database="28168" if matches is not None else None)
            await page.locator("#workflows-refresh").click()
            await expect(page.locator("#scanner-check-status")).to_have_text(message)
            if matches is None:
                await expect(page.locator("#scanner-check-counts")).to_be_empty()
            else:
                await expect(page.locator("#scanner-check-counts")).to_contain_text(f"Test file: {matches} of 1 flagged")
                await expect(page.locator("#scanner-check-version")).to_contain_text("ClamAV 1.5.4")
        passed("native Sensors scanner check requires a click and shows recognized, missed and unavailable separately")
        passed("native Sensors overview has no page error or nonlocal request", not errors and not violations)
    finally:
        await context.close()
