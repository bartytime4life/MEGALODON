"""Real browser journey over inert workflow responses; no tool starts."""
import json
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
    requests, errors, violations = [], [], []

    async def fixture(route):
        target = urlsplit(route.request.url)
        requests.append((target.path, route.request.method))
        if target.scheme != "http" or target.netloc != f"127.0.0.1:{port}":
            violations.append("nonlocal workflow request")
            await route.abort()
        elif target.path == "/api/support-workflows":
            if unavailable:
                await route.fulfill(status=503, content_type="application/json", body="{}")
                return
            value = workflow_fixture()
            value["observed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            for row in value["tools"]:
                row["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 90))
                if row["id"] in {"clamav", "osquery", "nmap"}:
                    row["state"] = "connected"
                if row["id"] == "clamav" and flagged_scan:
                    row.update(state="collecting" if collecting_scan else "needs_review", review_required=True,
                               message="Synthetic saved scan flagged files; review original evidence.",
                               metrics=[dict(label="Flagged files", value=2, unit="")])
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
        unavailable = True
        await page.locator("#workspace-tab-interfaces").click()
        await page.locator("#workflows-refresh").click()
        for key in ("ALL", "attention", "collecting", "saved_result"):
            await expect(page.locator("#workflows-count-" + key)).to_have_text("—")
        await expect(page.locator("#workflows-show-saved_result")).to_be_disabled()
        await expect(page.locator("#integrations-cards .workflow-metrics")).to_have_count(0)
        await expect(page.locator("#workflows-overview-note")).to_contain_text("unavailable")
        passed("native Sensors failed refresh removes current counts and metrics")
        passed("native Sensors navigation starts no tools, scans, model or response", not any(
            method == "POST" for _, method in requests))
        passed("native Sensors overview has no page error or nonlocal request", not errors and not violations)
    finally:
        await context.close()
