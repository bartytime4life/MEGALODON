"""Rendered library journey using synthetic receipts and intercepted actions.

Only the disposable HUD sign-in reaches a real POST handler. Every library
action is fulfilled here; no model, private catalog or transfer backend runs.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from urllib.parse import urlsplit

from browser_host_findings import configuration_fixture
from megalodon.config import AISettings
from megalodon.model_lifecycle import ModelLifecycle
from megalodon.model_library import ModelLibrary
from megalodon.model_telemetry import ModelTelemetry
from megalodon.model_test import ModelTest


async def exercise_model_library(browser, port, password, passed):
    from playwright.async_api import expect

    origin = f"http://127.0.0.1:{port}"
    now = datetime.now(timezone.utc)
    settings = AISettings(enabled=True)
    value = configuration_fixture("available", now)
    value["model"] = ModelTelemetry(lambda: settings).snapshot()
    value["model"].update(selection_state="restored", keep_ready=False,
        lifecycle=ModelLifecycle(lambda: settings).snapshot(), response_test=ModelTest(lambda: settings).snapshot())
    value["model_library"] = ModelLibrary(Path("/unused-synthetic-home")).snapshot()
    actions, errors, violations = [], [], []
    scenario = dict(outcome="success", signed_in=False, deny_download=False)
    check_request = dict(action="model_library_reuse", store_id="user", model=settings.model,
                         model_digest=settings.model_digest, verification_profile="standard")

    def observation(state, error=None):
        return dict(store_id="user", model=settings.model, manifest_sha256=settings.model_digest,
                    provider_sha256="c" * 64 if state == "files_verified" else None,
                    verified_bytes=123 if state == "files_verified" else 0, profile="standard",
                    state=state, error_code=error, checked_at=int(now.timestamp()))

    async def local_only(route):
        req = route.request
        target = urlsplit(req.url)
        if target.scheme != "http" or target.netloc != f"127.0.0.1:{port}":
            violations.append("nonlocal request")
            await route.abort()
            return
        if target.path == "/api/support-config":
            if req.method == "POST":
                body = req.post_data_json
                actions.append(body)
                if req.headers.get("x-megalodon-config-token") != value["token"]:
                    violations.append("missing operator token")
                    await route.abort()
                    return
                if body == check_request:
                    ok = scenario["outcome"] == "success"
                    value["model_library"].update(state="checked" if ok else "failed", active=None,
                        local_models=[observation("files_verified" if ok else "failed", None if ok else "FILES_UNAVAILABLE")],
                        message="Synthetic existing-file check passed; acceptance held." if ok else "Synthetic files missing; no download attempted.")
                elif body == dict(action="model_library_check"):
                    value["model_library"]["state"] = "checked"
                elif (scenario["deny_download"] and body == dict(action="model_stage_download",
                        catalog_id=value["model_library"]["catalog"][0]["id"])):
                    # Deny the explicit fixture request; a refresh must never
                    # repeat it. No transfer backend exists in this route.
                    scenario["deny_download"] = False
                    value["token"] = "d" * 32
                    await route.fulfill(status=403, content_type="application/json", body="{}")
                    return
                else:
                    violations.append("unexpected library action")
                    await route.abort()
                    return
            elif req.method != "GET":
                violations.append("unexpected configuration method")
                await route.abort()
                return
            await route.fulfill(status=200, content_type="application/json", body=json.dumps(value))
            return
        if req.method not in ("GET", "HEAD"):
            if req.method == "POST" and target.path == "/sign-in" and not scenario["signed_in"]:
                scenario["signed_in"] = True
            else:
                violations.append("unexpected host action")
                await route.abort()
                return
        await route.continue_()

    context = await browser.new_context(viewport=dict(width=1440, height=1000),
                                        reduced_motion="reduce", service_workers="block")
    await context.route("**/*", local_only)
    page = await context.new_page()
    page.set_default_timeout(10000)
    page.on("pageerror", lambda _: errors.append("uncaught page error"))
    artifacts = Path("artifacts/model-library-ux")
    artifacts.mkdir(parents=True, exist_ok=True)
    try:
        await page.goto(origin + "/")
        await page.locator("#password").fill(password)
        await page.locator("#submit").click()
        await expect(page.locator("#workspace-tab-setup")).to_be_visible()
        await page.goto(origin + "/#support-model-title")
        reuse = page.locator("#model-library-reuse")
        await expect(reuse).to_be_enabled()
        assert actions == []
        await expect(page.locator("#model-library-download")).to_be_disabled()
        await reuse.focus()
        await page.keyboard.press("Enter")
        await expect(page.locator("#model-library-local")).to_contain_text("Files verified at last check")
        assert actions == [check_request]
        await expect(page.locator("#model-library-acceptance")).to_contain_text("held (UNBOUND)")
        await expect(page.locator("#support-model-load")).to_be_disabled()
        for width in (1440, 390):
            await page.set_viewport_size(dict(width=width, height=1000))
            await reuse.scroll_into_view_if_needed()
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            await page.screenshot(path=str(artifacts / f"existing-files-{width}.png"))
        await page.reload()
        await expect(reuse).to_be_enabled()
        await expect(page.locator("#model-library-local")).to_contain_text("Files verified at last check")
        assert actions == [check_request], "reload must not repeat a check"

        scenario["outcome"] = "missing"
        await reuse.click()
        await expect(page.locator("#model-library-local")).to_contain_text("Not verified")
        await expect(page.locator("#model-library-local")).not_to_contain_text("Files verified")
        assert actions == [check_request, check_request]

        value["model_library"]["local_models"] = [observation("interrupted", "INTERRUPTED")]
        await page.reload()
        await expect(page.locator("#model-library-local")).to_contain_text("Interrupted")
        await page.wait_for_timeout(10500)  # Cover the normal 10-second status poll.
        assert actions == [check_request, check_request], "restart/polling must not resume work"
        value["model"]["selected_digest"] = "e" * 64
        await page.locator("#model-library-check").click()
        await expect(page.locator("#model-library-local")).to_contain_text("Previous selection")

        consent = page.locator("#model-library-online")
        await consent.check()
        value["model_library"]["catalog"][0]["sha256"] = "f" * 64
        await page.locator("#model-library-check").click()
        await expect(consent).not_to_be_checked()
        await expect(page.locator("#model-library-download")).to_be_disabled()

        await consent.check()
        scenario["deny_download"] = True
        before = len(actions)
        await page.locator("#model-library-download").click()
        await expect(page.locator("#support-config-status")).to_contain_text("confirm the download again")
        await expect(consent).not_to_be_checked()
        await expect(page.locator("#model-library-download")).to_be_disabled()
        assert len(actions) == before + 1, "permission refresh must not replay a download"
        await expect(page.locator("#support-model-load")).to_be_disabled()
        assert not errors and not violations, (errors, violations)
        passed("model library UX: explicit offline reuse, failure invalidation, interrupted reload/poll, identity drift, pin/permission consent, 390/1440px; synthetic only")
    finally:
        await context.close()
