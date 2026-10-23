"""Native browser inspector journey; synthetic GETs and all host actions refused."""
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from finding_evidence_fixture import finding_evidence_fixture
from megalodon.dashboard_assets import INDEX_HTML
from megalodon.dashboard_traffic import unavailable


async def exercise_finding_evidence(browser, port, password, passed):
    from playwright.async_api import expect

    origin = f"http://127.0.0.1:{port}"
    base = finding_evidence_fixture()
    context = await browser.new_context(viewport=dict(width=1440, height=1000),
        reduced_motion="reduce", service_workers="block")
    scenario = dict(mode="loading", signed_in=False)
    release, requested = asyncio.Event(), asyncio.Event()
    requests, violations, errors, captures = [], [], [], []

    async def local_only(route):
        target, method = urlsplit(route.request.url), route.request.method
        requests.append((target.path, method))
        if target.scheme != "http" or target.netloc != f"127.0.0.1:{port}":
            violations.append("nonlocal inspector request")
            await route.abort()
        elif method not in ("GET", "HEAD") and not (
                method == "POST" and target.path == "/sign-in" and not scenario["signed_in"]):
            violations.append("unexpected inspector action request")
            await route.abort()
        elif target.path == "/api/traffic":
            requested.set()
            if scenario["mode"] == "loading":
                await release.wait()
            mode = scenario["mode"]
            if mode == "failed":
                await route.fulfill(status=503, content_type="application/json", body="{}")
                return
            if mode == "oversized":
                await route.fulfill(status=200, content_type="application/json",
                    body=json.dumps(dict(padding="x" * 262145)))
                return
            value = deepcopy(base)
            value["generated_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            if mode == "stale":
                value["generated_at"] = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat().replace("+00:00", "Z")
            elif mode == "partial":
                value.update(truncated=True, quality="degraded", excluded_event_candidates=1)
            elif mode == "malicious":
                value["findings"][0]["rule_id"] = '<img src=x onerror="alert(1)">'
            elif mode == "vanished":
                value["findings"] = value["findings"][1:]
            elif mode == "changed_source":
                value["events"][0]["source"] = "scapy"
            elif mode == "empty":
                value = unavailable()
            await route.fulfill(status=200, content_type="application/json", body=json.dumps(value))
        elif target.path == "/api/traffic-history-v2":
            query = parse_qs(target.query)
            value = dict(schema="megalodon-traffic-history-v2", records=[], gaps=["Synthetic retained range."],
                source_segments=[], candidate_count=0, range=dict(start=query["start"][0], end=query["end"][0]),
                next_cursor=None, truncated=False)
            await route.fulfill(status=200, content_type="application/json", body=json.dumps(value))
        else:
            if method == "POST":
                scenario["signed_in"] = True
            await route.continue_()

    await context.route("**/*", local_only)
    page = await context.new_page()
    page.set_default_timeout(10000)
    page.on("pageerror", lambda _: errors.append("uncaught inspector page error"))
    output = Path(__file__).resolve().parents[1] / "artifacts" / "finding-inspector"

    async def capture(name, target_id, width, alignment="start"):
        output.mkdir(parents=True, exist_ok=True)
        path = output / name
        # Capture the actual viewport, including its surrounding navigation.
        # An element taller than a nested scrollport cannot be captured as one
        # faithful image: use native scrolling and separate viewport views.
        position = await page.evaluate("""({targetId,alignment}) => {
            const target=document.getElementById(targetId);
            const pageScroll=matchMedia('(max-width: 560px), (max-height: 500px)').matches;
            const scroll=pageScroll?document.scrollingElement:document.getElementById('workspace-content');
            const viewport=pageScroll?{top:0,bottom:innerHeight}:scroll.getBoundingClientRect();
            const bounds=target.getBoundingClientRect();
            const delta=alignment==='end'?bounds.bottom-viewport.bottom+12:bounds.top-viewport.top-12;
            scroll.scrollTop=Math.max(0,scroll.scrollTop+delta);
            return {surface:pageScroll?'document':'workspace-content',top:scroll.scrollTop,
                left:scroll.scrollLeft,target:targetId,alignment};
        }""", dict(targetId=target_id, alignment=alignment))
        await page.screenshot(path=str(path), animations="disabled", full_page=False)
        png = path.read_bytes()
        dimensions = dict(width=int.from_bytes(png[16:20], "big"), height=int.from_bytes(png[20:24], "big"))
        if dimensions != dict(width=width, height=1000):
            raise AssertionError("inspector viewport capture dimensions differ")
        captures.append(dict(file=name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            viewport=dict(width=width, height=1000), image=dimensions, scroll=position,
            state="unselected candidate" if "unselected" in name else "selected candidate, metadata disclosure open",
            scope="Synthetic qualified finding view; not installed HUD or live PC telemetry"))

    try:
        await page.goto(origin + "/")
        await page.locator("#password").fill(password)
        await page.locator("#submit").click()
        await asyncio.wait_for(requested.wait(), timeout=10)
        await page.locator("#workspace-tab-findings").click()
        panel = page.locator("#room-evidence-inspector")
        content = page.locator("#room-evidence-content")
        status = page.locator("#room-evidence-status")
        buttons = page.locator("#room-findings-table button[data-evidence-key]")
        await expect(content).to_be_hidden()
        await expect(buttons).to_have_count(0)
        passed("native finding inspector has no invented selection while metadata is loading")
        scenario["mode"] = "available"
        release.set()
        await expect(buttons).to_have_count(2)
        await page.evaluate("if (!state.paused) togglePause()")
        requests.clear()  # The explicit login is outside passive review acceptance.
        await capture("candidate-unselected-1440.png", "room-findings-title", 1440)

        await expect(page.locator("#room-case-summary")).to_contain_text("3 linked metadata events and 2 findings")
        await expect(page.locator("#room-case-coverage")).to_contain_text("Completeness beyond")
        await page.locator("#room-case-timeline button").first.click()
        await expect(page.locator("#room-evidence-finding")).to_have_text("1")
        passed("native automatic address case links retained records to the existing inspector")

        first = buttons.first
        await first.focus()
        await page.keyboard.press("Enter")
        await expect(content).to_be_visible()
        await expect(page.locator("#room-evidence-title")).to_be_focused()
        await expect(first).to_have_attribute("aria-expanded", "true")
        await expect(status).to_have_attribute("role", "status")
        await expect(page.locator("#room-evidence-finding")).to_have_text("1")
        await expect(page.locator("#room-evidence-event")).to_have_text("1")
        await expect(page.locator("#room-evidence-run")).to_have_text("1")
        await expect(page.locator("#room-evidence-observed")).to_have_text(base["events"][0]["observed_at"])
        await expect(page.locator("#room-evidence-detected")).to_have_text(base["findings"][0]["detected_at"])
        await expect(page.locator("#room-evidence-generated")).not_to_have_text(base["events"][0]["observed_at"])
        await expect(page.locator("#room-evidence-age")).to_contain_text("does not make this observation new")
        heading_visible = await page.locator("#room-evidence-title").evaluate("""n => {
            const r=n.getBoundingClientRect(), scroll=document.getElementById('workspace-content').getBoundingClientRect();
            return r.top>=Math.max(0,scroll.top)-1 && r.bottom<=Math.min(innerHeight,scroll.bottom)+1;
        }""")
        passed("native keyboard selection traces finding event run with separate clocks and visible focus target", heading_visible)

        summary = page.locator("#room-evidence-details > summary")
        await summary.focus()
        await page.keyboard.press("Enter")
        await expect(page.locator("#room-evidence-details")).to_have_attribute("open", "")
        await expect(page.locator("#room-evidence-bytes")).to_have_text("9223372036854775807 reported bytes")
        await expect(page.locator("#room-evidence-version")).to_have_text("unknown; not stored on historical finding")
        await expect(panel).to_contain_text("Detector evaluation window")
        await expect(panel).to_contain_text("Unknown; not supplied by this projection.")
        focus_style = await summary.evaluate("n => ({visible:n.matches(':focus-visible'),width:getComputedStyle(n).outlineWidth,style:getComputedStyle(n).outlineStyle})")
        passed("native inspector keyboard focus has a visible outline", focus_style["visible"] and
            focus_style["style"] != "none" and float(focus_style["width"].removesuffix("px")) >= 2)

        async def refresh(mode):
            scenario["mode"] = mode
            # Existing read helper issues a bounded GET; avoid timer-dependent assertions.
            await page.evaluate("refreshRoom()")

        await page.evaluate("""() => {
            const observed=document.getElementById('room-evidence-observed'), range=document.createRange();
            range.selectNodeContents(observed);const selection=getSelection();selection.removeAllRanges();selection.addRange(range);
            const scroll=document.getElementById('workspace-content');
            window.__findingProbe={button:document.querySelector('[data-evidence-key]'),
                detail:document.getElementById('room-evidence-details'), anchor:selection.anchorNode,
                text:selection.toString(),scrollTop:scroll.scrollTop,scrollLeft:scroll.scrollLeft};
        }""")
        await refresh("available")
        stable = await page.evaluate("""() => {
            const p=window.__findingProbe, scroll=document.getElementById('workspace-content');
            return p.button===document.querySelector('[data-evidence-key]') && p.detail===document.getElementById('room-evidence-details')
                && p.detail.open && document.activeElement===p.detail.querySelector('summary')
                && p.anchor===getSelection().anchorNode && p.text===getSelection().toString()
                && Math.abs(p.scrollTop-scroll.scrollTop)<=1 && Math.abs(p.scrollLeft-scroll.scrollLeft)<=1;
        }""")
        passed("native identical metadata refresh preserves selection disclosure keyboard focus text selection and scroll", stable)
        await page.evaluate("getSelection().removeAllRanges()")

        for width in (1440, 390, 320):
            await page.set_viewport_size(dict(width=width, height=1000))
            await panel.scroll_into_view_if_needed()
            fits = await panel.evaluate("n => n.scrollWidth<=n.clientWidth+1 && document.documentElement.scrollWidth<=innerWidth+1")
            passed("native finding inspector reflow " + str(width), fits)
            await capture("candidate-selected-" + str(width) + "-top.png", "room-evidence-inspector", width)
            await capture("candidate-selected-" + str(width) + "-metadata.png", "room-evidence-details", width)
            await capture("candidate-selected-" + str(width) + "-end.png", "room-evidence-inspector", width, "end")
        passed("native finding inspector respects the reduced motion preference",
            await page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches"))
        await page.set_viewport_size(dict(width=1440, height=1000))
        for mode in ("stale", "failed", "oversized", "malicious"):
            await refresh(mode)
            await expect(status).to_contain_text("Stale evidence")
            await expect(content).to_be_visible()
            await expect(page.locator("#room-evidence-bytes")).to_have_text("9223372036854775807 reported bytes")
            await expect(panel.locator("img,script,iframe")).to_have_count(0)
            await refresh("available")
            await expect(status).to_contain_text("Stored evidence")
        passed("native stale failed oversized and malicious refreshes preserve clearly stale evidence and recover")
        await refresh("partial")
        await expect(page.locator("#room-evidence-bounds")).to_contain_text("Candidate window truncated")
        await expect(page.locator("#room-evidence-bounds")).to_contain_text("1 excluded event candidates")
        passed("native finding inspector exposes partial candidate coverage")

        for mode in ("vanished", "changed_source"):
            await refresh("available")
            await first.click()
            await refresh(mode)
            await expect(content).to_be_hidden()
            await expect(status).to_contain_text("absence does not establish resolution")
            await expect(page.locator("#room-evidence-event")).to_have_text("")
        passed("native vanished or changed source identities clear reviewed evidence without declaring resolution")
        await refresh("available")
        await first.click()
        start = int(datetime(2026, 9, 17, 12, tzinfo=timezone.utc).timestamp() * 1000)
        await page.evaluate("""start => refreshRoom({history:{start,end:start+60000,before:null,
            next:null,candidates:0,previous:[]},range:'custom'})""", start)
        await expect(content).to_be_hidden()
        await expect(status).to_contain_text("Retained history")
        await expect(buttons).to_have_count(0)
        await page.evaluate("refreshRoom({history:null,range:'recorded'})")
        await expect(buttons).to_have_count(2)
        await expect(content).to_be_hidden()
        passed("native retained history clears the incompatible inspector and latest requires reselection")

        await first.click()
        for target in ("ingestion-runs-title", "storage-evidence-title", "room-reports-title"):
            await panel.locator('a[href="#' + target + '"]').click()
            await expect(page).to_have_url(origin + "/#" + target)
            await expect(page.locator("#" + target)).to_be_visible()
            await page.locator("#workspace-tab-findings").click()
            await expect(content).to_be_visible()
        passed("native evidence follow-ups reveal existing receipts retained evidence and reports")
        await page.locator("#room-evidence-close").click()
        await expect(first).to_be_focused()
        await expect(content).to_be_hidden()
        await refresh("empty")
        await expect(buttons).to_have_count(0)
        await expect(content).to_be_hidden()
        passed("native empty result and return-to-finding preserve an explicit passive state")
        passed("native evidence browsing never requests scans models captures firewall changes or nonlocal resources",
            not violations and not any(method not in ("GET", "HEAD") for _, method in requests))
        passed("native finding inspector has no uncaught page error", not errors)
        manifest = dict(schema="finding-inspector-browser-captures-v1", status="passed",
            fixture="synthetic-documentation-addresses-v1", browser=browser.version,
            candidate_sha=os.environ.get("GITHUB_SHA", "unknown; local browser invocation"),
            run_id=os.environ.get("GITHUB_RUN_ID"), run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"),
            dashboard_html_sha256=hashlib.sha256(INDEX_HTML.encode()).hexdigest(), captures=captures,
            limits=["Candidate unselected/selected comparison; no base-version screenshot",
                    "No screen-reader acceptance", "Viewport reflow is not native browser zoom acceptance",
                    "Synthetic test server; no installation or hosted Site parity claim",
                    "Request monitoring does not prove OS-level egress containment"])
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    finally:
        release.set()
        await context.close()
