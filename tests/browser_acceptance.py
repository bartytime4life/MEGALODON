"""Opt-in real-browser acceptance; synthetic data, real CLI/SQLite/HTTP, no sensor.

Run from an installed checkout with preinstalled Chrome, Playwright, and Xvfb:
    xvfb-run -a python tests/browser_acceptance.py
Missing prerequisites or failed assertions exit nonzero; no skip/fallback mode.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
from urllib.parse import urlsplit

REPORT = {"schema": "dashboard-browser-acceptance-v1", "status": "failed",
          "fixture": "synthetic-documentation-addresses-v1", "passed": [],
          "concurrent_writer_acceptance": "not_attempted; vendor patch status unverified",
          "limits": ["Not independent review or release approval", "No screen-reader acceptance",
                     "No installed-analyzer or native Windows acceptance",
                     "Page-request monitoring is not OS-level egress containment",
                     "Zoom reflow uses CSS viewport equivalence; native browser zoom input is not proven"]}


def passed(name: str, condition: bool = True) -> None:
    if not condition:
        raise AssertionError(name)
    REPORT["passed"].append(name)
    print("PASS " + name, flush=True)


def cli(*args: str, stdin: str | None = None) -> dict:
    result = subprocess.run([sys.executable, "-m", "megalodon", *args], input=stdin,
                            text=True, capture_output=True, timeout=20, check=False)
    if result.returncode or len(result.stdout) > 65536:
        raise AssertionError("fixture CLI failed")
    return json.loads(result.stdout)


def request(port: int, path: str, hosts: list[str] | None = None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.putrequest("GET", path, skip_host=True)
        for host in ([f"127.0.0.1:{port}"] if hosts is None else hosts):
            connection.putheader("Host", host)
        connection.endheaders()
        response = connection.getresponse()
        body = response.read(131073)
        if len(body) > 131072:
            raise AssertionError("HTTP response bound exceeded")
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()


def config(root: Path, name: str) -> tuple[Path, Path]:
    db = root / name / "audit.db"  # Writer alone creates this dedicated leaf.
    settings = root / (name + ".toml")
    settings.write_text('[app]\ndb_path = ' + json.dumps(str(db)) +
                        '\n[blocking]\nenabled = false\nauto_block = false\ndry_run = true\n'
                        '[dashboard]\nhost = "127.0.0.1"\nrefresh_seconds = 2\nevent_limit = 5\n',
                        encoding="utf-8")
    return settings, db


@contextmanager
def dashboard(settings: Path, offline: Path | None = None):
    # Reserve an ephemeral candidate port; a competing bind fails closed below.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    args = [sys.executable, "-m", "megalodon", "dashboard", "--config", str(settings),
            "--host", "127.0.0.1", "--port", str(port)]
    if offline is not None:
        args += ["--offline-run", str(offline)]
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("dashboard startup refused")
            try:
                if request(port, "/api/config")[0] == 200:
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        else:
            raise AssertionError("dashboard startup timeout")
        yield port
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise AssertionError("dashboard required forced cleanup")


def unsafe_startup(settings: Path, db: Path) -> None:
    result = subprocess.run([sys.executable, "-m", "megalodon", "dashboard", "--config", str(settings)],
                            capture_output=True, timeout=5, check=False)
    passed("missing database startup refusal", result.returncode == 2 and not db.exists()
           and not db.parent.exists())


def offline_fixture(root: Path) -> Path:
    source = root / "inputs"
    source.mkdir(mode=0o700)
    row = {"ts": "1788710400.123456", "uid": "synthetic001", "id.orig_h": "203.0.113.10",
           "id.orig_p": 40000, "id.resp_h": "203.0.113.20", "id.resp_p": 443,
           "proto": "tcp", "duration": "0.06685185432434082", "orig_bytes": 0,
           "resp_bytes": 0, "conn_state": "SF", "orig_pkts": 3, "resp_pkts": 2,
           "orig_ip_bytes": 180, "resp_ip_bytes": 120, "ip_proto": 6}
    (source / "synthetic.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
    output = root / "offline-report"
    result = subprocess.run([sys.executable, "-m", "megalodon.offline", "--source", "zeek-json",
                             "--input-root", str(source), "--input", "synthetic.jsonl",
                             "--output", str(output), "--case", "browser-fixture",
                             "--zeek-version", "8.0.0", "--max-records", "10"],
                            capture_output=True, timeout=20, check=False)
    passed("synthetic Zeek report CLI", result.returncode == 0 and (output / "manifest.json").is_file())
    return output


async def wait_native_visibility(page, hidden: bool) -> None:
    # Test-side polling avoids the driver's in-page eval poller under the real CSP.
    # Read native visibility only; do not override document.hidden or relax CSP.
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        if await page.evaluate("hidden => document.hidden === hidden", hidden):
            return
        await asyncio.sleep(0.05)
    visibility = "hidden" if hidden else "visible"
    raise AssertionError(f"native visibility deadline exceeded ({visibility})")


async def wait_refresh_idle(page, visibility: str) -> None:
    deadline = asyncio.get_running_loop().time() + 10
    while asyncio.get_running_loop().time() < deadline:
        if await page.evaluate("!state.refreshing"):
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"refresh idle deadline exceeded ({visibility})")


async def set_native_window_state(page, window_state: str) -> dict:
    cdp = await page.context.new_cdp_session(page)
    try:
        window = await cdp.send("Browser.getWindowForTarget")
        await cdp.send("Browser.setWindowBounds", {
            "windowId": window["windowId"],
            "bounds": {"windowState": window_state},
        })
        observed = await cdp.send("Browser.getWindowForTarget")
        return observed["bounds"]
    finally:
        await cdp.detach()


async def exercise(browser, port: int, nonempty: bool) -> None:
    from playwright.async_api import expect
    origin = f"http://127.0.0.1:{port}"
    context = await browser.new_context(viewport={"width": 1440, "height": 1000},
                                        reduced_motion="reduce", service_workers="block")
    violations: list[str] = []
    errors: list[str] = []
    counts = {"summary": 0, "events": 0, "advisory": 0}

    async def allow_local(route):
        parsed = urlsplit(route.request.url)
        if parsed.scheme != "http" or parsed.netloc != f"127.0.0.1:{port}":
            violations.append("nonlocal page request")
            await route.abort()
        else:
            await route.continue_()

    def audit_request(req):
        parsed = urlsplit(req.url)
        if parsed.scheme != "http" or parsed.netloc != f"127.0.0.1:{port}":
            violations.append("nonlocal page request")

    context.on("request", audit_request)
    await context.route("**/*", allow_local)
    page = await context.new_page()
    page.set_default_timeout(10000)
    page.on("pageerror", lambda _: errors.append("page error"))

    def count(req):
        path = urlsplit(req.url).path
        if path == "/api/summary":
            counts["summary"] += 1
        elif path == "/api/events":
            counts["events"] += 1
        elif path == "/api/advisory-receipt":
            counts["advisory"] += 1

    page.on("request", count)
    try:
        response = await page.goto(origin + ("/#reference-title" if not nonempty else "/"))
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip current")
        await expect(page.locator("#triage-panel")).to_have_attribute("aria-busy", "false")
        if not nonempty:
            await expect(page.locator("#workspace-live")).to_be_hidden()
            await expect(page.locator("#workspace-analysis")).to_be_visible()
            passed("startup fragment selects its owning workspace")
            await page.locator("#workspace-tab-live").click()
        else:
            await expect(page.locator("#workspace-live")).to_be_visible()
            await expect(page.locator("#workspace-analysis")).to_be_hidden()
        await page.locator("#workspace-tab-help").click()
        await expect(page).to_have_url(origin + "/#workspace-help")
        await page.locator("#workspace-tab-traffic").click()
        await page.go_back()
        await expect(page.locator("#workspace-help")).to_be_visible()
        await page.go_forward()
        await expect(page.locator("#workspace-traffic")).to_be_visible()
        await page.locator("#workspace-tab-live").click()
        passed("workspace links survive Back and Forward")
        await expect(page.locator("#workspace-interfaces")).to_be_hidden()
        await page.locator("#workspace-tab-analysis").click()
        await expect(page.locator("#analysis-window-title")).to_contain_text("unavailable")
        passed("display-only Qwen receipt is loaded once and remains unavailable when not supplied",
               counts["advisory"] == 1)
        await page.locator("#workspace-tab-analysis").click()
        await page.locator(".room-audit-history > summary").click()
        await page.locator("#triage-tools > summary").click()
        await page.locator("#pause-button").click()
        await expect(page.locator("#pause-button")).to_have_attribute("aria-pressed", "true")
        passed("real HTTP bootstrap " + ("nonempty" if nonempty else "empty"), response.status == 200)
        stable = dict(counts)
        await asyncio.sleep(2.4)
        passed("pause stops scheduled polling " + str(nonempty), counts == stable)
        await expect(page.locator("#room-updated")).not_to_have_text("Not fetched")
        await page.locator("#workspace-tab-traffic").click()
        traffic_views = page.locator("#room-traffic-grid .room-visual")
        await expect(traffic_views).to_have_count(8)
        for index in range(8):
            details = traffic_views.nth(index).locator(":scope > details")
            disclosure = details.locator(":scope > summary")
            await expect(disclosure).to_have_text("Source and coverage details")
            await expect(details.locator(".room-meta")).to_be_hidden()
            await disclosure.focus()
            await page.keyboard.press("Enter")
            await expect(details.locator(".room-meta")).to_be_visible()
            for label in ("source:", "vantage: unknown", "last update:", "unit:", "quality:"):
                await expect(details.locator(".room-meta")).to_contain_text(label)
            await page.keyboard.press("Enter")
            await expect(details.locator(".room-meta")).to_be_hidden()
        passed("eight traffic views expose source and quality through keyboard-operable disclosures")
        if nonempty:
            await expect(page.locator("#room-home-summary")).to_contain_text("2 stored metadata events")
            await expect(page.locator("#room-traffic-grid")).to_contain_text("200 reported bytes")
            await page.locator("#workspace-tab-findings").click()
            passed("qualified linked finding rows", await page.locator("#room-findings-table tbody tr").count() == 2)
            await page.locator("#room-range").select_option("hour")
            await page.locator("#room-apply").click()
            await expect(page.locator("#room-refresh")).to_be_enabled()
            await expect(page.locator("#room-coverage")).to_have_text("Unavailable")
            await expect(page.locator("#room-count")).to_have_text("Unavailable")
            passed("time filter does not turn missing coverage into zero traffic")
            await page.locator("#room-range").select_option("recorded")
            await page.locator("#room-apply").click()
            await expect(page.locator("#room-refresh")).to_be_enabled()
            await expect(page.locator("#room-home-summary")).to_contain_text("2 stored metadata events")
        else:
            await expect(page.locator("#room-traffic-grid")).to_contain_text("No qualified data available")
        await page.locator("#workspace-tab-reports").click()
        if nonempty:
            request_counts = dict(counts)
            violation_count = len(violations)
            await expect(page.locator("#room-report-download")).to_be_disabled()
            await page.locator("#room-report-create").click()
            await expect(page.locator("#room-report-status")).to_contain_text("Preview ready")
            await expect(page.locator("#room-report-download")).to_be_enabled()
            preview_text = await page.locator("#room-report-preview").inner_text()
            report = json.loads(preview_text)
            passed("local report preview uses the closed metadata-only schema",
                   list(report) == ["schema", "generated_at", "title", "range", "sources",
                                    "vantage", "quality", "freshness", "unit", "counts",
                                    "findings", "limitations", "build"] and
                   report["schema"] == "megalodon-local-report-v1" and
                   report["counts"] == {"events": 2, "findings": 2, "reported_bytes": "200"} and
                   all(token not in preview_text for token in ("192.0.2.", "198.51.100.", "src_ip", "dst_ip", "event_id")))
            async with page.expect_download() as download_info:
                await page.locator("#room-report-download").click()
            download = await download_info.value
            downloaded = Path(await download.path()).read_text(encoding="utf-8")
            passed("explicit browser download exactly matches the bounded preview",
                   downloaded == preview_text + ("\n" if not preview_text.endswith("\n") else "") and
                   download.suggested_filename.startswith("megalodon-local-report-") and
                   download.suggested_filename.endswith(".json") and len(downloaded.encode("utf-8")) <= 65536)
            passed("report preview and download make no page request",
                   counts == request_counts and len(violations) == violation_count)
        else:
            await page.locator("#room-report-create").click()
            await expect(page.locator("#room-report-status")).to_contain_text("No qualified data")
            await expect(page.locator("#room-report-download")).to_be_disabled()
            passed("empty report flow refuses to invent zero evidence")
        await page.locator(".room-back").click()
        await expect(page.locator("#workspace-live")).to_be_visible()
        passed("persistent return control reaches Home")
        await page.locator("#workspace-tab-analysis").click()
        await page.locator('details[aria-labelledby="offline-title"] > summary').click()
        if not nonempty:
            await expect(page.locator("#events")).to_contain_text("No detections recorded.")
            await expect(page.locator("#offline-empty")).to_be_visible()
            passed("empty database and unselected offline states")
            passed("empty page has no script errors or nonlocal requests", not errors and not violations)
            return

        rows = page.locator("#events tr")
        passed("nonempty five-cell semantic rows", await rows.count() == 2 and
               await rows.evaluate_all("rs => rs.every(r => r.cells.length === 5 && r.cells[0].firstElementChild.tagName === 'TIME')"))
        # Native keyboard activation of the real skip link, not a replacement DOM.
        await page.locator(".skip-link").focus()
        await page.keyboard.press("Enter")
        passed("skip-link keyboard target", await page.evaluate("document.activeElement.id") == "detections-title")
        await page.locator("#filter-query").fill("no-synthetic-match")
        await expect(page.locator("#events")).to_contain_text("No detections match these filters.")
        await page.locator("#clear-filters").click()
        passed("local search and clear", await rows.count() == 2)
        await page.locator("#workspace-tab-analysis").click()
        await expect(page.locator("#workspace-live")).to_be_hidden()
        await expect(page.locator("#workspace-analysis")).to_be_visible()
        await expect(page.locator("#offline-content")).to_be_visible()
        offline_text = await page.locator("#offline-content").inner_text()
        passed("real offline projection excludes addresses", "203.0.113." not in offline_text and
               "synthetic.jsonl" not in offline_text and "flow" in offline_text)
        await page.locator('details[aria-labelledby="reference-title"] > summary').click()
        await page.locator("#reference-port").fill("443")
        await page.locator("#reference-port-form button").click()
        await expect(page.locator("#reference-status")).to_contain_text("Reference context loaded for tcp/443")
        await page.locator("#reference-clear").click()
        await expect(page.locator("#reference-status")).to_contain_text("Displayed context cleared")
        passed("real IANA lookup and browser-only clear")

        async def fail(route):
            await route.abort("failed")

        await page.route("**/api/integrations?*", fail)
        await page.locator("#workspace-tab-interfaces").click()
        await expect(page.locator("#workspace-analysis")).to_be_hidden()
        await expect(page.locator("#workspace-interfaces")).to_be_visible()
        await expect(page.locator("#integrations-status")).to_contain_text("unavailable")
        await page.locator("#integrations-query").fill("no-synthetic-match")
        await expect(page.locator("#integrations-status")).to_contain_text("unavailable")
        passed("initial integration failure survives filtering")
        await page.unroute("**/api/integrations?*", fail)
        await page.locator("#integrations-clear").click()
        await page.locator("#integrations-load").click()
        await expect(page.locator("#integrations-profile")).to_contain_text("Loaded profile: linux")
        passed("real static Integration Map recovery")
        passed("four separate capability rows per supported app",
               await page.locator("#integrations-cards .app-status-grid").count() == 14 and
               await page.locator("#integrations-cards .app-status-row").count() == 56)
        legend = await page.locator(".app-state-legend").inner_text()
        passed("presence legend explains bounded green red and gray states",
               all(label in legend for label in ("Found candidate", "Not found", "Not checked")))

        async def slow(route):
            await asyncio.sleep(1)
            await route.continue_()

        await page.route("**/api/integrations?*", slow)
        await page.locator("#integrations-platform").select_option("windows")
        await page.locator("#integrations-load").click()
        await page.locator("#integrations-query").fill("no-synthetic-match")
        await expect(page.locator("#integrations-status")).to_contain_text("Loading the static windows")
        await expect(page.locator("#integrations-profile")).to_contain_text("Loaded profile: linux")
        await expect(page.locator("#integrations-profile")).to_contain_text("Loaded profile: windows")
        await page.unroute("**/api/integrations?*", slow)
        passed("pending integration profile survives real request delay")

        await page.locator("#workspace-tab-analysis").click()
        await expect(page.locator("#workspace-analysis")).to_be_visible()
        saved_rows = await page.locator("#events").inner_text()
        saved_time = await page.locator("#updated").get_attribute("datetime")
        await page.route("**/api/summary", fail)
        await page.route("**/api/events?*", slow)
        before = dict(counts)
        await page.locator("#refresh-button").click()
        await asyncio.sleep(0.2)
        passed("failed peer retains refresh guard", await page.evaluate("state.refreshing") and
               await page.locator("#refresh-button").is_disabled())
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip stale")
        expected_counts = dict(before)
        expected_counts["summary"] += 1
        expected_counts["events"] += 1
        passed("failed refresh preserves rows time and one request pair",
               await page.locator("#events").inner_text() == saved_rows and
               await page.locator("#updated").get_attribute("datetime") == saved_time and
               counts == expected_counts)
        await page.unroute("**/api/summary", fail)
        await page.unroute("**/api/events?*", slow)
        await page.locator("#refresh-button").click()
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip paused")
        passed("real-backend refresh recovers after fault")

        # The real requestJSON AbortController must expire a held HTTP response.
        from playwright.async_api import Error as BrowserError
        timeout_finished = asyncio.Event()

        async def exceed_timeout(route):
            try:
                await asyncio.sleep(6)
                await route.continue_()
            except BrowserError:
                pass  # The application may already have cancelled this intercepted request.
            finally:
                timeout_finished.set()

        await page.route("**/api/summary", exceed_timeout)
        saved_time = await page.locator("#updated").get_attribute("datetime")
        await page.locator("#refresh-button").click()
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip stale", timeout=8000)
        passed("real request helper timeout preserves prior data",
               await page.locator("#updated").get_attribute("datetime") == saved_time and
               await page.locator("#events").inner_text() == saved_rows)
        await asyncio.wait_for(timeout_finished.wait(), timeout=3)
        await page.unroute("**/api/summary", exceed_timeout)
        await page.locator("#refresh-button").click()
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip paused")
        passed("timeout recovery uses real backend")

        # Use an actual headed browser-window state transition under Xvfb; do not override document.hidden.
        REPORT["native_stimulus"] = "Browser.setWindowBounds:minimized/normal"
        REPORT["stage"] = "resume-before-native-visibility"
        await page.locator("#pause-button").click()
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip current")
        REPORT["stage"] = "minimize-native-dashboard-window"
        REPORT["native_window_after_minimize"] = await set_native_window_state(page, "minimized")
        try:
            REPORT["stage"] = "wait-native-hidden-and-idle"
            await wait_native_visibility(page, True)
            await wait_refresh_idle(page, "hidden")
            hidden_counts = dict(counts)
            await asyncio.sleep(2.4)
            passed("native hidden window suspends polling", counts == hidden_counts)
        finally:
            REPORT["stage"] = "restore-native-dashboard-window"
            REPORT["native_window_after_restore"] = await set_native_window_state(page, "normal")
        REPORT["stage"] = "wait-native-visible-and-idle"
        await wait_native_visibility(page, False)
        await wait_refresh_idle(page, "visible")
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip current")
        await page.locator("#pause-button").click()
        passed("native foreground resumes polling", counts["summary"] > hidden_counts["summary"])
        REPORT["stage"] = "mobile-layout-and-focus"
        await page.set_viewport_size({"width": 375, "height": 812})
        passed("mobile page fits viewport", await page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
        passed("command center remains viewport-pinned", await page.evaluate("""() => {
            const shell = document.querySelector('.shell').getBoundingClientRect();
            const scroller = document.querySelector('.workspace-scroll');
            return shell.top >= -1 && shell.bottom <= innerHeight + 1
                && getComputedStyle(document.documentElement).overflow === 'hidden'
                && getComputedStyle(document.body).overflow === 'hidden'
                && getComputedStyle(scroller).overflowY === 'auto';
        }"""))
        await page.locator("#filter-query").focus()
        passed("rendered keyboard focus", await page.locator("#filter-query").evaluate(
            "el => document.activeElement === el && getComputedStyle(el).outlineStyle !== 'none'"))
        await page.set_viewport_size({"width": 1440, "height": 1000})
        await page.locator("#workspace-tab-traffic").click()
        REPORT["zoom_equivalent_viewports"] = {}
        for level, width, height in ((200, 720, 500), (400, 360, 250)):
            await page.set_viewport_size({"width": width, "height": height})
            metrics = await page.evaluate("""() => ({
                width: innerWidth, height: innerHeight,
                root_scroll_width: document.documentElement.scrollWidth,
                workspace_scroll: getComputedStyle(document.querySelector('.workspace-scroll')).overflowY
            })""")
            REPORT["zoom_equivalent_viewports"][str(level)] = metrics
            passed(f"{level} percent zoom-equivalent viewport preserves return and internal scroll",
                   await page.locator(".room-back").is_visible() and
                   metrics["width"] == width and metrics["height"] == height and
                   metrics["root_scroll_width"] <= metrics["width"] + 1 and
                   metrics["workspace_scroll"] == "auto")
        await page.set_viewport_size({"width": 1440, "height": 1000})
        passed("no page script errors or nonlocal page requests", not errors and not violations)
    finally:
        await context.close()


async def run() -> None:
    from playwright.async_api import async_playwright
    from importlib.metadata import version
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("unprivileged Linux required")
    REPORT.update(python=platform.python_version(), os=platform.freedesktop_os_release().get("PRETTY_NAME"),
                  sqlite=sqlite3.sqlite_version, playwright=version("playwright"),
                  sandbox_requested=True, headed=True, reduced_motion="reduce",
                  viewports=[[1440, 1000], [375, 812]])
    with sqlite3.connect(":memory:") as connection:
        REPORT["sqlite_source_id"] = connection.execute("select sqlite_source_id()").fetchone()[0]
    REPORT["commit"] = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True, timeout=5).strip()
    REPORT["tree"] = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], text=True, timeout=5).strip()
    prior_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="megalodon-browser-") as temp:
            root = Path(temp)
            missing, missing_db = config(root, "missing")
            unsafe_startup(missing, missing_db)
            empty, empty_db = config(root, "empty")
            result = cli(
                "run", "--config", str(empty), "--source", "jsonl",
                "--max-events", "100", stdin="",
            )
            passed("empty fixture writer completed", result["status"] == "completed")
            populated, populated_db = config(root, "populated")
            events = [{"observed_at": "2026-01-01T00:00:00+00:00", "src_ip": f"192.0.2.{n}",
                       "dst_ip": "198.51.100.20", "protocol": "UDP", "src_port": 40000,
                       "dst_port": 53, "dns_query_length": 90, "byte_count": 100} for n in (10, 11)]
            result = cli(
                "run", "--config", str(populated), "--source", "jsonl",
                "--max-events", "100",
                stdin="".join(json.dumps(event) + "\n" for event in events),
            )
            passed("real ingestion produced complete synthetic evidence", result["status"] == "completed"
                   and result["processed"] == 2 and result["detections"] == 2 and result["actions"] == 2)
            offline = offline_fixture(root)
            async with async_playwright() as playwright:
                # No download, executable override, sandbox disable, or policy workaround.
                browser = await playwright.chromium.launch(channel="chrome", headless=False,
                                                            chromium_sandbox=True, timeout=20000)
                REPORT["browser"] = browser.version
                try:
                    for settings, db, nonempty in ((empty, empty_db, False), (populated, populated_db, True)):
                        original = hashlib.sha256(db.read_bytes()).hexdigest()
                        with dashboard(settings, offline if nonempty else None) as port:
                            status, headers, body = request(port, "/api/events?limit=5")
                            records = json.loads(body)
                            passed("five-field HTTP projection " + str(nonempty), status == 200 and
                                   len(records) == (2 if nonempty else 0) and all(set(row) ==
                                   {"detected_at", "rule_id", "severity", "src_ip", "message"} for row in records))
                            passed("HTTP security headers " + str(nonempty), headers.get("Cache-Control") == "no-store" and
                                   "unsafe-inline" not in headers.get("Content-Security-Policy", "unsafe-inline") and
                                   headers.get("X-Content-Type-Options") == "nosniff")
                            for query in ("limit=0", "limit=201", "limit=1&limit=2", "extra=1", "limit=x"):
                                passed("query refusal " + query + " " + str(nonempty),
                                       request(port, "/api/events?" + query)[0] == 400)
                            for label, hosts in (("missing", []), ("foreign", ["foreign.invalid"]),
                                                 ("wrong-port", ["127.0.0.1:1"]),
                                                 ("duplicate", [f"127.0.0.1:{port}", f"127.0.0.1:{port}"])):
                                passed("Host refusal " + label + " " + str(nonempty),
                                       request(port, "/api/summary", hosts)[0] == 400)
                            await exercise(browser, port, nonempty)
                        passed("main database bytes unchanged " + str(nonempty),
                               hashlib.sha256(db.read_bytes()).hexdigest() == original)
                finally:
                    await browser.close()
    finally:
        os.umask(prior_umask)
    REPORT.pop("stage", None)
    REPORT["status"] = "passed"


if __name__ == "__main__":
    try:
        asyncio.run(asyncio.wait_for(run(), timeout=180))
    except Exception as error:
        # Synthetic test stage names aid diagnosis without dumping app rows/paths.
        REPORT["failure"] = type(error).__name__
        sites = [frame.lineno for frame in traceback.extract_tb(error.__traceback__)
                 if frame.filename == __file__]
        REPORT["failure_line"] = sites[-1] if sites else None
        for needle, code in (("unsafe-eval", "CSP_EVAL_REFUSED"),
                             ("state is not defined", "STATE_SCOPE_UNAVAILABLE"),
                             ("Execution context was destroyed", "CONTEXT_DESTROYED"),
                             ("Target page, context or browser has been closed", "TARGET_CLOSED")):
            if needle in str(error):
                REPORT["driver_error_code"] = code
                break
        if isinstance(error, AssertionError):
            REPORT["failure_check"] = str(error)[:160]
    finally:
        print("MEGALODON_BROWSER_ACCEPTANCE " + json.dumps(REPORT, sort_keys=True), flush=True)
    raise SystemExit(0 if REPORT["status"] == "passed" else 1)
