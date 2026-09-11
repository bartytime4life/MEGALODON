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
                     "Page-request monitoring is not OS-level egress containment"]}


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


async def exercise(browser, port: int, nonempty: bool) -> None:
    from playwright.async_api import expect
    origin = f"http://127.0.0.1:{port}"
    context = await browser.new_context(viewport={"width": 1440, "height": 1000},
                                        reduced_motion="reduce", service_workers="block")
    violations: list[str] = []
    errors: list[str] = []
    counts = {"summary": 0, "events": 0}

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

    page.on("request", count)
    try:
        response = await page.goto(origin + "/")
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip current")
        await expect(page.locator("#triage-panel")).to_have_attribute("aria-busy", "false")
        await page.locator("#pause-button").click()
        await expect(page.locator("#pause-button")).to_have_attribute("aria-pressed", "true")
        passed("real HTTP bootstrap " + ("nonempty" if nonempty else "empty"), response.status == 200)
        stable = dict(counts)
        await asyncio.sleep(2.4)
        passed("pause stops scheduled polling " + str(nonempty), counts == stable)
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
        await expect(page.locator("#offline-content")).to_be_visible()
        offline_text = await page.locator("#offline-content").inner_text()
        passed("real offline projection excludes addresses", "203.0.113." not in offline_text and
               "synthetic.jsonl" not in offline_text and "flow" in offline_text)
        await page.locator("#reference-port").fill("443")
        await page.locator("#reference-port-form button").click()
        await expect(page.locator("#reference-status")).to_contain_text("Reference context loaded for tcp/443")
        await page.locator("#reference-clear").click()
        await expect(page.locator("#reference-status")).to_contain_text("Displayed context cleared")
        passed("real IANA lookup and browser-only clear")

        async def fail(route):
            await route.abort("failed")

        await page.route("**/api/integrations?*", fail)
        await page.locator("#integrations-load").click()
        await expect(page.locator("#integrations-status")).to_contain_text("unavailable")
        await page.locator("#integrations-query").fill("no-synthetic-match")
        await expect(page.locator("#integrations-status")).to_contain_text("unavailable")
        passed("initial integration failure survives filtering")
        await page.unroute("**/api/integrations?*", fail)
        await page.locator("#integrations-clear").click()
        await page.locator("#integrations-load").click()
        await expect(page.locator("#integrations-profile")).to_contain_text("Loaded profile: linux")
        passed("real static Integration Map recovery")

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
        passed("failed refresh preserves rows time and one request pair",
               await page.locator("#events").inner_text() == saved_rows and
               await page.locator("#updated").get_attribute("datetime") == saved_time and
               counts == {key: value + 1 for key, value in before.items()})
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

        # Real tab visibility in headed Chrome under Xvfb; do not override document.hidden.
        REPORT["stage"] = "resume-before-native-visibility"
        await page.locator("#pause-button").click()
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip current")
        REPORT["stage"] = "create-native-background-tab"
        other = await context.new_page()
        REPORT["stage"] = "activate-native-background-tab"
        await other.bring_to_front()
        REPORT["stage"] = "wait-native-hidden-and-idle"
        await page.wait_for_function("document.hidden && !state.refreshing")
        hidden_counts = dict(counts)
        await asyncio.sleep(2.4)
        passed("native hidden tab suspends polling", counts == hidden_counts)
        REPORT["stage"] = "activate-native-dashboard-tab"
        await page.bring_to_front()
        REPORT["stage"] = "wait-native-visible-and-idle"
        await page.wait_for_function("!document.hidden && !state.refreshing")
        await expect(page.locator("#trust-strip")).to_have_class("trust-strip current")
        await page.locator("#pause-button").click()
        await other.close()
        passed("native foreground resumes polling", counts["summary"] > hidden_counts["summary"])
        REPORT["stage"] = "mobile-layout-and-focus"
        await page.set_viewport_size({"width": 375, "height": 812})
        passed("mobile page fits viewport", await page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"))
        await page.locator("#filter-query").focus()
        passed("rendered keyboard focus", await page.locator("#filter-query").evaluate(
            "el => document.activeElement === el && getComputedStyle(el).outlineStyle !== 'none'"))
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
            result = cli("run", "--config", str(empty), "--source", "jsonl", stdin="")
            passed("empty fixture writer completed", result["status"] == "completed")
            populated, populated_db = config(root, "populated")
            events = [{"observed_at": "2026-01-01T00:00:00+00:00", "src_ip": f"192.0.2.{n}",
                       "dst_ip": "198.51.100.20", "protocol": "UDP", "src_port": 40000,
                       "dst_port": 53, "dns_query_length": 90, "byte_count": 100} for n in (10, 11)]
            result = cli("run", "--config", str(populated), "--source", "jsonl",
                         stdin="".join(json.dumps(event) + "\n" for event in events))
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
