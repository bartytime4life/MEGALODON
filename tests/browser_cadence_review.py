"""Exercise the fixed offline casebook as a reviewer, with correct and incorrect citations."""
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


PAGE = (Path(__file__).resolve().parents[1] / "examples" / "cadence-review.html").as_uri()
SEGMENT = "920593d1b5dbc87a1b2694e1112bca12"
ALL = (1, 2, 3, 4, 5)
# Independent expectations for the three projections of job 125495799362.
KEY = {
    ("fixture-listener", 0): ("Within grant scope", ALL),
    ("reserved-alternate", 0): ("Destination conflicts with grant", ALL),
    ("fixture-listener", 1): ("Insufficient evidence", (5,)),
}


def review(page, *, wrong):
    page.goto(PAGE)
    bundles = page.get_by_role("article").all()
    assert len(bundles) == 3
    check = page.get_by_role("button", name="Check my decisions")
    expect(check).to_be_disabled()
    seen, expected = set(), []
    for bundle in bundles:
        rows = bundle.locator("tbody tr")
        assert rows.count() == 5
        assert rows.locator("th").all_text_contents() == [f":{n}" for n in ALL]
        assert rows.locator("td:first-of-type").all_text_contents() == ["fixture-listener"] * 5
        grant = bundle.locator(".bundle").inner_text().removeprefix("Permitted endpoint: ")
        late = rows.filter(has_text="Slot empty at lookup after close")
        signature = (grant, late.count())
        answer, refs = KEY[signature]
        seen.add(signature)
        if late.count():
            expect(late.locator("th")).to_have_text(":5")
        expected.append((answer, refs))
        bundle.get_by_role("radio", name="Insufficient evidence" if wrong else answer, exact=True).check()
        expect(check).to_be_disabled()
        for n in ((1,) if wrong else refs):
            bundle.get_by_role("checkbox", name=f":{n}", exact=True).check()
        expect(page.get_by_text("Evidence check", exact=True)).to_have_count(0)
    assert seen == set(KEY)
    expect(check).to_be_enabled()
    # Removing the final bundle's citations closes the gate again.
    cited = [control for control in bundles[-1].get_by_role("checkbox").all() if control.is_checked()]
    for control in cited:
        control.uncheck()
    expect(check).to_be_disabled()
    for control in cited:
        control.check()
    check.focus()
    page.keyboard.press("Enter")
    expect(page.get_by_text("Evidence check", exact=True)).to_have_count(3)
    expect(bundles[0].get_by_role("heading", name="Evidence check")).to_be_focused()
    for bundle, (answer, refs) in zip(bundles, expected):
        feedback = bundle.locator(".feedback")
        agrees = (not wrong) or answer == "Insufficient evidence"
        expect(feedback).to_contain_text("Decision " + ("agrees" if agrees else "differs") +
                                         " · References " + ("differ" if wrong else "agree") + ".")
        expect(feedback).to_contain_text("Supporting references: " + ", ".join(f"{SEGMENT}:{n}" for n in refs))
        expect(bundle.get_by_role("radio").first).to_be_disabled()
    expect(check).to_be_disabled()
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.reload()
    expect(page.locator("input:checked")).to_have_count(0)
    expect(page.locator(".feedback")).to_have_count(0)


def main():
    errors, requests = [], []
    with sync_playwright() as driver:
        browser = driver.chromium.launch(channel="chrome", chromium_sandbox=True)
        for width, wrong in ((1100, False), (360, True)):
            context = browser.new_context(viewport={"width": width, "height": 720},
                                          offline=True, service_workers="block")
            page = context.new_page()
            page.set_default_timeout(4000)
            page.on("request", lambda request: requests.append(request.url))
            page.on("pageerror", lambda exc: errors.append(str(exc)))
            review(page, wrong=wrong)
            context.close()
        browser.close()
    assert set(requests) == {PAGE} and not errors
    print("Cadence review passed: offline file only, all three decisions and citations, "
          "early reveal refused, wrong answers, keyboard reveal, 360px layout and reload reset.")


if __name__ == "__main__":
    main()
