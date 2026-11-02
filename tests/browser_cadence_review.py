"""Walk through the public practice file using the controls a first-time reader sees."""
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


PAGE = (Path(__file__).resolve().parents[1] / "examples" / "cadence-review.html").as_uri()
SEGMENT = "920593d1b5dbc87a1b2694e1112bca12"
ALL = (1, 2, 3, 4, 5)
MATCH = "The program followed the rule on all five calls."
CONFLICT = "The program called a different place."
UNKNOWN = "We can’t tell whether the program followed the rule."
# Independent expectations for the three projections of job 125495799362.
KEY = {
    ("Front desk", 0): (MATCH, ALL),
    ("Mailroom", 0): (CONFLICT, ALL),
    ("Front desk", 1): (UNKNOWN, (5,)),
}


def row_names(numbers):
    return ("row " if len(numbers) == 1 else "rows ") + ", ".join(str(n) for n in numbers)


def review(page, *, wrong):
    page.goto(PAGE)
    expect(page.get_by_role("heading", name="Think of a phone call")).to_be_visible()
    expect(page.get_by_text("REGULAR_INTERVAL", exact=False)).to_be_hidden()
    expect(page.get_by_role("button", name="Go back")).to_have_count(0)
    seen, expected = set(), []
    for number in (1, 2, 3):
        case = page.get_by_role("article", name=f"Case {number} of 3")
        expect(page.get_by_role("article")).to_have_count(1)
        if number > 1:
            expect(case.get_by_role("heading")).to_be_focused()
        rows = case.locator("tbody tr")
        assert rows.locator("th").all_text_contents() == [str(n) for n in ALL]
        assert rows.locator("td:first-of-type").all_text_contents() == ["Front desk"] * 5
        late = rows.filter(has_text="The call had ended before anyone checked.")
        signature = (case.locator(".place").inner_text(), late.count())
        expect(rows.filter(has_text="The program was on the line.")).to_have_count(5 - late.count())
        if late.count():
            expect(late.locator("th")).to_have_text("5")
        seen.add(signature)
        answer, refs = KEY[signature]
        chosen, picked = (UNKNOWN, (1,)) if wrong else (answer, refs)
        expected.append((chosen, picked, answer, refs))
        advance = page.get_by_role("button", name="Next case" if number < 3 else "Check my answers")
        expect(advance).to_be_disabled()
        case.get_by_role("radio", name=chosen, exact=True).check()
        expect(advance).to_be_disabled()
        expect(page.get_by_role("status")).to_contain_text("choose at least one row")
        if picked == ALL:
            case.get_by_role("button", name="Select all five").click()
        else:
            case.get_by_role("checkbox", name=f"Row {picked[0]}", exact=True).check()
        expect(advance).to_be_enabled()
        # Back keeps the previous answer and row choices. The reader can revise them.
        if number == 2:
            page.get_by_role("button", name="Go back").click()
            first = page.get_by_role("article", name="Case 1 of 3")
            expect(first.get_by_role("radio", name=expected[0][0], exact=True)).to_be_checked()
            assert first.locator("input[type=checkbox]:checked").count() == len(expected[0][1])
            row = first.get_by_role("checkbox", name=f"Row {expected[0][1][0]}", exact=True)
            row.uncheck()
            if len(expected[0][1]) == 1:
                expect(page.get_by_role("button", name="Next case")).to_be_disabled()
            row.check()
            page.get_by_role("button", name="Next case").click()
            expect(case.get_by_role("radio", name=chosen, exact=True)).to_be_checked()
        expect(page.get_by_role("heading", name="Here’s what the records show")).to_have_count(0)
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        advance.focus()
        page.keyboard.press("Enter")
    assert seen == set(KEY)
    expect(page.get_by_role("heading", name="Here’s what the records show")).to_be_focused()
    expect(page.get_by_role("radio")).to_have_count(0)
    for card, (chosen, picked, answer, refs) in zip(page.locator(".feedback").all(), expected, strict=True):
        expect(card).to_contain_text(f"You chose: {chosen} You picked {row_names(picked)}.")
        expect(card).to_contain_text("Your answer fits." if chosen == answer else f"The supported answer is “{answer}”")
        expect(card).to_contain_text("You picked the supporting" if picked == refs else f"Look at {row_names(refs)}.")
        ids = card.locator("code")
        expect(ids).to_be_hidden()
        card.get_by_text("Original record IDs").click()
        expect(ids).to_have_text(", ".join(f"{SEGMENT}:{n}" for n in refs))
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.reload()
    expect(page.get_by_role("article", name="Case 1 of 3")).to_be_visible()
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
    print("Plain-language practice passed: one case at a time, back and edit, complete and "
          "incomplete answers, correct and incorrect rows, first answers shown, optional IDs, "
          "keyboard, 360px layout, reload reset and offline file only.")


if __name__ == "__main__":
    main()
