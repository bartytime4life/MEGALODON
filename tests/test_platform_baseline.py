"""Static integrity checks for executable platform-baseline instructions."""

from pathlib import Path
import re


BASELINE = (Path(__file__).parents[1] / "docs" / "platform-baseline.md").read_text(
    encoding="utf-8"
)
SHA = r"[0-9a-f]{40}"


def _one(pattern: str) -> str:
    matches = re.findall(pattern, BASELINE, flags=re.MULTILINE)
    assert len(matches) == 1
    return matches[0]


def test_header_and_executable_recipes_use_one_baseline_pin():
    declared = _one(rf"against `({SHA})` on `main`")
    bash = _one(rf"^BASE=({SHA})$")
    powershell = _one(rf"^\$Base = '({SHA})'$")

    assert bash == powershell == declared


def test_every_full_commit_pin_is_the_declared_baseline():
    declared = _one(rf"against `({SHA})` on `main`")
    assert set(re.findall(rf"(?<![0-9a-f]){SHA}(?![0-9a-f])", BASELINE)) == {declared}
