"""Static integrity checks for executable platform-baseline instructions."""

from pathlib import Path
import re


BASELINE = (Path(__file__).parents[1] / "docs" / "platform-baseline.md").read_text(
    encoding="utf-8"
)
SHA = r"[0-9a-f]{40}"
EXPECTED_COMMIT = "adff346c55fb41be9e51be3cea0c7d8701175c2f"
EXPECTED_TREE = "f2bcd4d39723a80d163aa1cd1271daf3020676f9"


def _one(pattern: str) -> str:
    matches = re.findall(pattern, BASELINE, flags=re.MULTILINE)
    assert len(matches) == 1
    return matches[0]


def test_header_and_executable_recipes_use_one_baseline_pin():
    declared = _one(rf"against\s+`({SHA})` on `main`")
    bash = _one(rf"^BASE=({SHA})$")
    powershell = _one(rf"^\$Base = '({SHA})'$")

    assert bash == powershell == declared == EXPECTED_COMMIT


def test_every_full_git_object_id_is_an_expected_baseline_object():
    assert set(re.findall(rf"(?<![0-9a-f]){SHA}(?![0-9a-f])", BASELINE)) == {
        EXPECTED_COMMIT,
        EXPECTED_TREE,
    }


def test_stale_firewall_candidate_claims_are_absent():
    stale = (
        "#65 candidate",
        "Pinned base has explicit apply",
        "At the pinned base, the firewall apply path",
        "can reach `nft`",
    )
    assert not [claim for claim in stale if claim in BASELINE]


def test_merged_delivery_and_open_governance_are_explicit():
    for number in (72, 73, 74, 75):
        assert f"https://github.com/bartytime4life/MEGALODON/pull/{number}" in BASELINE

    open_status_match = re.search(
        r"Selected platform/release follow-ups observed open included\s+"
        r"(.*?)\. Issue #65",
        BASELINE,
        flags=re.DOTALL,
    )
    assert open_status_match is not None
    open_status = open_status_match.group(1)
    for number in (3, 7, 23, 25, 27, 65, 66, 67, 68, 69, 70):
        assert f"https://github.com/bartytime4life/MEGALODON/issues/{number}" in open_status

    assert "automated `COMMENTED` review, not an approval" in BASELINE
    normalized = " ".join(BASELINE.split())
    assert (
        "No license decision, tag, release, package publication, deployment, "
        "protection/ruleset change, ready transition, or future merge is "
        "authorized by this baseline."
    ) in normalized
