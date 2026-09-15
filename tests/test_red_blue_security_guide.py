"""Static authority-boundary checks for the red/blue/purple practice guide."""

from pathlib import Path


ROOT = Path(__file__).parents[1]
GUIDE_PATH = ROOT / "docs" / "red-blue-security-guide.md"
GUIDE = GUIDE_PATH.read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")
SECURITY_REVIEW = (ROOT / "SECURITY_REVIEW.md").read_text(encoding="utf-8")


def test_guide_is_linked_from_primary_security_entry_points():
    link = "docs/red-blue-security-guide.md"
    assert link in README
    assert link in SECURITY_REVIEW


def test_current_ai_and_action_boundaries_are_explicit():
    normalized = " ".join(GUIDE.split())
    required = (
        "MEGALODON currently has no AI model",
        "permission to deploy them",
        "within a separately authorized scope",
        "within a separately authorized operating scope",
        "Live firewall application remains unsupported",
        "approved loopback boundary",
        "no egress or firewall path",
        "eligible independent reviewer",
        "No model may apply a firewall change",
        "they cannot create a capability",
    )
    assert not [text for text in required if text not in normalized]


def test_all_three_team_functions_and_future_ai_risks_are_covered():
    required = (
        "| Red |",
        "| Blue |",
        "| Purple |",
        "prompt injection",
        "Sensitive disclosure",
        "model extraction",
        "Supply-chain compromise",
        "Data/model poisoning",
        "Improper output handling",
        "Excessive agency",
        "System-prompt leakage",
        "Unbounded consumption",
    )
    assert not [text for text in required if text not in GUIDE]


def test_project_and_external_sources_are_recorded():
    required = (
        "MEGALODON_Advancement_Blueprint(1).docx",
        "MEGALODON Local Command Center Integration Blueprint(1).pdf",
        "https://doi.org/10.6028/NIST.AI.600-1",
        "https://genai.owasp.org/llm-top-10/",
        "https://atlas.mitre.org/",
        "https://novee.security/glossary/red-team-blue-team/",
        "https://cybexer.com/blog/red-team-vs-blue-team-vs-purple-team-the-difference-and-how-ai-changes-each",
    )
    assert not [source for source in required if source not in GUIDE]


def test_guide_stays_defensive_and_non_operational():
    prohibited = (
        "exploit a live target",
        "bypass authorization",
        "disable protections",
        "steal credentials",
    )
    assert not [text for text in prohibited if text in GUIDE.casefold()]
