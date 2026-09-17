"""Keep storage and Sites documentation aligned with executable entry points."""

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_storage_layout_names_supported_entry_points_and_owners():
    document = _text("docs/storage-layout.md")

    assert "`megalodon offline analyze`" not in document
    assert "`run`/`service`/replay commands" not in document
    assert "`megalodon/offline/*` evaluation commands" not in document
    assert "python -m megalodon run" in document
    assert "python -m megalodon.offline --source tshark" in document
    assert "python -m megalodon.evaluation corpus" in document
    assert "megalodon.reference.loader.evaluate_corpus" in document
    assert "megalodon.offline.suricata_consumer.consume_publication" in document
    assert "there is no CLI consumer" in document

    for module in ("megalodon", "megalodon.offline", "megalodon.evaluation"):
        result = subprocess.run(
            [sys.executable, "-m", module, "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr


def test_storage_layout_limits_gitignore_claim_to_exact_patterns():
    document = _text("docs/storage-layout.md")

    assert "created on the operator's filesystem by an\n   explicit command, never committed" not in document
    assert "cannot guarantee that every arbitrary operator-selected path" in document
    assert "git check-ignore --no-index <path>" in document

    ignored = subprocess.run(
        ["git", "check-ignore", "--no-index", "offline-runs/example/manifest.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ignored.returncode == 0, ignored.stderr

    arbitrary = subprocess.run(
        ["git", "check-ignore", "--no-index", "operator-output/example/manifest.json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert arbitrary.returncode == 1, arbitrary.stderr
    assert arbitrary.stdout == ""


def test_site_alignment_requires_a_specific_receipt_for_deployment_parity():
    document = _text("docs/site-source-alignment.md")
    normalized = " ".join(document.split())

    assert "`site/` matches all thirteen tracked Sites source files byte-for-byte" not in document
    assert "thirteen-file Site parity" not in document
    assert "Repository/hosted equality | **VERIFIED for the thirteen `site/` source files**" in document
    assert "`appgprj_6aaa2be9d9288191a15a9c1d743af0b3`" in document
    assert "appgver_706b9bc005cc8191aec7e17bd69448b9" in document
    assert "`appgdep_6aac008f26ec81919669f61df409945d`" in document
    assert "`sha256:e0a9b9b76a6bd85d6479bf4765d661191780139a4adee05e67459bfb104c1227`" in document
    assert "deployment reached terminal `succeeded`" in document
    assert "site/dist/index.html" in document
    assert "site/dist/styles.css" in document
    assert "does **not** establish runtime interoperability" in document
    assert "do not become a Sites deployment" in normalized
