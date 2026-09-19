"""Keep storage and Sites documentation aligned with executable entry points."""

from pathlib import Path
import re
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
    assert "Historical repository/source equality | **VERIFIED for the thirteen `site/` source files**" in document
    assert "Current `main` / version 18 equality | **NOT EQUAL**" in document
    assert "`appgprj_6aaa2be9d9288191a15a9c1d743af0b3`" in document
    assert "appgver_deed1835c49481918517a5e501536f99" in document
    assert "`appgdep_6aac954de9e88191aa6571bb40dde8b0` succeeded" in document
    assert "`sha256:60f60a5cbe4c8ca9c299c198af0996a32fb14a09e426213c599b527744b5fbf8`" in document
    assert "`9d751a2aa97d313534493e9ef9f1ef8e7136f0a3`" in document
    assert "`main@ceef9817c0cd9de5f9253683603feaa5dc11fcf8`" in document
    assert "`main@440fc176238f6f4c5e4dbb7964f76c30a95bf39d`" in document
    assert "site/dist/index.html" in document
    assert "site/dist/styles.css" in document
    assert "does **not** establish runtime interoperability" in normalized
    assert "later repository edits became a Sites deployment" in normalized


def test_ubuntu_zeek_recipe_pins_the_verified_release_identity():
    readme = _text("README.md")

    assert "ZEEK_VERSION=8.0.10" in readme
    assert (
        "ZEEK_SHA256=dbb1cb6c1eac27a8883ee4bd229a378b2f1253fa18e16cdeaaef8a00f124ddf1"
        in readme
    )
    assert (
        "ZEEK_PRIMARY_FINGERPRINT=962FD2187ED5A1DD82FC478A33F15EAEF8CB8019"
        in readme
    )
    assert (
        "ZEEK_SIGNING_FINGERPRINT=E9690B2B7D8AC1A19F921C4AC68B494DF56ACC7E"
        in readme
    )
    assert "https://download.zeek.org/zeek-$ZEEK_VERSION.tar.gz.asc" in readme
    assert (
        'https://keys.openpgp.org/vks/v1/by-fingerprint/$ZEEK_PRIMARY_FINGERPRINT'
        in readme
    )
    assert "ZEEK_SHA256=''" not in readme
    assert "exact SHA-256 published" not in readme


def test_ubuntu_zeek_recipe_verifies_before_extraction_without_managing_zeek():
    readme = _text("README.md")
    normalized = " ".join(readme.split())
    recipe_match = re.search(
        r"### 3\. Build Zeek as a private, non-service producer.*?~~~bash\n"
        r"(?P<recipe>.*?)\n~~~",
        readme,
        flags=re.DOTALL,
    )
    assert recipe_match is not None
    recipe = recipe_match.group("recipe")

    assert '--homedir "$gpg_home"' in recipe
    assert '--import-options show-only --import "$release_key"' in recipe
    assert 'actual_primary_fingerprint" = "$ZEEK_PRIMARY_FINGERPRINT"' in recipe
    assert '--verify "$signature" "$archive"' in recipe
    assert '$2 == "VALIDSIG"' in recipe
    assert recipe.index('--verify "$signature" "$archive"') < recipe.index(
        'tar -xzf "$archive"'
    )
    assert "systemctl" not in recipe
    assert "zeekctl" not in recipe.lower()

    assert "MEGALODON never launches Zeek" in normalized
    assert "closed-profile conn.log" in normalized
