"""Static CI guards for the committed source build-input inventory."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
INVENTORY_CHECK = "python tools/build_input_inventory.py --check"
CHECKOUT_GUARD = (
    "      - name: Build-input inventory guard\n"
    f"        run: {INVENTORY_CHECK}\n"
)
SDIST_ARTIFACTS = (
    '          test -f "${sdist_roots[0]}/contracts/build-inputs/v1/README.md"\n',
    '          test -f "${sdist_roots[0]}/contracts/build-inputs/v1/inventory.json"\n',
    '          cmp tools/build_input_inventory.py "${sdist_roots[0]}/tools/build_input_inventory.py"\n',
)
SDIST_CHECK = (
    '          (\n'
    '            cd "${sdist_roots[0]}"\n'
    '            "$RUNNER_TEMP/sdist-venv/bin/python" -I tools/build_input_inventory.py --check\n'
    '          )\n'
)
SDIST_INSTALL = (
    '          "$RUNNER_TEMP/sdist-venv/bin/python" -I -m pip install --no-index '
    '--no-deps --no-build-isolation --no-cache-dir "${sdists[0]}"\n'
)


def assert_inventory_ci_wiring(text: str) -> None:
    assert text.count(CHECKOUT_GUARD) == 1, "one checkout inventory guard required"
    assert text.index("      - name: Repository hygiene guard\n") < text.index(CHECKOUT_GUARD)
    assert text.index(CHECKOUT_GUARD) < text.index("      - name: Install package\n")
    for artifact_check in SDIST_ARTIFACTS:
        assert artifact_check in text, "source distribution inventory artifact check required"
    assert SDIST_CHECK in text, "source distribution inventory verification required"
    assert text.index(SDIST_ARTIFACTS[-1]) < text.index(SDIST_CHECK) < text.index(SDIST_INSTALL)


def test_ci_checks_checkout_and_source_distribution_inventory():
    assert_inventory_ci_wiring((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    "needle",
    (
        CHECKOUT_GUARD,
        *SDIST_ARTIFACTS,
        SDIST_CHECK,
    ),
)
def test_inventory_ci_weakenings_are_rejected(needle):
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    damaged = text.replace(needle, "          echo omitted\n", 1)
    assert damaged != text
    with pytest.raises(AssertionError):
        assert_inventory_ci_wiring(damaged)
