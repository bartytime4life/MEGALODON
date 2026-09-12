"""Driver-profile regressions require neither Playwright nor a browser."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "browser_native_profile", Path(__file__).with_name("browser_native_profile.py")
)
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


@pytest.fixture
def module_bytes(monkeypatch):
    source = b"// synthetic driver fixture\n" + profile.FOCUS_CALL + b"\n"
    expected = source.replace(profile.FOCUS_CALL, profile.NATIVE_CALL)
    monkeypatch.setattr(profile, "STOCK_SHA256", hashlib.sha256(source).hexdigest())
    monkeypatch.setattr(profile, "NATIVE_SHA256", hashlib.sha256(expected).hexdigest())
    return source, expected


def test_changes_only_the_driver_owned_focus_initialization(module_bytes):
    source, expected = module_bytes
    assert profile.native_driver_bytes(source) == expected
    assert expected.replace(profile.NATIVE_CALL, profile.FOCUS_CALL) == source


@pytest.mark.parametrize("kind", ["changed", "already-patched", "oversized"])
def test_refuses_unknown_or_already_modified_driver(module_bytes, kind):
    source, expected = module_bytes
    invalid = {"changed": source + b"x", "already-patched": expected, "oversized": b"x" * 65537}[kind]
    with pytest.raises(profile.ProfileError, match="DRIVER_SOURCE_MISMATCH"):
        profile.native_driver_bytes(invalid)


def test_refuses_nonunique_call_even_with_matching_source_digest(monkeypatch, module_bytes):
    source, _ = module_bytes
    duplicate = source + profile.FOCUS_CALL
    monkeypatch.setattr(profile, "STOCK_SHA256", hashlib.sha256(duplicate).hexdigest())
    with pytest.raises(profile.ProfileError, match="DRIVER_CALL_MISMATCH"):
        profile.native_driver_bytes(duplicate)


def test_refuses_unexpected_output_digest(monkeypatch, module_bytes):
    monkeypatch.setattr(profile, "NATIVE_SHA256", "0" * 64)
    with pytest.raises(profile.ProfileError, match="DRIVER_RESULT_MISMATCH"):
        profile.native_driver_bytes(module_bytes[0])


def test_copy_preserves_installed_source_and_other_files(tmp_path, module_bytes):
    source = tmp_path / "installed"
    module = source / profile.DRIVER_MODULE
    module.parent.mkdir(parents=True)
    module.write_bytes(module_bytes[0])
    (source / "unchanged.py").write_text("sentinel\n")
    destination = tmp_path / "isolated" / "playwright"
    profile.prepare_profile(source, destination)
    assert module.read_bytes() == module_bytes[0]
    assert profile.read_driver(destination) == module_bytes[1]
    assert (destination / "unchanged.py").read_text() == "sentinel\n"


def test_unknown_source_fails_before_copy(tmp_path):
    source = tmp_path / "installed"
    module = source / profile.DRIVER_MODULE
    module.parent.mkdir(parents=True)
    module.write_bytes(b"not the pinned driver")
    destination = tmp_path / "isolated"
    with pytest.raises(profile.ProfileError, match="DRIVER_SOURCE_MISMATCH"):
        profile.prepare_profile(source, destination)
    assert not destination.exists()


def test_child_failure_is_not_converted_to_success(monkeypatch):
    calls = []

    class Child:
        def wait(self, *, timeout):
            assert timeout == 210
            return 7

        def poll(self):
            return 7

    def launch(args, **kwargs):
        calls.append((args, kwargs))
        return Child()

    monkeypatch.setattr(profile.subprocess, "Popen", launch)
    assert profile.run_suite({"PYTHONPATH": "synthetic-only"}) == 7
    assert len(calls) == 1
    assert Path(calls[0][0][1]).name == "browser_acceptance.py"
    assert calls[0][1]["start_new_session"] is True
