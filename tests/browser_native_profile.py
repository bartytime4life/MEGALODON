"""Run the fixed browser suite with an isolated, pinned native-focus driver copy.

Stock Playwright 1.57.0 forces pages active on its own CDP session. A second
session cannot release that session's Chromium capturer. Change only that
initialization call, in a temporary copy; never edit the installed driver.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile

PROFILE = "playwright-1.57.0-native-focus-v1"
DRIVER_MODULE = Path("driver/package/lib/server/chromium/crPage.js")
STOCK_SHA256 = "71aab16b0912f23cb9aa3095b8072bfc6fbd6e47e4e13a7be3684b796aa1cd28"
NATIVE_SHA256 = "13b187fcf0558fb182751ada23d5864f5ba1daba7a7b5b585cfd7a7b974c63cd"
FOCUS_CALL = b'promises.push(this._client.send("Emulation.setFocusEmulationEnabled", { enabled: true }));'
NATIVE_CALL = FOCUS_CALL.replace(b"true", b"false")


class ProfileError(RuntimeError):
    """Fixed diagnostic only; no dependency paths or source content."""


def native_driver_bytes(data: bytes) -> bytes:
    if len(data) > 65536 or hashlib.sha256(data).hexdigest() != STOCK_SHA256:
        raise ProfileError("DRIVER_SOURCE_MISMATCH")
    if data.count(FOCUS_CALL) != 1:
        raise ProfileError("DRIVER_CALL_MISMATCH")
    result = data.replace(FOCUS_CALL, NATIVE_CALL)
    if hashlib.sha256(result).hexdigest() != NATIVE_SHA256:
        raise ProfileError("DRIVER_RESULT_MISMATCH")
    return result


def read_driver(root: Path) -> bytes:
    with (root / DRIVER_MODULE).open("rb") as stream:
        return stream.read(65537)


def prepare_profile(source: Path, destination: Path) -> None:
    """Copy a trusted installed test dependency, with finite preflight budgets."""
    original = read_driver(source)
    candidate = native_driver_bytes(original)
    size = entries = 0
    for root, directories, files in os.walk(source, followlinks=False):
        for name in directories + files:
            item = Path(root) / name
            entries += 1
            if item.is_symlink() or not (item.is_file() or item.is_dir()):
                raise ProfileError("DRIVER_COPY_TYPE")
            if item.is_file():
                size += item.stat().st_size
            if entries > 10000 or size > 256 * 1024 * 1024:
                raise ProfileError("DRIVER_COPY_BUDGET")
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if read_driver(destination) != original:
        raise ProfileError("DRIVER_COPY_MISMATCH")
    (destination / DRIVER_MODULE).write_bytes(candidate)
    if read_driver(source) != original or read_driver(destination) != candidate:
        raise ProfileError("DRIVER_READBACK_MISMATCH")


def run_suite(environment: dict[str, str]) -> int:
    """Run one fixed test file; bounded group cleanup also handles interruption."""
    child = subprocess.Popen(
        [sys.executable, str(Path(__file__).with_name("browser_acceptance.py"))],
        env=environment, start_new_session=True,
    )
    try:
        return child.wait(timeout=210)
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


def main() -> int:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ProfileError("UNPRIVILEGED_LINUX_REQUIRED")
    if version("playwright") != "1.57.0":
        raise ProfileError("DRIVER_VERSION_MISMATCH")
    if any(os.environ.get(key) for key in ("PLAYWRIGHT_NODEJS_PATH", "NODE_OPTIONS")):
        raise ProfileError("DRIVER_OVERRIDE_REFUSED")
    import playwright
    source = Path(playwright.__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="megalodon-native-driver-") as temporary:
        prepare_profile(source, Path(temporary) / "playwright")
        receipt = {"profile": PROFILE, "source_sha256": STOCK_SHA256,
                   "result_sha256": NATIVE_SHA256, "installed_driver_changed": False,
                   "focus_emulation_enabled": False, "status": "prepared"}
        print("MEGALODON_BROWSER_DRIVER_PROFILE " + json.dumps(receipt, sort_keys=True), flush=True)
        # Only the test subprocess imports this copy. No package installation,
        # browser-policy change, production module, or input-selected command.
        result = run_suite({**os.environ, "PYTHONPATH": temporary})
        receipt.update(status="passed" if result == 0 else "failed", suite_exit_code=result)
        print("MEGALODON_BROWSER_DRIVER_PROFILE " + json.dumps(receipt, sort_keys=True), flush=True)
        return result


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        failure = str(error) if isinstance(error, ProfileError) else type(error).__name__
        print("MEGALODON_BROWSER_DRIVER_PROFILE " + json.dumps(
            {"profile": PROFILE, "status": "failed", "failure": failure}, sort_keys=True), flush=True)
        raise SystemExit(1)
