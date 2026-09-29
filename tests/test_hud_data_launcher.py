"""Process-lifecycle check for the combined HUD and metadata launcher."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "start-hud-data.sh"


@pytest.mark.parametrize("first_to_stop", ["capture", "hud"])
def test_first_exit_stops_other_process(tmp_path: Path, first_to_stop: str) -> None:
    marker = tmp_path / "calls"
    ready = tmp_path / "ready"
    ready.mkdir()
    fake_python = tmp_path / "python"
    fake_python.write_text(
        f"#!{sys.executable}\n"
        "import os, signal, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "if args[0] == '-c': raise SystemExit(0)\n"
        "marker = Path(os.environ['LAUNCHER_TEST_MARKER'])\n"
        "ready = Path(os.environ['LAUNCHER_TEST_READY'])\n"
        "def mark(value):\n"
        "    with marker.open('a') as handle: handle.write(value + '\\n')\n"
        "def stop(_signal, _frame):\n"
        "    mark(role + '-stopped')\n"
        "    raise SystemExit(0)\n"
        "role = 'capture' if 'run' in args else 'hud' if 'hud' in args else None\n"
        "if role is None: raise SystemExit(2)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "signal.signal(signal.SIGUSR1, lambda _signal, _frame: sys.exit(0))\n"
        "mark(role + '-started')\n"
        "(ready / role).write_text(str(os.getpid()))\n"
        "while True: signal.pause()\n"
    )
    fake_python.chmod(0o700)
    master, slave = os.openpty()
    try:
        process = subprocess.Popen(
            [str(LAUNCHER), "--interface", "lo", "--max-events", "2"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=slave,
            stderr=slave,
            env={**os.environ, "MEGALODON_PYTHON": str(fake_python),
                 "LAUNCHER_TEST_MARKER": str(marker),
                 "LAUNCHER_TEST_READY": str(ready)},
        )
        os.close(slave)
        slave = -1
        deadline = time.monotonic() + 12
        while not all((ready / role).exists() for role in ("capture", "hud")):
            assert process.poll() is None, "launcher exited before both fake processes started"
            assert time.monotonic() < deadline, "fake processes did not both start"
            time.sleep(0.01)
        os.kill(int((ready / first_to_stop).read_text()), signal.SIGUSR1)
        assert process.wait(timeout=5) == 0
        assert marker.read_text().splitlines() == (
            ["capture-started", "hud-started", "hud-stopped"]
            if first_to_stop == "capture" else
            ["capture-started", "hud-started", "capture-stopped"]
        )
    finally:
        if slave >= 0:
            os.close(slave)
        os.close(master)
        if "process" in locals() and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
