"""Process-lifecycle check for the combined HUD and metadata launcher."""

from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "start-hud-data.sh"


@pytest.mark.skipif(
    not LAUNCHER.is_file(),
    reason="Repository-only HUD data launcher is not included in the source distribution",
)
@pytest.mark.parametrize("first_to_stop", ["capture", "hud"])
def test_first_exit_stops_other_process(tmp_path: Path, first_to_stop: str) -> None:
    marker = tmp_path / "calls"
    hud_ready = tmp_path / "hud-ready"
    os.mkfifo(hud_ready)
    fake_python = tmp_path / "python"
    fake_python.write_text(
        f"#!{sys.executable}\n"
        "import os, signal, sys\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "if args[0] == '-c': raise SystemExit(0)\n"
        "marker = Path(os.environ['LAUNCHER_TEST_MARKER'])\n"
        "def mark(value):\n"
        "    with marker.open('a') as handle: handle.write(value + '\\n')\n"
        "def stop(_signal, _frame):\n"
        "    mark('capture-stopped' if 'run' in args else 'hud-stopped')\n"
        "    raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM, stop)\n"
        "if 'run' in args:\n"
        "    mark('capture-started')\n"
        "    if os.environ['LAUNCHER_TEST_FIRST'] == 'capture':\n"
        "        with open(os.environ['LAUNCHER_TEST_HUD_READY'], 'rb') as ready:\n"
        "            assert ready.read(1) == b'1'\n"
        "    else: signal.pause()\n"
        "elif 'hud' in args:\n"
        "    mark('hud-started')\n"
        "    if os.environ['LAUNCHER_TEST_FIRST'] == 'capture':\n"
        "        with open(os.environ['LAUNCHER_TEST_HUD_READY'], 'wb') as ready:\n"
        "            ready.write(b'1')\n"
        "        signal.pause()\n"
        "else: raise SystemExit(2)\n"
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
                 "LAUNCHER_TEST_HUD_READY": str(hud_ready),
                 "LAUNCHER_TEST_FIRST": first_to_stop},
            start_new_session=True,
        )
        os.close(slave)
        slave = -1
        assert process.wait(timeout=8) == 0
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
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
