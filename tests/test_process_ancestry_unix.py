"""Applications behind a web server on a Unix socket (gunicorn and uvicorn behind nginx) count as services too."""
from __future__ import annotations

import subprocess
import sys
import threading
import time

import pytest

from megalodon import process_ancestry as anc
from test_process_ancestry import NOW, proc, root  # noqa: F401

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
HEADER = "Num       RefCount Protocol Flags    Type St Inode Path\n"


def unix(root, pid, rows, holds=()):
    """Give `pid` a Unix socket table of (inode, flags, type, path) rows, and descriptors for the inodes in `holds`."""
    net = root / "proc" / str(pid) / "net"
    net.mkdir(parents=True, exist_ok=True)
    (net / "unix").write_text(HEADER + "".join(
        f"0000000000000000: 00000002 00000000 {flags} {kind} 01 {inode}{' ' + path if path else ''}\n"
        for inode, flags, kind, path in rows))
    fds = root / "proc" / str(pid) / "fd"
    fds.mkdir(exist_ok=True)
    for number, inode in enumerate(holds, start=3):
        (fds / str(number)).symlink_to(f"socket:[{inode}]")


def found(root):
    return {f["evidence"]["pid"]: f for f in anc.check(str(root), now=NOW)["findings"]}


def test_an_application_on_a_unix_socket_starting_a_shell_is_found(root):  # noqa: F811
    proc(root, 70, 1, "/usr/bin/python3.12", ["/usr/bin/python3", "/usr/local/bin/gunicorn", "--bind",
                                               "unix:/run/gunicorn/app.sock", "app:app"])
    unix(root, 70, [(700, "00010000", "0001", "/run/gunicorn/app.sock"),
                    (701, "00000000", "0001", "")], holds=(700, 701))
    proc(root, 71, 70, "/usr/bin/dash", ["sh", "-c", "id"])
    shell = found(root)[71]
    assert (shell["rule_id"], shell["severity"], shell["evidence"]["service"]["category"]) == (
        "SERVICE_SPAWNED_SHELL", "MEDIUM", "application")


def test_unix_sockets_that_are_not_a_service_s_stay_quiet(root):  # noqa: F811
    cases = {
        100: (1000, "00010000", "0001", "@abstract-ipc"),                  # abstract: no file anyone connects to
        110: (1100, "00010000", "0001", "/run/user/1000/editor-ipc.sock"),  # a person's desktop session
        120: (1200, "00010000", "0001", "/tmp/pymp-k2x9/listener-77"),      # multiprocessing's own
        130: (1300, "00000000", "0001", "/run/app/client.sock"),            # bound, not listening
        140: (1400, "00010000", "0002", "/run/app/dgram.sock"),             # not a stream socket
    }
    for pid, row in cases.items():
        proc(root, pid, 1, "/usr/bin/python3.12", ["python3", f"/srv/job{pid}.py"])
        unix(root, pid, [row], holds=(row[0],))
        proc(root, pid + 1, pid, "/usr/bin/dash", ["sh", "-c", "date"])
    proc(root, 150, 1, "/usr/bin/node", ["node", "/srv/app.js"])
    unix(root, 150, [(1500, "00010000", "0001", "/run/app/app.sock")], holds=())   # someone else's listener
    proc(root, 151, 150, "/usr/bin/dash", ["sh", "-c", "date"])
    assert not {101, 111, 121, 131, 141, 151} & set(found(root))



def watch(run):
    seen = []
    watcher = anc.Watcher(seen.append, interval=0.05)
    stop = threading.Event()
    worker = threading.Thread(target=watcher.run, args=(stop,), kwargs=dict(timeout=0.1), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        pid = run()
        time.sleep(0.5)
    finally:
        stop.set()
        worker.join(5)
        watcher.close()
    return [f for f in seen if f["evidence"]["service"]["pid"] == pid], watcher.mode


@linux
def test_a_live_unix_socket_server_starting_a_shell_is_caught(tmp_path):
    server = (
        "import socket, subprocess, sys, time\n"
        "s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen()\n"
        "time.sleep(0.6)\n"
        "subprocess.run(['/bin/sh', '-c', 'sleep 0.6; /usr/bin/id >/dev/null; sleep 0.6'])\n")

    def run():
        child = subprocess.Popen([sys.executable, "-c", server, str(tmp_path / "app.sock")])
        child.wait(10)
        return child.pid
    mine, mode = watch(run)
    assert ("SERVICE_SPAWNED_SHELL", "application") in {
        (f["rule_id"], f["evidence"]["service"]["category"]) for f in mine}, mode


@linux
def test_a_live_multiprocessing_listener_is_not_a_service(tmp_path):
    # Its own listener, in the process that then starts a shell: multiprocessing puts it under /tmp/pymp-*.
    script = (
        "import subprocess, time\n"
        "from multiprocessing.connection import Listener\n"
        "listener = Listener(family='AF_UNIX')\n"
        "assert '/pymp-' in listener.address, listener.address\n"
        "time.sleep(0.6)\n"
        "subprocess.run(['/bin/sh', '-c', 'sleep 0.6; /usr/bin/id >/dev/null; sleep 0.6'])\n"
        "listener.close()\n")
    (tmp_path / "job.py").write_text(script)

    def run():
        child = subprocess.Popen([sys.executable, str(tmp_path / "job.py")], cwd=tmp_path)
        assert child.wait(20) == 0
        return child.pid
    mine, _mode = watch(run)
    assert mine == []


def test_process_managers_starting_programs_is_their_job(root):  # noqa: F811
    managers = {
        200: ["/usr/bin/python3", "/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"],
        210: ["/usr/bin/python3", "/usr/bin/fail2ban-server", "-xf", "start"],
        220: ["/usr/bin/python3", "/usr/bin/salt-minion"],
        230: ["node", "/usr/lib/node_modules/pm2/lib/Daemon.js"],
    }
    for pid, argv in managers.items():
        proc(root, pid, 1, "/usr/bin/node" if argv[0] == "node" else "/usr/bin/python3.12", argv)
        unix(root, pid, [(pid * 10, "00010000", "0001", f"/run/manager{pid}.sock")], holds=(pid * 10,))
        proc(root, pid + 1, pid, "/usr/bin/dash", ["sh", "-c", "iptables -I f2b 1 -s 192.0.2.1 -j DROP"])
    # An application a process manager runs is still one.
    proc(root, 202, 200, "/usr/bin/python3.12", ["/usr/bin/python3", "/srv/app/venv/bin/gunicorn", "app:app"])
    unix(root, 202, [(2020, "00010000", "0001", "/run/app/app.sock")], holds=(2020,))
    proc(root, 203, 202, "/usr/bin/dash", ["sh", "-c", "id"])
    assert set(found(root)) == {203}
