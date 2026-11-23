"""Applications run by an interpreter or the JVM count as services while they hold a listening socket."""
from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time

import pytest

from megalodon import process_ancestry as anc
from test_process_ancestry import NOW, proc, root  # noqa: F401

linux = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="reads /proc")
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def listening(root, pid, inode, holds=True, state="0A"):
    """Give process `pid` a TCP socket table with one socket, and (with `holds`) a descriptor for it."""
    net = root / "proc" / str(pid) / "net"
    net.mkdir(parents=True, exist_ok=True)
    (net / "tcp").write_text(HEADER + f"   0: 0100007F:1F40 00000000:0000 {state} 00000000:00000000 00:00000000 "
                                      f"00000000  1000        0 {inode} 1\n")
    fds = root / "proc" / str(pid) / "fd"
    fds.mkdir(exist_ok=True)
    if holds:
        (fds / "3").symlink_to(f"socket:[{inode}]")


def findings(root):
    return {f["evidence"]["pid"]: f for f in anc.check(str(root), now=NOW)["findings"]}


def test_a_python_application_server_starting_a_shell_is_found(root):  # noqa: F811
    proc(root, 70, 1, "/usr/bin/python3.12", ["/usr/bin/python3", "/usr/local/bin/gunicorn", "app:app"])
    proc(root, 71, 70, "/usr/bin/python3.12", ["/usr/bin/python3", "/usr/local/bin/gunicorn", "app:app"])
    for pid in (70, 71):
        listening(root, pid, 777)                         # workers inherit the master's listening socket
    proc(root, 72, 71, "/usr/bin/dash", ["sh", "-c", "id; uname -a"])
    proc(root, 73, 72, "/usr/bin/id", ["id"])
    found = findings(root)
    shell = found[72]
    assert (shell["rule_id"], shell["severity"]) == ("SERVICE_SPAWNED_SHELL", "MEDIUM")
    assert shell["evidence"]["service"] == dict(program="/usr/bin/python3.12", category="application", pid=71,
                                                start=1071, allow_as="/usr/bin/python3.12 /usr/local/bin/gunicorn")
    assert shell["message"].startswith("application service python3.12 /usr/local/bin/gunicorn (pid 71) started")
    assert (found[73]["rule_id"], found[73]["evidence"]["kind"]) == ("SERVICE_SPAWNED_TOOL", "recon")


def test_node_and_java_servers(root):  # noqa: F811
    proc(root, 80, 1, "/usr/bin/node", ["node", "server.js"])
    listening(root, 80, 801)
    proc(root, 81, 80, "/usr/bin/curl", ["curl", "-s", "http://example.test/x"])
    proc(root, 90, 1, "/usr/lib/jvm/java-21/bin/java", ["java", "-Xmx1g", "-jar", "/opt/app/app.jar"])
    listening(root, 90, 901)
    proc(root, 91, 90, "/usr/bin/bash", ["bash", "-i"])
    found = findings(root)
    assert (found[81]["rule_id"], found[81]["evidence"]["service"]["allow_as"]) == (
        "SERVICE_SPAWNED_TOOL", "/usr/bin/node ./server.js")
    assert found[91]["evidence"]["service"]["allow_as"] == "/usr/lib/jvm/java-21/bin/java -jar /opt/app/app.jar"


def test_runtimes_that_are_not_serving_and_their_own_children_stay_quiet(root):  # noqa: F811
    proc(root, 100, 1, "/usr/bin/python3.12", ["python3", "/opt/jobs/backup.py"])       # a script, no socket
    proc(root, 101, 100, "/usr/bin/dash", ["sh", "-c", "tar czf /tmp/b.tgz /srv"])
    proc(root, 110, 1, "/usr/bin/python3.12", ["python3", "/srv/app/serve.py"])
    listening(root, 110, 1100, holds=False)              # a listener in its namespace, held by someone else
    (root / "proc/110/fd/4").symlink_to("socket:[999]")   # its own socket is another one: a client connection
    proc(root, 111, 110, "/usr/bin/dash", ["sh", "-c", "date"])
    proc(root, 120, 1, "/usr/bin/python3.12", ["python3", "/srv/app/serve.py"])
    listening(root, 120, 1200, state="01")               # an established connection, not a listener
    proc(root, 121, 120, "/usr/bin/dash", ["sh", "-c", "date"])
    proc(root, 130, 1, "/usr/bin/python3.12", ["python3", "/srv/api/main.py"])
    listening(root, 130, 1300)
    proc(root, 131, 130, "/usr/bin/python3.12", ["python3", "-c", "from multiprocessing.spawn import spawn_main"])
    found = findings(root)
    assert not {101, 111, 121, 131} & set(found), "not serving, or the runtime starting itself again"


def test_allowing_one_application_does_not_allow_every_one(root, tmp_path):  # noqa: F811
    allow = tmp_path / "allow.json"
    for pid, script in ((140, "/srv/a/manage.py"), (150, "/srv/b/manage.py")):
        proc(root, pid, 1, "/usr/bin/python3.12", ["python3", script, "runserver"])
        listening(root, pid, pid * 10)
        proc(root, pid + 1, pid, "/usr/bin/dash", ["sh", "-c", "git pull"])
    anc.allow(allow, "/usr/bin/python3.12 /srv/a/manage.py", "/usr/bin/dash")
    report = anc.check(str(root), allow_path=allow, now=NOW)
    assert [f["evidence"]["pid"] for f in report["findings"]] == [151]
    anc.allow(allow, "/usr/bin/python3.12", "/usr/bin/dash")
    assert [f["evidence"]["pid"] for f in anc.check(str(root), allow_path=allow, now=NOW)["findings"]] == [151], \
        "the runtime alone names no application"


def test_not_listening_is_remembered_briefly_and_listening_for_good(root):  # noqa: F811
    proc(root, 160, 1, "/usr/bin/node", ["node", "/srv/app.js"])
    clock = [0.0]
    listens = anc.Listeners(root / "proc", clock=lambda: clock[0])
    app = anc.read_proc(root / "proc", 160)
    assert listens(app) is False
    listening(root, 160, 1600)                           # it opens its port after starting
    clock[0] = anc.QUIET_SECONDS - 1
    assert listens(app) is False, "remembered for a while"
    clock[0] = anc.QUIET_SECONDS + 1
    assert listens(app) is True, "then looked at again"
    (root / "proc/160/fd/3").unlink()
    clock[0] += 10 * anc.QUIET_SECONDS
    assert listens(app) is True, "a server stays one"


@linux
def test_a_live_python_server_starting_a_shell_is_caught(tmp_path):
    server = (
        "import socket, subprocess, time\n"
        "s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen()\n"
        "time.sleep(0.6)\n"
        "subprocess.run(['/bin/sh', '-c', 'sleep 0.6; /usr/bin/id >/dev/null; sleep 0.6'])\n")
    found = []
    watcher = anc.Watcher(found.append, interval=0.05)
    stop = threading.Event()
    worker = threading.Thread(target=watcher.run, args=(stop,), kwargs=dict(timeout=0.1), daemon=True)
    worker.start()
    try:
        time.sleep(0.3)
        child = subprocess.Popen([sys.executable, "-c", server])
        child.wait(10)
        time.sleep(0.5)
    finally:
        stop.set()
        worker.join(5)
        watcher.close()
    mine = [f for f in found if f["evidence"]["service"]["pid"] == child.pid]
    assert ("SERVICE_SPAWNED_SHELL", "MEDIUM", "application") in {
        (f["rule_id"], f["severity"], f["evidence"]["service"]["category"]) for f in mine}, watcher.mode


def test_only_runtimes_become_application_services(root):  # noqa: F811
    listening(root, 60, 600)                             # sshd listens too, and a login shell is its job
    assert 61 not in findings(root)


def in_folder(root, pid, folder):
    (root / "proc" / str(pid) / "cwd").symlink_to(folder)


def test_relative_scripts_and_archives_are_named_from_the_application_s_folder(root, tmp_path):  # noqa: F811
    allow = tmp_path / "allow.json"
    for pid, folder in ((170, "/srv/a"), (180, "/srv/b")):
        proc(root, pid, 1, "/usr/bin/node", ["node", "server.js"])
        in_folder(root, pid, folder)
        listening(root, pid, pid * 10)
        proc(root, pid + 1, pid, "/usr/bin/curl", ["curl", "-s", "http://example.test/"])
    proc(root, 190, 1, "/usr/lib/jvm/java-21/bin/java", ["java", "-jar", "build/app.jar"])
    in_folder(root, 190, "/opt/app")
    listening(root, 190, 1900)
    proc(root, 191, 190, "/usr/bin/dash", ["sh", "-c", "id"])
    found = findings(root)
    assert [found[p]["evidence"]["service"]["allow_as"] for p in (171, 181, 191)] == [
        "/usr/bin/node /srv/a/server.js", "/usr/bin/node /srv/b/server.js",
        "/usr/lib/jvm/java-21/bin/java -jar /opt/app/build/app.jar"]
    anc.allow(allow, "/usr/bin/node /srv/a/server.js", "/usr/bin/curl")
    assert [f["evidence"]["pid"] for f in anc.check(str(root), allow_path=allow, now=NOW)["findings"]
            if f["evidence"]["program"] == "/usr/bin/curl"] == [181], "the same script name in another folder"


def test_one_application_s_routine_command_does_not_quiet_another_s(root):  # noqa: F811
    from test_process_ancestry import Events
    for pid, script in ((200, "/srv/a/server.js"), (210, "/srv/b/app.js")):
        proc(root, pid, 1, "/usr/bin/node", ["node", script])
        listening(root, pid, pid * 10)
        proc(root, pid + 1, pid, "/usr/bin/id", ["id"])
    found = []
    watcher = anc.Watcher(found.append, root=root, source=Events([]))
    for pid in (201, 211, 201):
        watcher.handle("exec", pid, 0)
    assert [f["evidence"]["pid"] for f in found] == [201, 211], "the same command in each, once per cooldown"


def test_a_forked_child_is_remembered_with_its_parent_s_folder(root):  # noqa: F811
    from test_process_ancestry import Events
    proc(root, 220, 1, "/usr/bin/python3.12", ["python3", "serve.py"])
    in_folder(root, 220, "/srv/c")
    watcher = anc.Watcher(lambda f: None, root=root, source=Events([]))
    watcher.handle("fork", 221, 220)                     # it runs its parent's program, and is gone before it is read
    assert (watcher.cache[221].argv, watcher.cache[221].cwd) == (["python3", "serve.py"], "/srv/c")
