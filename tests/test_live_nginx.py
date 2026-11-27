"""Web lures against a real nginx: opt-in, with MEGALODON_TEST_LIVE_NGINX=1, as root on a machine with nginx.

Runs nginx in the foreground on a free loopback port, from a temporary folder, its workers as `nobody`: a web
server running as another user, as one does. Two agent lures are planted in what it serves, one with
`--web-readable` and one without. The test asks it for each note, for a placeholder page and for the readable
lure's page, then reads the access log nginx wrote. nginx is stopped and the folder removed after. Nothing outside
the folder is changed, and nothing is sent off this machine.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import pytest

from megalodon import canary
from megalodon import response_engine as re_
from megalodon import web_review

NGINX = shutil.which("nginx") or "/usr/sbin/nginx"


def _group():
    for name in ("nogroup", "nobody"):
        try:
            return grp.getgrnam(name).gr_name
        except KeyError:
            continue
    return None


def _usable():
    try:
        pwd.getpwnam("nobody")
    except KeyError:
        return False
    return os.path.isfile(NGINX) and hasattr(os, "geteuid") and os.geteuid() == 0 and _group() is not None


pytestmark = pytest.mark.skipif(
    os.environ.get("MEGALODON_TEST_LIVE_NGINX") != "1" or not _usable(),
    reason="explicit live nginx check: needs MEGALODON_TEST_LIVE_NGINX=1, nginx, root and the nobody user")

CONFIG = """daemon off;
master_process on;
worker_processes 1;
user nobody {group};
pid {base}/nginx.pid;
error_log {base}/error.log;
events {{ worker_connections 16; }}
http {{
    access_log {base}/access.log combined;
    client_body_temp_path {base}/temp/body;
    proxy_temp_path {base}/temp/proxy;
    fastcgi_temp_path {base}/temp/fastcgi;
    uwsgi_temp_path {base}/temp/uwsgi;
    scgi_temp_path {base}/temp/scgi;
    server {{
        listen 127.0.0.1:{port};
        root {base}/www;
        location / {{ }}
    }}
}}
"""


def _port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.fixture(scope="module")
def site():
    # A folder the workers can reach: pytest's own temporary folders are the owner's alone.
    base = Path(tempfile.mkdtemp(prefix="megalodon-live-nginx-", dir="/tmp"))
    try:
        # Modes set outright, not left to mkdir and the umask: under umask 077 the workers could reach nothing.
        base.chmod(0o755)
        (base / "www").mkdir()
        (base / "www").chmod(0o755)
        (base / "temp").mkdir(mode=0o700)
        (base / "manifests").mkdir(mode=0o700)
        planted = {}
        for name, readable in (("plain", False), ("readable", True)):
            folder = base / "www" / name
            folder.mkdir()
            folder.chmod(0o755)
            planted[name] = canary.plant(str(folder), str(base / "manifests" / f"{name}.json"), count=1, lure=True,
                                         web_readable=readable)
        port = _port()
        config = base / "nginx.conf"
        config.write_text(CONFIG.format(base=base, port=port, group=_group()))
        server = subprocess.Popen([NGINX, "-c", str(config), "-p", str(base), "-e", str(base / "error.log")],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                pytest.fail("nginx did not start: " + (base / "error.log").read_text(errors="replace")[-500:])
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # loopback, never a proxy

            def get(path):
                try:
                    with opener.open(f"http://127.0.0.1:{port}{path}", timeout=10) as answer:
                        return answer.status, answer.read().decode()
                except urllib.error.HTTPError as refused:
                    return refused.code, ""
            [page] = planted["readable"]["lure_pages"]
            answers = dict(plain=get(f"/plain/{canary.LURE_NAME}"), readable=get(f"/readable/{canary.LURE_NAME}"),
                           placeholder=get("/placeholder"), page=get(f"{page}?check=placeholder"))
        finally:
            server.terminate()
            server.wait(timeout=30)
        yield dict(base=base, planted=planted, page=page, answers=answers, log=base / "access.log",
                   manifest=base / "manifests" / "readable.json")
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_a_web_server_running_as_another_user_serves_only_a_web_readable_lure(site):
    assert site["answers"]["plain"][0] == 403, "the owner's alone: nginx's workers cannot read it"
    status, body = site["answers"]["readable"]
    assert status == 200 and f"path:  {site['page']}" in body, "served, so a browsing agent can read the page"


def test_nginx_writes_lines_web_review_reads(site):
    lines = Path(site["log"]).read_bytes().splitlines(keepends=True)
    assert len(lines) == 4
    report, _ = web_review.review(lines, source=str(site["log"]))
    assert report["input"]["requests"] == 4 and report["input"]["unrecognized_lines"] == 0
    assert report["input"]["invalid_timestamps"] == 0
    start = datetime.fromisoformat(report["window"]["start"])
    assert abs(datetime.now(timezone.utc) - start) < timedelta(minutes=5), "read in UTC, as nginx wrote it"


def test_a_request_for_the_lures_page_in_a_real_access_log_is_lure_followed(site):
    pages = canary.web_lures(str(site["manifest"]))
    report, _ = web_review.review(web_review.read_lines(str(site["log"])), source=str(site["log"]), lure_pages=pages)
    [finding] = report["findings"]
    assert (finding["rule_id"], finding["evidence"]["source"], finding["evidence"]["page"]) == (
        "LURE_FOLLOWED", "127.0.0.1", site["page"])
    assert site["answers"]["page"][0] == 404, "whatever the server answered"


def test_the_response_engine_decides_it_from_the_real_access_log(site, tmp_path):
    policy = tmp_path / "policy.toml"
    re_.write_default_policy(policy)
    text = policy.read_text()
    for name in ("process_review", "rootkit_check"):
        text = text.replace(f"{name} = true", f"{name} = false")
    keep = {"canary_manifest": str(site["manifest"]), "web_log": str(site["log"]), "auth_log": ""}
    lines = []
    for line in text.splitlines():
        name = line.split("=")[0].strip()
        if name in keep:
            line = f"{name} = {json.dumps(keep[name])}"
        elif name.endswith(("_manifest", "_file", "_db")):
            line = f'{name} = ""'
        lines.append(line)
    policy.write_text("\n".join(lines) + "\n")
    ledger = tmp_path / "ledger.jsonl"
    result = re_.run(policy_path=policy, ledger=ledger, state_path=tmp_path / "state.json", protected=set(),
                     now=datetime.now(timezone.utc))
    assert not [gap for gap in result["gaps"] if gap.startswith(("web", "canary"))], result["gaps"]
    [decision] = [json.loads(line) for line in ledger.read_text().splitlines()
                  if json.loads(line)["signal"]["rule_id"] == "LURE_FOLLOWED"]
    assert decision["playbook"] == "lure-followed" and decision["signal"]["source"] == "web"
    assert decision["signal"]["summary"].startswith(f"127.0.0.1 asked this site for {site['page']}, the page "
                                                    f"{canary.LURE_NAME} names")
    blocks = [a for a in decision["actions"] if a["action"] == "block_address"]
    assert [a["status"] for a in blocks] == ["refused"], "a loopback address is never blocked"
