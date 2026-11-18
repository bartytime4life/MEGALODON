"""Threat-feed refresh: strict parsing, conditional fetches, last-good fallback, output watchlist."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading

import pytest

from megalodon import threat_feeds
from megalodon.config import Settings, load_settings
from megalodon.models import PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.threat_detector import ThreatDetectionSettings
from megalodon.threat_feeds import FeedError, FeedSettings, FeedSource, parse_feed
from megalodon.validation import ValidationError
from megalodon.watchlist import load_watchlist

FEODO = """# Feodo Tracker Botnet C2 IP Blocklist
# Last updated: 2026-11-18
203.0.113.66
198.51.100.7
not-an-ip
"""
DROP = """; Spamhaus DROP List
192.0.2.0/24 ; SBL123456
10.0.0.0/4 ; far too broad, refused
"""
HOSTS = """# URLhaus-style hostfile
127.0.0.1\tlocalhost
0.0.0.0 malware-drop.example
0.0.0.0 c2.bad-domain.test # comment
"""
JA3 = """# ja3_md5,Firstseen,Lastseen,Listingreason
72a589da586844d7f0818ce684948eea,2019-01-01 00:00:00,2026-11-01 00:00:00,Trickbot
not-a-hash,x,y,z
"""


class Server:
    def __init__(self):
        self.bodies, self.requests = {}, []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append((self.path, dict(self.headers)))
                route = owner.bodies.get(self.path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                status, body, headers = route
                if headers.get("ETag") and self.headers.get("If-None-Match") == headers["ETag"]:
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def serve(self, path, body, status=200, **headers):
        self.bodies[path] = (status, body.encode() if isinstance(body, str) else body, headers)
        return self.base + path

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def server():
    value = Server()
    yield value
    value.close()


def settings_for(tmp_path, *sources, **extra):
    return FeedSettings(output=str(tmp_path / "out" / "feeds.watchlist"), state_dir=str(tmp_path / "state"),
                        sources=tuple(sources), **extra)


# ------------------------------------------------------------- parsing

def test_formats_parse_strictly_and_count_unreadable_lines():
    ips, bad = parse_feed(FEODO, "ip")
    assert [str(v.network_address) for v in ips] == ["203.0.113.66", "198.51.100.7"] and bad == 1
    nets, bad = parse_feed(DROP, "ip")
    assert [v.with_prefixlen for v in nets] == ["192.0.2.0/24"] and bad == 1, "a /4 is refused"
    names, bad = parse_feed(HOSTS, "hosts")
    assert names == ["malware-drop.example", "c2.bad-domain.test"] and bad == 0
    prints, bad = parse_feed(JA3, "ja3")
    assert prints == [("ja3", "72a589da586844d7f0818ce684948eea")] and bad == 1
    assert parse_feed("evil.example\ncom\n", "domain") == (["evil.example"], 1)


def test_settings_parse_and_refuse(tmp_path):
    path = tmp_path / "settings.toml"
    path.write_text('[feeds]\nbase = "~/watch.txt"\n[[feeds.source]]\nname = "feodo"\n'
                    'url = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"\n', encoding="utf-8")
    feeds = load_settings(path).feeds
    assert feeds.sources[0].format == "ip" and feeds.base == "~/watch.txt"
    assert Settings().feeds.sources == ()
    for body in ('[[feeds.source]]\nname = "x"\nurl = "http://feeds.example/x"\n',
                 '[[feeds.source]]\nname = "x"\nurl = "https://h/x"\nformat = "stix"\n',
                 '[[feeds.source]]\nname = "x"\nurl = "https://h/x"\nmax_entries = 0\n',
                 '[[feeds.source]]\nname = "x"\nurl = "https://h/x"\nheader_name = "Auth-Key"\n',
                 '[[feeds.source]]\nname = "x"\n',
                 '[feeds]\nmystery = 1\n'):
        path.write_text(body, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_settings(path)


# ------------------------------------------------------------- refresh

def test_refresh_builds_a_labeled_watchlist_after_the_base_list(tmp_path, server):
    base = tmp_path / "mine.txt"
    base.write_text("203.0.113.66  # my own note\n", encoding="utf-8")
    base.chmod(0o600)
    settings = settings_for(
        tmp_path, FeedSource("feodo", server.serve("/feodo", FEODO)),
        FeedSource("urlhaus", server.serve("/hosts", HOSTS), format="hosts"),
        FeedSource("sslbl", server.serve("/ja3", JA3), format="ja3"), base=str(base))
    report = threat_feeds.refresh(settings)
    assert {name: item["status"] for name, item in report["sources"].items()} == {
        "feodo": "updated", "urlhaus": "updated", "sslbl": "updated"}
    assert report["output"]["from_base"] == 1 and report["output"]["from_feeds"] == {
        "feodo": 1, "urlhaus": 2, "sslbl": 1}, "the base list's entry is not repeated"
    output = Path(report["output"]["path"])
    assert oct(output.stat().st_mode & 0o777) == "0o600"
    watch = load_watchlist(output)
    assert watch.match("203.0.113.66") == ("203.0.113.66", "my own note")
    assert watch.match("198.51.100.7") == ("198.51.100.7", "feed:feodo")
    assert watch.match_domain("x.malware-drop.example") == ("malware-drop.example", "feed:urlhaus")
    assert watch.match_fingerprint("ja3", "72a589da586844d7f0818ce684948eea")[1] == "feed:sslbl"
    assert all(item["stale"] is False for item in threat_feeds.status(settings)["sources"].values())


def test_conditional_requests_and_if_older(tmp_path, server):
    url = server.serve("/feodo", FEODO, ETag='"v1"')
    settings = settings_for(tmp_path, FeedSource("feodo", url))
    threat_feeds.refresh(settings)
    second = threat_feeds.refresh(settings)
    assert second["sources"]["feodo"]["status"] == "not_modified" and second["sources"]["feodo"]["indicators"] == 2
    assert server.requests[-1][1].get("If-None-Match") == '"v1"'
    count = len(server.requests)
    assert threat_feeds.refresh(settings, only_if_older_minutes=60)["sources"]["feodo"]["status"] == "skipped_recent"
    assert len(server.requests) == count


@pytest.mark.parametrize("route", ["html", "error", "empty", "binary"])
def test_a_bad_download_keeps_the_last_good_copy(tmp_path, server, route):
    settings = settings_for(tmp_path, FeedSource("feodo", server.serve("/feodo", FEODO)))
    threat_feeds.refresh(settings)
    if route == "html":
        server.serve("/feodo", "<html><body>Service unavailable</body></html>\n<p>try later</p>\n")
    elif route == "error":
        server.serve("/feodo", "down", status=503)
    elif route == "empty":
        server.serve("/feodo", "# nothing today\n")
    else:
        server.serve("/feodo", b"\xff\xfe\x00garbage")
    report = threat_feeds.refresh(settings)
    assert report["sources"]["feodo"]["status"] == "failed" and report["sources"]["feodo"]["indicators"] == 2
    assert load_watchlist(report["output"]["path"]).match("203.0.113.66")


def test_first_failure_and_unreachable_sources_are_reported(tmp_path, server):
    settings = settings_for(tmp_path, FeedSource("gone", server.base + "/missing"),
                            FeedSource("down", "http://127.0.0.1:1/never"))
    report = threat_feeds.refresh(settings)
    assert report["sources"]["gone"]["error"] == "HTTP 404" and report["sources"]["down"]["status"] == "failed"
    assert all(item["stale"] for item in report["sources"].values())
    assert report["output"]["indicators"] == 0


def test_redirects_may_not_downgrade_or_carry_the_token(tmp_path, server):
    token = tmp_path / "key"
    token.write_text("SECRET-KEY\n", encoding="utf-8")
    token.chmod(0o600)
    target = server.serve("/real", FEODO)
    server.serve("/hop", "", status=302, Location=target)
    settings = settings_for(tmp_path, FeedSource("hop", server.base + "/hop", header_name="Auth-Key",
                                                 token_file=str(token)))
    assert threat_feeds.refresh(settings)["sources"]["hop"]["status"] == "updated"
    first, follow = server.requests[-2:]
    assert first[1].get("Auth-Key") == "SECRET-KEY" and "Auth-Key" not in follow[1]
    server.serve("/hop", "", status=302, Location="http://feeds.example/plain")
    report = threat_feeds.refresh(settings_for(tmp_path / "b", FeedSource("hop", server.base + "/hop")))
    assert report["sources"]["hop"]["status"] == "failed"


def test_a_long_run_of_304s_stays_fresh_but_failures_go_stale(tmp_path, server):
    settings = settings_for(tmp_path, FeedSource("feodo", server.serve("/feodo", FEODO, ETag='"v1"')), stale_hours=1)
    threat_feeds.refresh(settings)
    meta_path = tmp_path / "state" / "feodo.json"
    meta = json.loads(meta_path.read_text())
    old = "2026-01-01T00:00:00Z"
    meta_path.write_text(json.dumps(dict(meta, fetched_at=old, validated_at=old)))
    report = threat_feeds.refresh(settings)
    assert report["sources"]["feodo"]["status"] == "not_modified" and report["sources"]["feodo"]["stale"] is False
    assert threat_feeds.status(settings)["sources"]["feodo"]["stale"] is False, "a confirmed-current feed is fresh"
    meta_path.write_text(json.dumps(dict(json.loads(meta_path.read_text()), validated_at=old)))
    server.serve("/feodo", "down", status=500)
    report = threat_feeds.refresh(settings)
    assert report["sources"]["feodo"]["status"] == "failed" and report["sources"]["feodo"]["stale"] is True


def test_a_changed_url_never_reuses_the_old_sources_copy(tmp_path, server):
    first = settings_for(tmp_path, FeedSource("feed", server.serve("/a", "203.0.113.66\n", ETag='"v1"')))
    threat_feeds.refresh(first)
    # Same name, new endpoint that happens to share the ETag.
    second = settings_for(tmp_path, FeedSource("feed", server.serve("/b", "198.51.100.7\n", ETag='"v1"')))
    report = threat_feeds.refresh(second)
    assert report["sources"]["feed"]["status"] == "updated"
    assert "If-None-Match" not in server.requests[-1][1], "validators belong to the old URL"
    watch = load_watchlist(report["output"]["path"])
    assert watch.match("198.51.100.7") and watch.match("203.0.113.66") is None
    # A format change on the same URL also starts over.
    third = settings_for(tmp_path, FeedSource("feed", server.base + "/b", format="ja3"))
    assert threat_feeds.refresh(third)["sources"]["feed"]["status"] == "failed"
    assert threat_feeds.build_output(third)["indicators"] == 0


def test_the_secret_never_reaches_a_redirect_target_whatever_its_header(tmp_path, server):
    token = tmp_path / "key"
    token.write_text("SECRET-KEY\n", encoding="utf-8")
    token.chmod(0o600)
    for reserved in ("User-Agent", "accept", "If-None-Match", "Host"):
        with pytest.raises(FeedError, match="does not set itself"):
            FeedSource("x", server.base + "/x", header_name=reserved, token_file=str(token))
    target = server.serve("/real", FEODO)
    server.serve("/hop", "", status=302, Location=target)
    for name in ("Auth-Key", "X-Custom-Token", "Authorization"):
        settings = settings_for(tmp_path / name, FeedSource("hop", server.base + "/hop", header_name=name,
                                                            token_file=str(token)))
        assert threat_feeds.refresh(settings)["sources"]["hop"]["status"] == "updated"
        first, follow = server.requests[-2:]
        assert first[1].get(name) == "SECRET-KEY"
        assert "SECRET-KEY" not in json.dumps(follow[1]), f"{name} leaked to the redirect target"


def test_size_and_entry_caps(tmp_path, server, monkeypatch):
    many = "\n".join(f"198.51.{i // 250}.{i % 250 + 1}" for i in range(500))
    settings = settings_for(tmp_path, FeedSource("big", server.serve("/many", many), max_entries=100))
    report = threat_feeds.refresh(settings)
    assert report["sources"]["big"]["indicators"] == 100 and report["sources"]["big"]["truncated"] == 400
    monkeypatch.setattr(threat_feeds, "MAX_FEED_BYTES", 1000)
    huge = settings_for(tmp_path / "h", FeedSource("huge", server.serve("/huge", "203.0.113.1\n" * 200)))
    assert "16 MiB" in threat_feeds.refresh(huge)["sources"]["huge"]["error"]


def test_an_unsafe_state_folder_or_base_list_is_refused(tmp_path, server):
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o755)
    settings = settings_for(tmp_path, FeedSource("feodo", server.serve("/feodo", FEODO)))
    with pytest.raises(FeedError, match="private directory"):
        threat_feeds.refresh(settings)
    state.chmod(0o700)
    shared = tmp_path / "shared.txt"
    shared.write_text("203.0.113.9\n", encoding="utf-8")
    shared.chmod(0o666)
    with pytest.raises(ValidationError, match="group- or world-writable"):
        threat_feeds.refresh(settings_for(tmp_path, *settings.sources, base=str(shared)))


# ------------------------------------------------------------- service

def test_refreshed_feed_drives_ioc_match_with_its_label(tmp_path, server):
    settings = settings_for(tmp_path, FeedSource("feodo", server.serve("/feodo", FEODO)))
    output = threat_feeds.refresh(settings)["output"]["path"]
    config = Settings(db_path=tmp_path / "audit.db",
                      threat=ThreatDetectionSettings(watchlist_path=output))
    with Store(config.db_path) as store:
        service = MegalodonService(config, store)
        found = service.process(PacketEvent(datetime.now(timezone.utc) - timedelta(seconds=30), "192.168.1.20",
                                            "203.0.113.66", "TCP", src_port=50000, dst_port=443,
                                            tcp_flags=frozenset({"SYN"})))
    assert [(f.rule_id, f.evidence.get("indicator_label")) for f in found] == [("IOC_MATCH", "feed:feodo")]


def test_cli_refresh_and_status(tmp_path, server, capsys):
    from megalodon.cli import main
    config = tmp_path / "settings.toml"
    config.write_text(f'[feeds]\noutput = "{tmp_path}/o.watchlist"\nstate_dir = "{tmp_path}/s"\n'
                      f'[[feeds.source]]\nname = "feodo"\nurl = "{server.serve("/feodo", FEODO)}"\n',
                      encoding="utf-8")

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("feeds", "status", "--config", str(config)) == 1, "never fetched is stale"
    capsys.readouterr()
    assert code("feeds", "refresh", "--config", str(config)) == 0
    assert json.loads(capsys.readouterr().out)["output"]["indicators"] == 2
    assert code("feeds", "status", "--config", str(config)) == 0
    server.serve("/feodo", "down", status=500)
    assert code("feeds", "refresh", "--config", str(config)) == 1
    assert os.path.exists(tmp_path / "o.watchlist")
