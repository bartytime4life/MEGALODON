"""The optional local region lookup uses synthetic addresses and a fake MMDB reader."""

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
from threading import Thread
from types import SimpleNamespace

import pytest

from megalodon.dashboard import DashboardHandler, UnconfiguredDashboardReader
from megalodon.cli import build_parser
from megalodon.offline_locations import OfflineLocations, validate_lookup_ips


class FakeReader:
    closed = False

    def get(self, address):
        return {
            "8.8.8.8": {"location": {"latitude": 39.2, "longitude": -77.2}, "country": {"iso_code": "US"}},
            "9.9.9.9": {"location": {"latitude": float("nan"), "longitude": 1}},
        }.get(address)

    def close(self):
        self.closed = True


def test_hud_accepts_only_explicit_offline_region_path():
    assert build_parser().parse_args(["hud"]).geoip_db is None
    assert build_parser().parse_args(["hud", "--geoip-db", "/private/regions.mmdb"]).geoip_db == Path("/private/regions.mmdb")


def test_private_database_open_and_coarse_global_lookup(tmp_path, monkeypatch):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "regions.mmdb"
    path.write_bytes(b"synthetic database")
    path.chmod(0o600)
    fake = FakeReader()
    def open_database(descriptor, mode):
        assert os.read(descriptor, 9) == b"synthetic"
        assert mode == "fd"
        return fake
    monkeypatch.setitem(sys.modules, "maxminddb", SimpleNamespace(
        Mode=SimpleNamespace(FD="fd"), open_database=open_database))
    regions = OfflineLocations.open(path)
    answer = regions.lookup(["8.8.8.8", "192.168.1.1", "9.9.9.9"])
    assert answer == {"schema": "dashboard-offline-locations-v1", "status": "available",
                      "source": "offline database", "locations": {
                          "8.8.8.8": {"latitude": 40, "longitude": -75, "label": "Approx. region US"}}}
    regions.close()
    assert fake.closed


@pytest.mark.parametrize("ips", [["8.8.8.8", "8.8.8.8"], ["008.8.8.8"], ["8.8.8.8/32"],
    ["8.8.8.8 "], ["8.8.8.8"] * 21, "8.8.8.8", [1]])
def test_lookup_rejects_unbounded_or_noncanonical_inputs(ips):
    with pytest.raises(ValueError):
        validate_lookup_ips(ips)


def test_private_database_rejects_symlink_or_readable_file(tmp_path, monkeypatch):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "regions.mmdb"
    path.write_bytes(b"synthetic database")
    path.chmod(0o644)
    monkeypatch.setitem(sys.modules, "maxminddb", SimpleNamespace(Mode=SimpleNamespace(FD="fd")))
    with pytest.raises(ValueError):
        OfflineLocations.open(path)
    path.chmod(0o600)
    link = directory / "link.mmdb"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        OfflineLocations.open(link)


def test_http_lookup_is_same_origin_only_and_unconfigured_is_explicit():
    handler = type("OfflineLocationTestHandler", (DashboardHandler,),
                   {"store": UnconfiguredDashboardReader(), "offline_locations": None})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    worker.start()
    body = json.dumps({"ips": ["8.8.8.8"]})
    host = f"127.0.0.1:{server.server_port}"
    def request(headers, payload=body):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("POST", "/api/offline-locations", payload, headers)
        response = connection.getresponse()
        result = response.status, json.loads(response.read()), response.getheader("Cache-Control")
        connection.close()
        return result
    try:
        headers = {"Origin": f"http://{host}", "X-Megalodon-Location": "1", "Content-Type": "application/json"}
        status, value, cache = request(headers)
        assert status == 200 and cache == "no-store"
        assert value == {"schema": "dashboard-offline-locations-v1", "status": "unconfigured", "source": "none", "locations": {}}
        assert request({**headers, "Origin": "http://evil.example"})[0] == 403
        assert request({k: v for k, v in headers.items() if k != "X-Megalodon-Location"})[0] == 403
        assert request(headers, json.dumps({"ips": ["8.8.8.8"], "path": "/etc/passwd"}))[0] == 400
        assert request(headers, '{"ips":[],"ips":[]}')[0] == 400
        assert request(headers, json.dumps({"ips": ["008.8.8.8"]}))[0] == 400
        assert request(headers, "x" * 2049)[0] == 400
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_http_configured_lookup_returns_only_coarse_public_regions():
    handler = type("ConfiguredLocationTestHandler", (DashboardHandler,),
                   {"store": UnconfiguredDashboardReader(), "offline_locations": OfflineLocations(FakeReader())})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    worker.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        connection.request("POST", "/api/offline-locations",
            json.dumps({"ips": ["8.8.8.8", "192.168.1.1"]}),
            {"Origin": f"http://127.0.0.1:{server.server_port}",
             "X-Megalodon-Location": "1", "Content-Type": "application/json"})
        response = connection.getresponse()
        value = json.loads(response.read())
        connection.close()
        assert response.status == 200
        assert value["locations"] == {"8.8.8.8": {"latitude": 40, "longitude": -75,
                                                 "label": "Approx. region US"}}
        assert "192.168.1.1" not in value["locations"]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
