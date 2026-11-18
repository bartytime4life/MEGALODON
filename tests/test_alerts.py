"""Off-machine alerts: settings, secret files, payloads, delivery and service wiring."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import threading
import time

import pytest

from megalodon import alerts
from megalodon.alerts import (AlertConfigError, AlertDestination, AlertDispatcher, AlertSettings, Channel,
                              check_url, parse_settings, read_secret, record, syslog_message, webhook_request)
from megalodon.config import Settings, load_settings
from megalodon.models import DetectionResult, PacketEvent
from megalodon.service import MegalodonService
from megalodon.storage import Store
from megalodon.validation import ValidationError

LAN = "192.168.7.10"


def finding(severity="HIGH", rule="BRUTE_FORCE", message="15 connection attempts to port 22 from 203.0.113.9"):
    return DetectionResult(datetime(2026, 11, 18, 2, 0, tzinfo=timezone.utc), rule, severity, "203.0.113.9", LAN,
                           message)


def secret(tmp_path, name, value, mode=0o600):
    path = tmp_path / name
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(mode)
    return str(path)


class Receiver:
    """A real local HTTP endpoint recording each POST."""

    def __init__(self, status=200):
        self.requests, received = [], self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.requests.append((self.path, dict(self.headers), body))
                self.send_response(received.status)
                if received.status in (301, 302):
                    self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                self.end_headers()

            def log_message(self, *args):
                pass
        self.status = status
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook/secret-token"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    value = Receiver()
    yield value
    value.close()


def webhook(tmp_path, url, fmt="json", **extra):
    return AlertDestination(name=fmt, kind="webhook", format=fmt, url_file=secret(tmp_path, f"{fmt}.url", url), **extra)


# ------------------------------------------------------------------ settings

def test_settings_parse_destinations_and_refuse_unknown_or_unsafe(tmp_path):
    path = tmp_path / "settings.toml"
    path.write_text('[alerts]\nenabled = true\nmin_severity = "medium"\n'
                    '[[alerts.destination]]\nname = "phone"\nkind = "webhook"\nformat = "ntfy"\nurl_file = "~/n.url"\n'
                    '[[alerts.destination]]\nname = "siem"\nkind = "syslog"\nhost = "10.0.0.5"\nport = 6514\n'
                    'protocol = "tcp"\n', encoding="utf-8")
    settings = load_settings(path).alerts
    assert settings.enabled and settings.min_severity == "MEDIUM" and settings.detail == "standard"
    assert [(d.name, d.kind) for d in settings.destinations] == [("phone", "webhook"), ("siem", "syslog")]
    assert Settings().alerts == AlertSettings() and not AlertSettings().enabled
    for body in ('[alerts]\nenabled = true\n',
                 '[alerts]\nmystery = 1\n',
                 '[alerts]\ndetail = "everything"\n',
                 '[[alerts.destination]]\nname = "x"\nkind = "email"\n',
                 '[[alerts.destination]]\nname = "x"\nkind = "webhook"\n',
                 '[[alerts.destination]]\nname = "x"\nkind = "webhook"\nurl = "https://h"\nurl_file = "f"\n',
                 '[[alerts.destination]]\nname = "x"\nkind = "syslog"\nhost = "bad host"\n',
                 '[[alerts.destination]]\nname = "x"\nkind = "syslog"\nhost = "h"\nport = "514"\n',
                 '[[alerts.destination]]\nname = "x"\nkind = "syslog"\nhost = "h"\n'
                 '[[alerts.destination]]\nname = "x"\nkind = "syslog"\nhost = "h"\n'):
        path.write_text(body, encoding="utf-8")
        with pytest.raises(ValidationError):
            load_settings(path)


def test_secret_files_must_be_private_single_lines(tmp_path):
    assert read_secret(secret(tmp_path, "ok", "https://ntfy.sh/topic")) == "https://ntfy.sh/topic"
    for path in (secret(tmp_path, "shared", "https://x", 0o644), secret(tmp_path, "two", "a\nb"),
                 secret(tmp_path, "space", "https://x y"), str(tmp_path / "absent")):
        with pytest.raises(AlertConfigError):
            read_secret(path)
    os.mkfifo(tmp_path / "fifo", 0o600)
    started = time.monotonic()
    with pytest.raises(AlertConfigError):
        read_secret(str(tmp_path / "fifo"))
    assert time.monotonic() - started < 2
    (tmp_path / "link").symlink_to(tmp_path / "ok")
    with pytest.raises(AlertConfigError):
        read_secret(str(tmp_path / "link"))


def test_urls_need_https_except_to_private_literal_addresses():
    assert check_url("https://hooks.slack.com/services/x", "s")
    assert check_url("http://192.168.1.5:8080/topic", "s") and check_url("http://127.0.0.1/x", "s")
    for url in ("http://ntfy.sh/topic", "http://example.lan/x", "ftp://h/x", "https://user:pw@h/x",
                "http://169.254.1.1/x", "https:///nohost"):
        with pytest.raises(AlertConfigError):
            check_url(url, "s")


# ------------------------------------------------------------------ payloads

def test_detail_levels_control_what_leaves_the_machine():
    minimal = record(finding(), "minimal", "sensor-1")
    assert "src_ip" not in minimal and "message" not in minimal
    assert minimal["rule_id"] == "BRUTE_FORCE" and minimal["attack"] == ["T1110"]
    standard = record(finding(), "standard", "sensor-1")
    assert standard["src_ip"] == "203.0.113.9" and "message" not in standard
    assert record(finding(), "full", "sensor-1")["message"].startswith("15 connection")


def test_formats_neutralize_markup_and_mentions():
    value = record(finding(message="<!channel> @everyone hi"), "full", "s")
    dest = lambda fmt: AlertDestination(name=fmt, kind="webhook", format=fmt, url_file="unused")  # noqa: E731
    body, headers = webhook_request(dest("slack"), "u", None, value)
    assert "<!channel>" not in json.loads(body)["text"] and "&lt;!channel&gt;" in json.loads(body)["text"]
    body, _ = webhook_request(dest("discord"), "u", None, value)
    assert json.loads(body)["allowed_mentions"] == {"parse": []}
    body, headers = webhook_request(dest("ntfy"), "u", "tok", value)
    assert headers["Title"] == "MEGALODON HIGH BRUTE_FORCE" and headers["Priority"] == "4"
    assert headers["Authorization"] == "Bearer tok" and body.decode().startswith("MEGALODON HIGH")
    body, headers = webhook_request(dest("json"), "u", None, value)
    assert json.loads(body)["schema"] == "megalodon-alert-v1"


def test_syslog_is_rfc5424_with_escaped_structured_data():
    dest = AlertDestination(name="siem", kind="syslog", host="10.0.0.5", facility="local3")
    value = record(finding(), "standard", "sensor-1", suppressed=2)
    message = syslog_message(dest, value, now=datetime(2026, 11, 18, tzinfo=timezone.utc)).decode()
    assert message.startswith("<155>1 2026-11-18T00:00:00Z sensor-1 megalodon - BRUTE_FORCE [megalodon@32473 ")
    assert 'rule="BRUTE_FORCE"' in message and 'src_ip="203.0.113.9"' in message and 'suppressed="2"' in message
    assert alerts.SYSLOG_PRIORITY["CRITICAL"] < alerts.SYSLOG_PRIORITY["LOW"]


# ------------------------------------------------------------------ delivery

def test_webhook_delivery_to_a_real_endpoint(tmp_path, receiver):
    settings = AlertSettings(enabled=True, destinations=(webhook(tmp_path, receiver.url, token_file=secret(
        tmp_path, "tok", "s3cret")),))
    dispatcher = AlertDispatcher(settings)
    dispatcher.submit([finding("LOW"), finding("MEDIUM"), finding("HIGH"), finding("CRITICAL", "IOC_MATCH")])
    dispatcher.close(timeout=10)
    assert [json.loads(body)["severity"] for _, _, body in receiver.requests] == ["HIGH", "CRITICAL"]
    path, headers, _ = receiver.requests[0]
    assert path == "/hook/secret-token" and headers["Authorization"] == "Bearer s3cret"
    assert dispatcher.snapshot()["json"]["sent"] == 2


def test_redirects_and_errors_are_failures_without_echoing_the_url(tmp_path, caplog):
    for status in (302, 500):
        target = Receiver(status)
        try:
            channel = Channel(webhook(tmp_path, target.url), AlertSettings(), sleep=lambda _s: None)
            assert channel.deliver(finding()) is False
            assert len(target.requests) == len(alerts.RETRY_DELAYS)
            assert channel.stats["failed"] == 1 and channel.stats["last_error"] == "HTTPError"
        finally:
            target.close()
    assert "secret-token" not in caplog.text


def test_rate_limit_and_queue_bound_are_counted_and_reported_on_the_next_alert(tmp_path):
    sent, now = [], [0.0]
    settings = AlertSettings(max_per_minute=2)
    channel = Channel(webhook(tmp_path, "https://example.test/h"), settings, transport=sent.append,
                      clock=lambda: now[0])
    for _ in range(5):
        channel.offer(finding())
    channel.closed = True  # With no thread started, _run drains the queue and returns.
    channel._run()
    assert len(sent) == 2 and channel.stats["rate_limited"] == 3
    now[0] = 60.0
    channel.deliver(finding())
    assert sent[-1]["suppressed_before"] == 3 and channel.suppressed == 0
    channel.closed = False
    channel.queue.extend([finding()] * alerts.MAX_QUEUE)
    channel.offer(finding())
    assert channel.stats["dropped"] == 1 and channel.suppressed == 1


def test_drops_during_an_in_flight_delivery_are_reported_on_the_next_alert(tmp_path):
    sent = []
    channel = Channel(webhook(tmp_path, "https://example.test/h"), AlertSettings(), transport=sent.append)
    channel.suppressed = 2

    def slow(value):
        # While this alert is in flight, the capture thread drops three more.
        for _ in range(3):
            channel.queue.extend([finding()] * (alerts.MAX_QUEUE - len(channel.queue)))
            channel.offer(finding())
        sent.append(value)
    channel.transport = slow
    assert channel.deliver(finding())
    assert sent[-1]["suppressed_before"] == 2 and channel.suppressed == 3
    channel.transport = sent.append
    channel.queue.clear()
    channel.deliver(finding())
    assert sent[-1]["suppressed_before"] == 3 and channel.suppressed == 0


def test_one_failing_destination_does_not_hold_back_another(tmp_path, receiver):
    stuck = threading.Event()

    def hang(_value):
        stuck.wait(5)
        raise OSError("down")
    settings = AlertSettings(enabled=True, destinations=(
        AlertDestination(name="siem", kind="syslog", host="127.0.0.1"), webhook(tmp_path, receiver.url)))
    dispatcher = AlertDispatcher(settings, start=False)
    dispatcher.channels[0].transport = hang
    for channel in dispatcher.channels:
        channel.start()
    dispatcher.submit([finding()])
    deadline = time.monotonic() + 5
    while not receiver.requests:
        assert time.monotonic() < deadline
        time.sleep(.01)
    stuck.set()
    dispatcher.close(timeout=1)


def test_syslog_udp_and_tcp_reach_real_listeners():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(5)
        tcp.bind(("127.0.0.1", 0))
        tcp.listen(1)
        tcp.settimeout(5)
        for protocol, port in (("udp", udp.getsockname()[1]), ("tcp", tcp.getsockname()[1])):
            dest = AlertDestination(name=protocol, kind="syslog", host="127.0.0.1", port=port, protocol=protocol)
            assert Channel(dest, AlertSettings(), sleep=lambda _s: None).deliver(finding())
        data, _ = udp.recvfrom(4096)
        assert data.startswith(b"<131>1 ") and b"BRUTE_FORCE" in data
        connection, _ = tcp.accept()
        with connection:
            framed = connection.recv(4096)
        length, _, message = framed.partition(b" ")
        assert int(length) == len(message) and message.startswith(b"<131>1 ")


def test_alerts_test_reports_each_destination(tmp_path, receiver):
    settings = AlertSettings(destinations=(webhook(tmp_path, receiver.url),
                                           AlertDestination(name="bad", kind="webhook", url_file=str(tmp_path / "x"))))
    result = alerts.test_destinations(settings)
    assert result["json"] == dict(ok=True, error=None) and result["bad"]["ok"] is False
    assert json.loads(receiver.requests[0][2])["rule_id"] == "IOC_MATCH"


# ------------------------------------------------------------------ service wiring

def brute(start):
    return [PacketEvent(start + timedelta(seconds=i), "203.0.113.9", LAN, "TCP", src_port=50000 + i, dst_port=22,
                        tcp_flags=frozenset({"SYN"}), byte_count=60) for i in range(15)]


def test_service_forwards_only_committed_findings(tmp_path, monkeypatch):
    sent = []
    settings_alerts = AlertSettings(enabled=True, min_severity="MEDIUM",
                                    destinations=(AlertDestination(name="siem", kind="syslog", host="127.0.0.1"),))
    monkeypatch.setattr(alerts, "_shared", {})
    real = AlertDispatcher

    def capture(settings):
        dispatcher = real(settings, transport=sent.append)
        alerts._shared[settings] = dispatcher
        return dispatcher
    monkeypatch.setattr("megalodon.service.dispatcher_for", capture)
    settings = Settings(db_path=tmp_path / "audit.db", alerts=settings_alerts)
    events = brute(datetime.now(timezone.utc) - timedelta(seconds=120))
    with Store(settings.db_path) as store:
        service = MegalodonService(settings, store)
        for event in events[:-1]:
            service.process(event)
        original = store.record_event_bundle
        store.record_event_bundle = lambda *a, **k: (_ for _ in ()).throw(OSError("disk"))
        with pytest.raises(OSError):
            service.process(events[-1])
        store.record_event_bundle = original
        service.alerts.close(timeout=2)
        assert sent == [], "a finding whose save failed is never forwarded"
        service.alerts = capture(settings_alerts)
        service.process(events[-1])
        service.alerts.close(timeout=5)
    assert [item["rule_id"] for item in sent] == ["BRUTE_FORCE"]


def test_unreadable_secret_refuses_startup(tmp_path, monkeypatch):
    monkeypatch.setattr(alerts, "_shared", {})
    settings = Settings(db_path=tmp_path / "audit.db", alerts=AlertSettings(enabled=True, destinations=(
        AlertDestination(name="hook", kind="webhook", url_file=str(tmp_path / "absent")),)))
    with Store(settings.db_path) as store, pytest.raises(ValidationError, match="cannot be opened"):
        MegalodonService(settings, store)


def test_buffered_recording_forwards_after_the_batch_is_durable(tmp_path, monkeypatch):
    from megalodon.buffered_recording import BufferedRecording
    sent = []
    monkeypatch.setattr("megalodon.service.dispatcher_for",
                        lambda s: AlertDispatcher(s, transport=sent.append) if s.enabled else None)
    settings = Settings(db_path=tmp_path / "audit.db", alerts=AlertSettings(enabled=True, destinations=(
        AlertDestination(name="siem", kind="syslog", host="127.0.0.1"),)))
    with Store(settings.db_path) as store:
        recording = BufferedRecording(settings, store, run_id=store.start_ingestion_run("jsonl"))
        for event in brute(datetime.now(timezone.utc) - timedelta(seconds=120)):
            recording.process(event)
        recording.flush()
        recording.service.alerts.close(timeout=5)
    assert [item["rule_id"] for item in sent] == ["BRUTE_FORCE"]


def test_cli_alerts_test(tmp_path, receiver, capsys):
    from megalodon.cli import main
    config = tmp_path / "settings.toml"
    config.write_text(f'[[alerts.destination]]\nname = "hook"\nkind = "webhook"\n'
                      f'url_file = "{secret(tmp_path, "u", receiver.url)}"\n', encoding="utf-8")

    def code(*argv):
        with pytest.raises(SystemExit) as exit_:
            main(list(argv))
        return exit_.value.code
    assert code("alerts", "test", "--config", str(config)) == 0
    assert json.loads(capsys.readouterr().out)["destinations"]["hook"]["ok"] is True
    Path(config).write_text("[alerts]\n", encoding="utf-8")
    assert code("alerts", "test", "--config", str(config)) == 2
