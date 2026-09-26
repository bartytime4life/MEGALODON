"""An incomplete loopback request must not grow dashboard threads without bound."""

from __future__ import annotations

from http.client import HTTPConnection
import socket
from threading import Event, Thread, current_thread

from megalodon.dashboard import DashboardHandler, ThreadingHTTPServer


def test_incomplete_requests_are_capped_and_normal_requests_resume() -> None:
    started = Event()
    workers: list[Thread] = []

    class LimitedServer(ThreadingHTTPServer):
        max_connections = 2
        request_timeout_seconds = 2

        def process_request_thread(self, request, client_address) -> None:
            workers.append(current_thread())
            if len(workers) == 2:
                started.set()
            super().process_request_thread(request, client_address)

    server = LimitedServer(("127.0.0.1", 0), DashboardHandler)
    runner = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    runner.start()
    sockets: list[socket.socket] = []
    try:
        for _ in range(2):
            sockets.append(socket.create_connection(server.server_address, timeout=2))
        assert started.wait(1)

        excess = socket.create_connection(server.server_address, timeout=2)
        sockets.append(excess)
        assert excess.recv(1) == b""  # refused before another handler thread starts
        assert len(workers) == 2

        for connection in sockets[:2]:
            connection.close()
        for worker in workers:
            worker.join(timeout=2)
            assert not worker.is_alive()

        client = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            client.request("GET", "/", headers={"Host": f"127.0.0.1:{server.server_port}"})
            response = client.getresponse()
            assert response.status == 200
            assert b"MEGALODON" in response.read()
        finally:
            client.close()
    finally:
        for connection in sockets:
            connection.close()
        server.shutdown()
        server.server_close()
        runner.join(timeout=2)


def test_incomplete_request_times_out_before_headers() -> None:
    class ShortTimeoutServer(ThreadingHTTPServer):
        request_timeout_seconds = 0.2

    server = ShortTimeoutServer(("127.0.0.1", 0), DashboardHandler)
    runner = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    runner.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as connection:
            connection.settimeout(2)
            assert connection.recv(1) == b""
    finally:
        server.shutdown()
        server.server_close()
        runner.join(timeout=2)
