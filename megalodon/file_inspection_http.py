"""Strict localhost upload envelope; never accepts a path, filename or command."""
import hmac
import os
import time

from .file_inspection import InspectionBusy
from .file_inspection_contract import MAX_INPUT


def action(handler):
    from .dashboard import _tool_management_user
    service = handler.file_inspection
    # Unread body bytes must never become another request on this connection.
    handler.close_connection = True
    headers = handler.headers
    tokens = headers.get_all('X-Megalodon-Config-Token', [])
    if (service is None or handler.support_config is None or not _tool_management_user()
            or headers.get_all('X-Megalodon-Check', []) != ['1']
            or headers.get_all('Origin', []) != [f'http://{headers.get("Host")}']
            or len(tokens) != 1 or len(tokens[0]) != 32 or not tokens[0].isascii()
            or not hmac.compare_digest(tokens[0], handler.support_config.token)
            or headers.get_all('Transfer-Encoding', []) or headers.get_all('Content-Encoding', [])):
        handler._send_json({'error': 'same-origin local file inspection action required'}, status=403)
        return
    cancel = handler.path == '/api/file-inspection/cancel'
    if headers.get_all('Content-Type', []) != ['application/json' if cancel else 'application/octet-stream']:
        handler._send_json({'error': 'unsupported file inspection content type'}, status=400)
        return
    lengths = headers.get_all('Content-Length', [])
    if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
            or len(lengths[0]) > 8 or not 1 <= int(lengths[0]) <= MAX_INPUT):
        handler._send_json({'error': 'choose one executable no larger than 64 MiB'}, status=413)
        return
    size = int(lengths[0])
    if cancel:
        try:
            handler.connection.settimeout(2)
            if size != 2 or handler.rfile.read(2) != b'{}':
                raise ValueError
        except (OSError, ValueError):
            handler._send_json({'error': 'invalid cancellation body'}, status=400)
            return
        service.cancel()
        value = service.snapshot()
        value['token'] = handler.support_config.token
        handler._send_json(value, status=202)
        return
    fd, job, owned = None, None, False
    try:
        job, fd, root = service.reserve(size)
        deadline, remaining = time.monotonic() + 10, size
        handler.connection.settimeout(.5)
        while remaining:
            if service.receiving_cancelled(job):
                raise ValueError
            if time.monotonic() >= deadline:
                raise ValueError
            chunk = handler.rfile.read1(min(65536, remaining))
            if not chunk:
                raise ValueError
            remaining -= len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        owned = service.submit(job, fd, size, root)
    except InspectionBusy:
        handler._send_json({'error': 'an inspection is already in progress'}, status=409)
        return
    except (OSError, ValueError):
        if job is not None:
            service.abort(job)
        handler._send_json({'error': 'file inspection could not receive or admit this file; check inspector and try again'}, status=422)
        return
    finally:
        if fd is not None and not owned:
            os.close(fd)
    value = service.snapshot()
    value['token'] = handler.support_config.token
    handler._send_json(value, status=202)
