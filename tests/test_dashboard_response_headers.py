"""Response headers must be complete before the HUD writes a status line."""

from io import BytesIO
from unittest.mock import Mock

import pytest

from megalodon.dashboard import DashboardHandler


@pytest.mark.parametrize(("content_type", "headers"), (
    ("text/plain\r\nX-Injected: yes", {}),
    ("text/plain", {"X-Report\r\nX-Injected": "value"}),
    ("text/plain", {"X-Report: forged": "value"}),
    ("text/plain", {"X-Report": "value\nX-Injected: yes"}),
    ("text/plain", {"X-Report": "value\rX-Injected: yes"}),
))
def test_dynamic_header_line_breaks_are_rejected_before_response(content_type, headers):
    handler = object.__new__(DashboardHandler)
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = BytesIO()

    with pytest.raises(ValueError, match="HTTP header"):
        handler._send(200, content_type, b"body", extra_headers=headers)

    handler.send_response.assert_not_called()
    handler.send_header.assert_not_called()
    handler.end_headers.assert_not_called()
    assert handler.wfile.getvalue() == b""
