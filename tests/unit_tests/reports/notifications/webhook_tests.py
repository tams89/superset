# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.


from typing import Any

import pandas as pd
import pytest

from superset.reports.notifications.exceptions import (
    NotificationParamException,
)
from superset.reports.notifications.webhook import WebhookNotification
from superset.utils.core import HeaderDataType


@pytest.fixture
def mock_header_data() -> HeaderDataType:
    return {
        "notification_format": "PNG",
        "notification_type": "Alert",
        "owners": [1],
        "notification_source": None,
        "chart_id": None,
        "dashboard_id": None,
        "slack_channels": None,
        "execution_id": "test-execution-id",
    }


def test_get_webhook_url(mock_header_data) -> None:
    """
    Test the _get_webhook_url function to ensure it correctly extracts
    the webhook URL from recipient configuration
    """
    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert",
        header_data=mock_header_data,
        embedded_data=pd.DataFrame({"A": [1, 2, 3], "B": [4, 5, 6]}),
        description="Test description",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://example.com/webhook"}',
        ),
        content=content,
    )

    result = webhook_notification._get_webhook_url()

    assert result == "https://example.com/webhook"


def test_get_webhook_url_missing_url(mock_header_data) -> None:
    """
    Test that _get_webhook_url raises an exception when URL is missing
    """
    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert",
        header_data=mock_header_data,
        description="Test description",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json="{}",
        ),
        content=content,
    )

    with pytest.raises(NotificationParamException, match="Webhook URL is required"):
        webhook_notification._get_webhook_url()


def test_get_req_payload_basic(mock_header_data) -> None:
    """
    Test that _get_req_payload returns correct payload structure
    """
    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="Payload Name",
        header_data=mock_header_data,
        embedded_data=None,
        description="Payload Description",
        url="http://example.com/report",
        text="Report Text",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://webhook.com"}',
        ),
        content=content,
    )

    payload = webhook_notification._get_req_payload()

    assert payload["name"] == "Payload Name"
    assert payload["description"] == "Payload Description"
    assert payload["url"] == "http://example.com/report"
    assert payload["text"] == "Report Text"
    assert isinstance(payload["header"], dict)
    # Optional fields from header_data
    assert payload["header"]["notification_format"] == "PNG"
    assert payload["header"]["notification_type"] == "Alert"


def test_get_files_includes_all_content_types(mock_header_data) -> None:
    """
    Test that _get_files correctly includes csv, pdf, and multiple screenshot attachments
    """  # noqa: E501

    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    csv_bytes = b"col1,col2\n1,2"
    pdf_bytes = b"%PDF-1.4"
    screenshots = [b"fakeimg1", b"fakeimg2"]

    content = NotificationContent(
        name="file test",
        header_data=mock_header_data,
        csv=csv_bytes,
        pdf=pdf_bytes,
        screenshots=screenshots,
        description="files test",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://webhook.com"}',
        ),
        content=content,
    )
    files = webhook_notification._get_files()
    # There should be 1 csv, 1 pdf, and 2 screenshots = 4 files total
    assert len(files) == 4

    file_names = [file_info[1][0] for file_info in files]
    assert "report.csv" in file_names
    assert "report.pdf" in file_names
    assert "screenshot_0.png" in file_names
    assert "screenshot_1.png" in file_names

    mime_types = [file_info[1][2] for file_info in files]
    assert "text/csv" in mime_types
    assert "application/pdf" in mime_types
    assert mime_types.count("image/png") == 2


def test_get_files_empty_when_no_content(mock_header_data) -> None:
    """
    Test that _get_files returns empty list when no files present
    """
    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="no files",
        header_data=mock_header_data,
        description="no files test",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://webhook.com"}',
        ),
        content=content,
    )
    files = webhook_notification._get_files()
    assert files == []


def _install_webhook_mocks(monkeypatch, config_overrides=None) -> None:
    """Install the standard mocks required to exercise ``WebhookNotification.send``."""
    base_config = {
        "ALERT_REPORTS_WEBHOOK_HTTPS_ONLY": True,
        "ALERT_REPORTS_WEBHOOK_HOST_ALLOWLIST": [],
        "ALERT_REPORTS_WEBHOOK_ALLOW_PRIVATE_IPS": False,
    }
    if config_overrides:
        base_config.update(config_overrides)

    class MockCurrentApp:
        config = base_config

    monkeypatch.setattr(
        "superset.reports.notifications.webhook.current_app", MockCurrentApp
    )
    monkeypatch.setattr(
        "superset.reports.notifications.webhook.feature_flag_manager.is_feature_enabled",
        lambda flag: True,
    )


def test_send_http_only_https_check(monkeypatch, mock_header_data) -> None:
    """
    Test send raises when URL is not HTTPS and config enforces HTTPS only
    """
    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert", header_data=mock_header_data, description="Test description"
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "http://notsecure.com/webhook"}',
        ),
        content=content,
    )

    _install_webhook_mocks(monkeypatch)

    with pytest.raises(NotificationParamException, match="HTTPS is required by config"):
        webhook_notification.send()


def test_send_blocks_private_ip_resolution(monkeypatch, mock_header_data) -> None:
    """send() refuses to dispatch when the host resolves to a private address."""
    import socket

    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert", header_data=mock_header_data, description="Test description"
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://internal.local/webhook"}',
        ),
        content=content,
    )

    _install_webhook_mocks(monkeypatch)

    def fake_getaddrinfo(host, port, *args, **kwargs):  # noqa: ARG001
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", port or 0))]

    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(
        NotificationParamException, match="non-routable or private address"
    ):
        webhook_notification.send()


def test_send_blocks_host_not_in_allowlist(monkeypatch, mock_header_data) -> None:
    """send() rejects hosts that are not on the configured allowlist."""
    import socket

    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert", header_data=mock_header_data, description="Test description"
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://evil.com/webhook"}',
        ),
        content=content,
    )

    _install_webhook_mocks(
        monkeypatch,
        {"ALERT_REPORTS_WEBHOOK_HOST_ALLOWLIST": ["api.example.com"]},
    )

    def fake_getaddrinfo(host, port, *args, **kwargs):  # noqa: ARG001
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port or 0))
        ]

    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    with pytest.raises(
        NotificationParamException, match="not in the configured allowlist"
    ):
        webhook_notification.send()


def test_send_disables_redirects_and_uses_pinned_dns(
    monkeypatch, mock_header_data
) -> None:
    """send() must disable redirects and pin DNS while issuing the request."""
    import socket
    from unittest.mock import MagicMock

    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert",
        header_data=mock_header_data,
        description="Test description",
        url="https://example.com/report",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://api.example.com/webhook"}',
        ),
        content=content,
    )

    _install_webhook_mocks(monkeypatch)

    def fake_getaddrinfo(host, port, *args, **kwargs):  # noqa: ARG001
        if host == "api.example.com":
            return [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    ("93.184.216.34", port or 0),
                )
            ]
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    captured_url: list[str] = []
    captured_kwargs: list[dict[str, Any]] = []
    captured_patched: list[bool] = []

    def fake_post(url, **kwargs):
        # Capture the resolver state at the moment of the request so we can
        # confirm that DNS was still pinned when requests.post executed.
        captured_patched.append(
            socket.getaddrinfo is not fake_getaddrinfo
            and socket.getaddrinfo.__module__
            == "superset.reports.notifications.webhook_security"
        )
        captured_url.append(url)
        captured_kwargs.append(kwargs)
        response = MagicMock()
        response.status_code = 200
        response.text = "ok"
        return response

    monkeypatch.setattr(
        "superset.reports.notifications.webhook.requests.post", fake_post
    )

    webhook_notification.send()

    assert captured_url == ["https://api.example.com/webhook"]
    assert captured_kwargs[0]["allow_redirects"] is False
    assert captured_kwargs[0]["timeout"] == 60
    assert captured_patched == [True]


def test_send_disables_redirects_for_file_upload(monkeypatch, mock_header_data) -> None:
    """The multipart upload path must also disable redirects."""
    import socket
    from unittest.mock import MagicMock

    from superset.reports.models import ReportRecipients, ReportRecipientType
    from superset.reports.notifications.base import NotificationContent

    content = NotificationContent(
        name="test alert",
        header_data=mock_header_data,
        description="Test description",
        csv=b"col1,col2\n1,2",
    )
    webhook_notification = WebhookNotification(
        recipient=ReportRecipients(
            type=ReportRecipientType.WEBHOOK,
            recipient_config_json='{"target": "https://api.example.com/webhook"}',
        ),
        content=content,
    )

    _install_webhook_mocks(monkeypatch)

    def fake_getaddrinfo(host, port, *args, **kwargs):  # noqa: ARG001
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port or 0))
        ]

    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        fake_getaddrinfo,
    )

    captured_url: list[str] = []
    captured_kwargs: list[dict[str, Any]] = []

    def fake_post(url, **kwargs):
        captured_url.append(url)
        captured_kwargs.append(kwargs)
        response = MagicMock()
        response.status_code = 200
        response.text = "ok"
        return response

    monkeypatch.setattr(
        "superset.reports.notifications.webhook.requests.post", fake_post
    )

    webhook_notification.send()

    assert captured_kwargs[0]["allow_redirects"] is False
    assert "files" in captured_kwargs[0]
    assert "data" in captured_kwargs[0]
