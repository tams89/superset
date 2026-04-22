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

import socket

import pytest

from superset.reports.notifications.exceptions import NotificationParamException
from superset.reports.notifications.webhook_security import (
    _hostname_matches_allowlist,
    _is_disallowed_ip,
    pinned_dns,
    validate_webhook_url,
)


def _fake_getaddrinfo(mapping):
    def _inner(host, port, *args, **kwargs):  # noqa: ARG001
        if host in mapping:
            results = []
            for family, ip in mapping[host]:
                if family == socket.AF_INET6:
                    sockaddr = (ip, port or 0, 0, 0)
                else:
                    sockaddr = (ip, port or 0)
                results.append((family, socket.SOCK_STREAM, 0, "", sockaddr))
            return results
        raise socket.gaierror(-2, "Name or service not known")

    return _inner


def test_is_disallowed_ip_blocks_loopback_and_private():
    assert _is_disallowed_ip("127.0.0.1")
    assert _is_disallowed_ip("10.0.0.1")
    assert _is_disallowed_ip("172.16.0.1")
    assert _is_disallowed_ip("192.168.0.1")
    assert _is_disallowed_ip("169.254.169.254")
    assert _is_disallowed_ip("0.0.0.0")  # noqa: S104
    assert _is_disallowed_ip("::1")
    assert _is_disallowed_ip("fe80::1")
    assert _is_disallowed_ip("ff02::1")
    assert _is_disallowed_ip("::ffff:127.0.0.1")


def test_is_disallowed_ip_allows_public():
    assert not _is_disallowed_ip("8.8.8.8")
    assert not _is_disallowed_ip("1.1.1.1")
    assert not _is_disallowed_ip("2606:4700:4700::1111")


def test_is_disallowed_ip_rejects_garbage():
    assert _is_disallowed_ip("not-an-ip")
    assert _is_disallowed_ip("")


def test_hostname_matches_allowlist_exact_and_suffix():
    assert _hostname_matches_allowlist("api.example.com", ["api.example.com"])
    assert _hostname_matches_allowlist("api.example.com", [".example.com"])
    assert _hostname_matches_allowlist("deep.nested.example.com", [".example.com"])
    assert _hostname_matches_allowlist("example.com", [".example.com"])
    assert _hostname_matches_allowlist("API.EXAMPLE.COM", ["api.example.com"])
    assert _hostname_matches_allowlist("api.example.com", ["example.com"])


def test_hostname_matches_allowlist_rejects_non_matches():
    assert not _hostname_matches_allowlist(
        "evil.com", ["api.example.com", ".example.com"]
    )
    assert not _hostname_matches_allowlist("example.com.evil.com", [".example.com"])
    assert not _hostname_matches_allowlist("notexample.com", [".example.com"])
    assert not _hostname_matches_allowlist("api.example.com", [])
    assert not _hostname_matches_allowlist("api.example.com", ["", "  "])


def test_validate_webhook_url_requires_non_empty():
    with pytest.raises(NotificationParamException, match="Webhook URL is required"):
        validate_webhook_url(
            "", https_only=True, allow_private_ips=False, host_allowlist=[]
        )


def test_validate_webhook_url_rejects_non_http_scheme():
    with pytest.raises(NotificationParamException, match="http or https scheme"):
        validate_webhook_url(
            "ftp://example.com/hook",
            https_only=False,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_rejects_file_scheme():
    with pytest.raises(NotificationParamException, match="http or https scheme"):
        validate_webhook_url(
            "file:///etc/passwd",
            https_only=False,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_requires_https_when_configured(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"example.com": [(socket.AF_INET, "93.184.216.34")]}),
    )
    with pytest.raises(NotificationParamException, match="HTTPS is required"):
        validate_webhook_url(
            "http://example.com/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_missing_hostname():
    with pytest.raises(NotificationParamException, match="missing a hostname"):
        validate_webhook_url(
            "https:///nohost",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_allows_public_host(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"example.com": [(socket.AF_INET, "93.184.216.34")]}),
    )
    result = validate_webhook_url(
        "https://example.com/hook",
        https_only=True,
        allow_private_ips=False,
        host_allowlist=[],
    )
    assert result.hostname == "example.com"
    assert result.scheme == "https"
    assert result.port == 443
    assert result.resolved == ((socket.AF_INET, "93.184.216.34"),)


def test_validate_webhook_url_respects_explicit_port(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"example.com": [(socket.AF_INET, "93.184.216.34")]}),
    )
    result = validate_webhook_url(
        "https://example.com:8443/hook",
        https_only=True,
        allow_private_ips=False,
        host_allowlist=[],
    )
    assert result.port == 8443


def test_validate_webhook_url_blocks_private_resolution(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"internal.local": [(socket.AF_INET, "10.0.0.1")]}),
    )
    with pytest.raises(
        NotificationParamException, match="non-routable or private address"
    ):
        validate_webhook_url(
            "https://internal.local/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_blocks_metadata_ip():
    with pytest.raises(
        NotificationParamException, match="non-routable or private address"
    ):
        validate_webhook_url(
            "https://169.254.169.254/latest/meta-data",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_blocks_loopback_literal():
    with pytest.raises(
        NotificationParamException, match="non-routable or private address"
    ):
        validate_webhook_url(
            "https://127.0.0.1/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_blocks_ipv6_loopback():
    with pytest.raises(
        NotificationParamException, match="non-routable or private address"
    ):
        validate_webhook_url(
            "https://[::1]/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_blocks_when_any_resolved_ip_is_private(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo(
            {
                "mixed.example.com": [
                    (socket.AF_INET, "93.184.216.34"),
                    (socket.AF_INET, "10.0.0.1"),
                ]
            }
        ),
    )
    with pytest.raises(
        NotificationParamException, match="non-routable or private address"
    ):
        validate_webhook_url(
            "https://mixed.example.com/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_resolution_failure(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({}),
    )
    with pytest.raises(NotificationParamException, match="could not resolve host"):
        validate_webhook_url(
            "https://nope.invalid/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=[],
        )


def test_validate_webhook_url_allowlist_rejects_non_match(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"evil.com": [(socket.AF_INET, "93.184.216.34")]}),
    )
    with pytest.raises(
        NotificationParamException, match="not in the configured allowlist"
    ):
        validate_webhook_url(
            "https://evil.com/hook",
            https_only=True,
            allow_private_ips=False,
            host_allowlist=["api.example.com", ".partner.com"],
        )


def test_validate_webhook_url_allowlist_allows_suffix_match(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"api.partner.com": [(socket.AF_INET, "93.184.216.34")]}),
    )
    result = validate_webhook_url(
        "https://api.partner.com/hook",
        https_only=True,
        allow_private_ips=False,
        host_allowlist=[".partner.com"],
    )
    assert result.hostname == "api.partner.com"


def test_validate_webhook_url_allow_private_override(monkeypatch):
    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        _fake_getaddrinfo({"internal.local": [(socket.AF_INET, "10.0.0.1")]}),
    )
    result = validate_webhook_url(
        "https://internal.local/hook",
        https_only=True,
        allow_private_ips=True,
        host_allowlist=[],
    )
    assert result.resolved == ((socket.AF_INET, "10.0.0.1"),)


def test_pinned_dns_returns_only_validated_ips():
    original = socket.getaddrinfo
    try:
        with pinned_dns("pinned.example.com", [(socket.AF_INET, "203.0.113.5")]):
            results = socket.getaddrinfo("pinned.example.com", 443)
            assert results
            ips = {info[4][0] for info in results}
            assert ips == {"203.0.113.5"}
    finally:
        assert socket.getaddrinfo is original


def test_pinned_dns_falls_through_for_other_hosts(monkeypatch):
    call_args = []

    def tracker(host, port, *args, **kwargs):  # noqa: ARG001
        call_args.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", port))]

    monkeypatch.setattr(
        "superset.reports.notifications.webhook_security.socket.getaddrinfo",
        tracker,
    )
    monkeypatch.setattr(socket, "getaddrinfo", tracker)
    with pinned_dns("pinned.example.com", [(socket.AF_INET, "203.0.113.5")]):
        socket.getaddrinfo("other.example.com", 443)
    assert call_args == ["other.example.com"]


def test_pinned_dns_restores_original_resolver():
    original = socket.getaddrinfo
    with pinned_dns("pinned.example.com", [(socket.AF_INET, "203.0.113.5")]):
        assert socket.getaddrinfo is not original
    assert socket.getaddrinfo is original


def test_pinned_dns_restores_on_exception():
    original = socket.getaddrinfo
    with pytest.raises(RuntimeError):
        with pinned_dns("pinned.example.com", [(socket.AF_INET, "203.0.113.5")]):
            raise RuntimeError("boom")
    assert socket.getaddrinfo is original


def test_pinned_dns_handles_bytes_host():
    with pinned_dns("pinned.example.com", [(socket.AF_INET, "203.0.113.5")]):
        results = socket.getaddrinfo(b"pinned.example.com", 443)
        ips = {info[4][0] for info in results}
        assert ips == {"203.0.113.5"}
