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
"""SSRF guardrails for outbound webhook notifications.

Webhook URLs are user-supplied, so they must be validated before any
outbound HTTP request is issued. The guardrails provided in this module
collectively prevent Server-Side Request Forgery against internal
infrastructure (metadata services, link-local endpoints, loopback, and
RFC 1918 ranges) and limit redirects that would otherwise bypass the
same checks.

The module exposes two entry points:

* :func:`validate_webhook_url` - parses the URL, enforces scheme,
  allowlist, and IP range policy, and returns the validated host and
  the list of resolved IP addresses.
* :func:`pinned_dns` - a context manager that pins DNS resolution for
  the validated host to the pre-validated IP addresses for the duration
  of the outbound request, closing the resolve/connect TOCTOU window
  that DNS rebinding attacks rely on.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from superset.reports.notifications.exceptions import NotificationParamException


@dataclass(frozen=True)
class WebhookURLValidation:
    """Result of a successful webhook URL validation."""

    hostname: str
    scheme: str
    port: int
    resolved: tuple[tuple[int, str], ...] = field(default_factory=tuple)


def _is_disallowed_ip(ip_str: str) -> bool:
    """Return True if the address belongs to a non-routable range.

    Any address that is private, loopback, link-local, multicast,
    reserved, or unspecified is rejected. IPv4-mapped IPv6 addresses
    are normalised before the check so that ``::ffff:127.0.0.1`` is
    treated the same as ``127.0.0.1``.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _hostname_matches_allowlist(hostname: str, allowlist: Iterable[str]) -> bool:
    """Return True when ``hostname`` matches any entry in ``allowlist``.

    Entries may be exact hostnames (``api.example.com``) or a domain
    suffix prefixed with a dot (``.example.com``) which matches the
    domain and any subdomain of it. Empty entries are ignored so that
    operators can leave placeholder values in configuration files.
    """
    host = hostname.lower().rstrip(".")
    for raw_entry in allowlist:
        entry = (raw_entry or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            suffix = entry
            bare = entry.lstrip(".")
            if host == bare or host.endswith(suffix):
                return True
        else:
            if host == entry or host.endswith("." + entry):
                return True
    return False


def _resolve_host(hostname: str) -> list[tuple[int, str]]:
    """Resolve ``hostname`` to a list of ``(address_family, ip)`` tuples.

    Raises :class:`NotificationParamException` when the hostname cannot
    be resolved, so the caller can fail closed without issuing a
    network request.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as ex:
        raise NotificationParamException(
            f"Webhook failed: could not resolve host '{hostname}'"
        ) from ex
    unique: dict[tuple[int, str], None] = {}
    for info in infos:
        family = info[0]
        sockaddr = info[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if isinstance(ip, str) and ip:
            unique.setdefault((int(family), ip), None)
    return list(unique.keys())


def _enforce_scheme(url: str, *, https_only: bool) -> str:
    """Validate the URL shape and return the lowercase scheme."""
    if not url or not isinstance(url, str):
        raise NotificationParamException("Webhook URL is required")
    try:
        parsed = urlparse(url)
    except ValueError as ex:
        raise NotificationParamException("Webhook URL is invalid") from ex
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise NotificationParamException(
            "Webhook URL must use the http or https scheme."
        )
    if https_only and scheme != "https":
        raise NotificationParamException(
            "Webhook failed: HTTPS is required by config for webhook URLs."
        )
    return scheme


def _resolve_target(hostname: str) -> list[tuple[int, str]]:
    """Resolve ``hostname`` as either a literal IP or via DNS."""
    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        return _resolve_host(hostname)
    family = (
        socket.AF_INET6
        if isinstance(literal_ip, ipaddress.IPv6Address)
        else socket.AF_INET
    )
    return [(int(family), str(literal_ip))]


def validate_webhook_url(
    url: str,
    *,
    https_only: bool,
    allow_private_ips: bool,
    host_allowlist: Iterable[str],
) -> WebhookURLValidation:
    """Validate a webhook URL against the configured SSRF guardrails.

    :param url: The target URL supplied by the recipient configuration.
    :param https_only: When True, only ``https://`` URLs are accepted.
    :param allow_private_ips: When True, private / loopback / link-local
        addresses are permitted (intended for test environments only).
    :param host_allowlist: Iterable of hostnames or dot-prefixed domain
        suffixes. When non-empty, the request target must match one of
        the entries. When empty, any public hostname is allowed.
    :raises NotificationParamException: If any policy check fails.
    :returns: A :class:`WebhookURLValidation` with the hostname, scheme,
        port, and the resolved ``(family, ip)`` tuples.
    """
    scheme = _enforce_scheme(url, https_only=https_only)
    parsed = urlparse(url)

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        raise NotificationParamException("Webhook URL is missing a hostname.")

    normalized_allowlist = [entry for entry in host_allowlist if entry]
    if normalized_allowlist and not _hostname_matches_allowlist(
        hostname, normalized_allowlist
    ):
        raise NotificationParamException(
            f"Webhook host '{hostname}' is not in the configured allowlist."
        )

    resolved = _resolve_target(hostname)
    if not resolved:
        raise NotificationParamException(
            f"Webhook failed: could not resolve host '{hostname}'."
        )

    if not allow_private_ips:
        for _family, ip in resolved:
            if _is_disallowed_ip(ip):
                raise NotificationParamException(
                    f"Webhook failed: host '{hostname}' resolves to a "
                    "non-routable or private address."
                )

    port = parsed.port or (443 if scheme == "https" else 80)

    return WebhookURLValidation(
        hostname=hostname,
        scheme=scheme,
        port=port,
        resolved=tuple(resolved),
    )


@contextmanager
def pinned_dns(hostname: str, resolved: Iterable[tuple[int, str]]) -> Iterator[None]:
    """Pin DNS resolution for ``hostname`` to the pre-validated addresses.

    While the context manager is active, ``socket.getaddrinfo`` is
    intercepted so that lookups for the supplied hostname return only
    the IP addresses that were validated by :func:`validate_webhook_url`.
    Lookups for any other hostname fall through to the original
    resolver. This prevents DNS rebinding attacks in the narrow window
    between validation and connection establishment.
    """
    target = hostname.lower().rstrip(".")
    pinned_addresses = list(resolved)
    original = socket.getaddrinfo

    def patched(
        host: Any,
        port: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        host_str: str | None
        if isinstance(host, (bytes, bytearray)):
            host_str = host.decode("ascii", errors="ignore")
        elif isinstance(host, str):
            host_str = host
        else:
            host_str = None

        if host_str and host_str.lower().rstrip(".") == target:
            sock_type = socket.SOCK_STREAM
            if len(args) >= 2 and args[1]:
                sock_type = args[1]
            elif "type" in kwargs and kwargs["type"]:
                sock_type = kwargs["type"]
            port_value: Any = port if port is not None else 0
            results: list[tuple[Any, Any, int, str, tuple[Any, ...]]] = []
            for family, ip in pinned_addresses:
                if family == socket.AF_INET6:
                    sockaddr: tuple[Any, ...] = (ip, port_value, 0, 0)
                else:
                    sockaddr = (ip, port_value)
                results.append((family, sock_type, 0, "", sockaddr))
            if results:
                return results
        return original(host, port, *args, **kwargs)

    socket.getaddrinfo = patched
    try:
        yield
    finally:
        socket.getaddrinfo = original
