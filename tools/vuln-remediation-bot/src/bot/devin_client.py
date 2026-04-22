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
"""Minimal async client for the Devin v1 REST API."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx


class DevinAPIError(RuntimeError):
    """Raised when the Devin API returns a non-retryable error."""


@dataclass
class SessionResponse:
    session_id: str
    status: str
    url: str | None
    raw: dict[str, Any]


class DevinClient:
    """Thin wrapper around the Devin v1 session endpoints.

    Only the two calls we actually need are modelled:
    ``create_session`` and ``get_session``. All other endpoints are accessible
    via :meth:`raw_request` if callers need them.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.devin.ai/v1",
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        if not api_key:
            raise ValueError("api_key is required")
        self._base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=timeout,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "vuln-remediation-bot/0.1",
            },
        )
        self._max_retries = max_retries

    async def aclose(self) -> None:
        await self._client.aclose()

    async def create_session(
        self,
        prompt: str,
        *,
        idempotent: bool = True,
        playbook_id: str | None = None,
        snapshot_id: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> SessionResponse:
        body: dict[str, Any] = {"prompt": prompt, "idempotent": idempotent}
        if playbook_id:
            body["playbook_id"] = playbook_id
        if snapshot_id:
            body["snapshot_id"] = snapshot_id
        if extra:
            body.update(extra)
        data = await self._request("POST", "/sessions", json=body)
        return _parse_session(data)

    async def get_session(self, session_id: str) -> SessionResponse:
        data = await self._request("GET", f"/session/{session_id}")
        return _parse_session(data)

    async def send_message(self, session_id: str, message: str) -> dict[str, Any]:
        return await self._request(
            "POST", f"/session/{session_id}/message", json={"message": message}
        )

    async def raw_request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        return await self._request(method, path, **kwargs)

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        last_exc: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.request(method, url, **kwargs)
            except httpx.HTTPError as exc:
                last_exc = exc
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code == 429 or response.status_code >= 500:
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code >= 400:
                raise DevinAPIError(f"{method} {path} -> {response.status_code}: {response.text}")
            if response.headers.get("content-type", "").startswith("application/json"):
                return response.json()
            return {"raw": response.text}
        raise DevinAPIError(
            f"{method} {path} failed after {self._max_retries} attempts: {last_exc}"
        )


def _parse_session(data: dict[str, Any]) -> SessionResponse:
    session_id = (
        data.get("session_id") or data.get("id") or (data.get("data") or {}).get("session_id", "")
    )
    status = (
        data.get("status")
        or data.get("status_enum")
        or (data.get("data") or {}).get("status", "unknown")
    )
    url = data.get("url") or (data.get("data") or {}).get("url")
    return SessionResponse(session_id=session_id, status=status, url=url, raw=data)
