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
from __future__ import annotations

from typing import Any

import httpx
import pytest

from bot.devin_client import DevinAPIError, DevinClient


async def test_create_session_posts_expected_payload() -> None:
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content.decode()
        return httpx.Response(
            201,
            json={"session_id": "devin-123", "status": "running", "url": "https://x"},
        )

    transport = httpx.MockTransport(handler)
    client = DevinClient("cog_test", base_url="https://api.devin.ai/v1")
    client._client = httpx.AsyncClient(
        transport=transport,
        headers={"Authorization": "Bearer cog_test", "Content-Type": "application/json"},
    )

    response = await client.create_session("fix foo", playbook_id="pb-1")
    assert response.session_id == "devin-123"
    assert response.status == "running"
    assert response.url == "https://x"
    assert captured["url"].endswith("/v1/sessions")
    assert "cog_test" in captured["headers"]["authorization"]
    assert "playbook_id" in captured["body"]

    await client.aclose()


async def test_create_session_retries_on_5xx() -> None:
    attempts = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["count"] += 1
        if attempts["count"] < 3:
            return httpx.Response(500, text="boom")
        return httpx.Response(201, json={"session_id": "ok", "status": "running"})

    transport = httpx.MockTransport(handler)
    client = DevinClient("cog_test")
    client._client = httpx.AsyncClient(
        transport=transport,
        headers={"Authorization": "Bearer cog_test"},
    )
    response = await client.create_session("do thing")
    assert response.session_id == "ok"
    assert attempts["count"] == 3
    await client.aclose()


async def test_create_session_raises_on_4xx() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad prompt")

    transport = httpx.MockTransport(handler)
    client = DevinClient("cog_test")
    client._client = httpx.AsyncClient(
        transport=transport,
        headers={"Authorization": "Bearer cog_test"},
    )
    with pytest.raises(DevinAPIError):
        await client.create_session("bad prompt")
    await client.aclose()
