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
"""HTTP smoke tests for the FastAPI app."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from httpx import ASGITransport, AsyncClient

from bot.config import Settings
from bot.main import create_app


@pytest.fixture
async def client(settings: Settings) -> AsyncClient:
    app = create_app(settings)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        async with app.router.lifespan_context(app):
            yield c


async def test_healthz(client: AsyncClient) -> None:
    response = await client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


async def test_scan_then_dashboard_then_metrics(client: AsyncClient) -> None:
    scan = await client.post("/scan")
    assert scan.status_code == 200
    body = scan.json()
    assert body["found"] > 0

    dashboard = await client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Vuln Remediation Bot" in dashboard.text
    assert "Findings" in dashboard.text

    metrics = await client.get("/metrics")
    assert metrics.status_code == 200
    payload = metrics.json()
    assert payload["metrics"]["totals"]["findings"] > 0
    assert "findings_by_severity" in payload["metrics"]


async def test_dispatch_creates_dry_run_sessions(client: AsyncClient) -> None:
    await client.post("/scan")
    response = await client.post("/dispatch")
    assert response.status_code == 200
    data = response.json()
    assert data["dispatched"], "expected at least one dispatched workstream"
    assert all(d["dry_run"] for d in data["dispatched"])


async def test_github_webhook_requires_signature_when_configured(
    settings: Settings,
) -> None:
    app = create_app(Settings(**{**settings.model_dump(), "github_webhook_secret": "s3cr3t"}))
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c,
        app.router.lifespan_context(app),
    ):
        response = await c.post(
            "/webhook/github",
            json={"zen": "be nice"},
            headers={"X-GitHub-Event": "ping"},
        )
        assert response.status_code == 401


async def test_github_webhook_push_triggers_scan(settings: Settings) -> None:
    secret = "s3cr3t"
    app = create_app(Settings(**{**settings.model_dump(), "github_webhook_secret": secret}))
    payload = {"ref": f"refs/heads/{settings.default_base_branch}", "after": "abc"}
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    async with (
        AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c,
        app.router.lifespan_context(app),
    ):
        response = await c.post(
            "/webhook/github",
            content=body,
            headers={
                "X-GitHub-Event": "push",
                "X-Hub-Signature-256": sig,
                "content-type": "application/json",
            },
        )
        assert response.status_code == 200
        body_json = response.json()
        assert body_json["event"] == "push"
        assert body_json["scan"]["found"] > 0
