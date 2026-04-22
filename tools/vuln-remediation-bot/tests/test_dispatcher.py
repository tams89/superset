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

import pytest
from sqlalchemy import select

from bot.config import Settings
from bot.devin_client import DevinClient, SessionResponse
from bot.dispatcher import Dispatcher
from bot.models import DevinSession, Finding
from bot.scanner import Finding as ScannerFinding
from bot.scanner import load_rules, scan
from bot.storage import Storage


@pytest.fixture
def sample_findings(sample_repo, rules_path) -> list[ScannerFinding]:
    rules = load_rules(rules_path)
    return scan(sample_repo, rules)


async def test_upsert_findings_is_idempotent(
    storage: Storage, settings: Settings, sample_findings: list[ScannerFinding]
) -> None:
    dispatcher = Dispatcher(storage, settings)
    first = await dispatcher.upsert_findings(sample_findings)
    second = await dispatcher.upsert_findings(sample_findings)
    assert first == second == len(sample_findings)

    async with storage.session() as session:
        count = len((await session.execute(select(Finding))).scalars().all())
    assert count == len(sample_findings)


async def test_dispatch_dry_run_records_session_per_workstream(
    storage: Storage, settings: Settings, sample_findings: list[ScannerFinding]
) -> None:
    dispatcher = Dispatcher(storage, settings)
    await dispatcher.upsert_findings(sample_findings)
    results = await dispatcher.dispatch_pending()
    workstreams = {r.workstream for r in results}
    assert "W1" in workstreams
    assert all(r.dry_run for r in results)
    assert all(r.status == "dry_run" for r in results)

    # Subsequent dispatch is a no-op because sessions are in flight.
    async with storage.session() as session:
        for s in (await session.execute(select(DevinSession))).scalars():
            s.status = "running"
        await session.commit()
    second = await dispatcher.dispatch_pending()
    assert second == []


async def test_mark_missing_resolves_fixed_findings(
    storage: Storage, settings: Settings, sample_findings: list[ScannerFinding]
) -> None:
    dispatcher = Dispatcher(storage, settings)
    await dispatcher.upsert_findings(sample_findings)

    # Simulate: one finding disappears on the next scan.
    still_present = {sample_findings[0].id}
    resolved = await dispatcher.mark_missing_as_resolved(still_present)
    assert resolved == len(sample_findings) - 1

    async with storage.session() as session:
        open_count = (
            (await session.execute(select(Finding).where(Finding.status.in_(("open", "reopened")))))
            .scalars()
            .all()
        )
    assert len(open_count) == 1


async def test_dispatch_with_client_posts_session(
    storage: Storage,
    settings: Settings,
    sample_findings: list[ScannerFinding],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live_settings = replace_settings(settings, dry_run=False)
    calls: list[dict[str, Any]] = []

    class FakeClient(DevinClient):  # pragma: no cover - trivial
        def __init__(self) -> None:  # noqa: D401 - override without super()
            pass

        async def create_session(self, prompt: str, **kwargs: Any) -> SessionResponse:
            calls.append({"prompt": prompt, **kwargs})
            return SessionResponse(
                session_id="devin-abc",
                status="running",
                url="https://app.devin.ai/sessions/abc",
                raw={"session_id": "devin-abc"},
            )

        async def aclose(self) -> None:
            return None

    dispatcher = Dispatcher(storage, live_settings, FakeClient())
    await dispatcher.upsert_findings(sample_findings)
    results = await dispatcher.dispatch_pending()
    assert len(results) >= 1
    assert calls, "FakeClient.create_session was not invoked"
    assert all(r.status == "running" for r in results)
    assert all(not r.dry_run for r in results)


def replace_settings(settings: Settings, **overrides: Any) -> Settings:
    data = settings.model_dump()
    data.update(overrides)
    return Settings(**data)
