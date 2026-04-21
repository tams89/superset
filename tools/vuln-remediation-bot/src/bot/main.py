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
"""FastAPI entry point for the vuln-remediation-bot."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

from .config import Settings, get_settings
from .dashboard import dashboard_payload, render_dashboard
from .devin_client import DevinClient
from .dispatcher import Dispatcher
from .github_webhook import mark_pr_merge, verify_signature
from .logging_setup import configure_logging
from .scanner import load_rules, scan
from .storage import Storage

_logger = structlog.get_logger(__name__)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the FastAPI app.

    Exposed as a factory so tests can instantiate with overridden settings.
    """

    settings = settings or get_settings()
    configure_logging(settings.log_level)

    storage = Storage(settings.database_url)
    devin_client: DevinClient | None = None
    if settings.devin_api_key and not settings.dry_run:
        devin_client = DevinClient(settings.devin_api_key, settings.devin_api_base)
    dispatcher = Dispatcher(storage, settings, devin_client)
    scheduler = AsyncIOScheduler(timezone="UTC")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await storage.init_models()
        if settings.scheduler_enabled:
            scheduler.add_job(
                _scheduled_scan,
                "interval",
                seconds=settings.scan_interval_seconds,
                args=(storage, dispatcher, settings),
                id="periodic-scan",
                replace_existing=True,
                next_run_time=None,
            )
            scheduler.start()
            _logger.info(
                "scheduler.started",
                interval_seconds=settings.scan_interval_seconds,
            )
        try:
            yield
        finally:
            if scheduler.running:
                scheduler.shutdown(wait=False)
            if devin_client is not None:
                await devin_client.aclose()
            await storage.close()

    app = FastAPI(title="vuln-remediation-bot", version="0.1.0", lifespan=lifespan)
    app.state.storage = storage
    app.state.dispatcher = dispatcher
    app.state.settings = settings
    app.state.scheduler = scheduler

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics() -> JSONResponse:
        return JSONResponse(await dashboard_payload(storage, settings))

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return HTMLResponse(await render_dashboard(storage, settings))

    @app.post("/scan")
    async def run_scan() -> JSONResponse:
        result = await _run_scan(storage, dispatcher, settings)
        return JSONResponse(result)

    @app.post("/dispatch")
    async def run_dispatch() -> JSONResponse:
        dispatches = await dispatcher.dispatch_pending()
        return JSONResponse(
            {
                "dispatched": [
                    {
                        "workstream": d.workstream,
                        "finding_count": d.finding_count,
                        "session_id": d.session_id,
                        "devin_session_id": d.devin_session_id,
                        "status": d.status,
                        "dry_run": d.dry_run,
                    }
                    for d in dispatches
                ]
            }
        )

    @app.post("/refresh")
    async def run_refresh() -> JSONResponse:
        updated = await dispatcher.refresh_sessions()
        return JSONResponse({"updated": updated})

    @app.post("/webhook/github")
    async def github_webhook(request: Request) -> Response:
        body = await request.body()
        event = request.headers.get("X-GitHub-Event", "")
        signature = request.headers.get("X-Hub-Signature-256")
        if settings.github_webhook_secret and not verify_signature(
            settings.github_webhook_secret, signature, body
        ):
            raise HTTPException(status_code=401, detail="invalid signature")

        payload = await request.json()
        await storage.record_event(
            "github.webhook",
            "github",
            {"event": event, "action": payload.get("action")},
        )

        if event == "push" and payload.get("ref") == f"refs/heads/{settings.default_base_branch}":
            result = await _run_scan(storage, dispatcher, settings)
            dispatch = await dispatcher.dispatch_pending()
            return JSONResponse(
                {
                    "event": event,
                    "scan": result,
                    "dispatched": len(dispatch),
                }
            )

        if event == "pull_request":
            merge = mark_pr_merge(payload)
            if merge:
                await storage.record_event(
                    "pr.merged", "github", {"pr_url": merge[0], "sha": merge[1]}
                )

        return JSONResponse({"event": event, "accepted": True})

    return app


async def _run_scan(storage: Storage, dispatcher: Dispatcher, settings: Settings) -> dict[str, int]:
    rules = load_rules(settings.rules_path)
    findings = scan(settings.repo_path, rules)
    await dispatcher.upsert_findings(findings)
    resolved = await dispatcher.mark_missing_as_resolved({f.id for f in findings})
    await storage.record_event(
        "scan.completed",
        "scanner",
        {"found": len(findings), "resolved": resolved, "rules": len(rules)},
    )
    return {"found": len(findings), "resolved": resolved, "rules": len(rules)}


async def _scheduled_scan(storage: Storage, dispatcher: Dispatcher, settings: Settings) -> None:
    try:
        await _run_scan(storage, dispatcher, settings)
        await dispatcher.dispatch_pending()
        await dispatcher.refresh_sessions()
    except Exception as exc:  # noqa: BLE001 - structured logging for any failure
        _logger.error("scheduled_scan.failed", error=str(exc))


app = create_app()
