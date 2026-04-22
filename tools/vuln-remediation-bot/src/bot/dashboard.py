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
"""Renders the HTML dashboard from the current state of the store."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import desc, select

from .config import Settings
from .metrics import compute_metrics
from .models import DevinSession, Event, Finding
from .storage import Storage

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=select_autoescape(("html",)),
    enable_async=False,
)


async def render_dashboard(storage: Storage, settings: Settings) -> str:
    metrics = await compute_metrics(storage)
    async with storage.session() as session:
        findings = (
            (
                await session.execute(
                    select(Finding).order_by(Finding.severity.desc(), Finding.first_seen_at.desc())
                )
            )
            .scalars()
            .all()
        )
        sessions = (
            (
                await session.execute(
                    select(DevinSession).order_by(desc(DevinSession.created_at)).limit(50)
                )
            )
            .scalars()
            .all()
        )
        events = (
            (await session.execute(select(Event).order_by(desc(Event.at)).limit(20)))
            .scalars()
            .all()
        )

    template = _env.get_template("dashboard.html")
    return template.render(
        repo_slug=settings.repo_slug,
        dry_run=settings.dry_run,
        scan_interval=settings.scan_interval_seconds,
        max_concurrent=settings.max_concurrent_sessions,
        metrics=metrics,
        findings=findings,
        sessions=sessions,
        events=events,
    )


async def dashboard_payload(storage: Storage, settings: Settings) -> dict[str, Any]:
    """Machine-readable variant returned by ``/metrics``."""

    metrics = await compute_metrics(storage)
    return {
        "repo_slug": settings.repo_slug,
        "dry_run": settings.dry_run,
        "metrics": metrics,
    }
