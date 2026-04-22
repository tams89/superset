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
"""Aggregate-metric computation for the dashboard and ``/metrics`` endpoint."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select

from .models import DevinSession, Event, Finding
from .storage import Storage


async def compute_metrics(storage: Storage) -> dict[str, Any]:
    async with storage.session() as session:
        findings_by_status = dict(
            (status, count)
            for status, count in (
                await session.execute(select(Finding.status, func.count()).group_by(Finding.status))
            ).all()
        )
        findings_by_severity = dict(
            (severity, count)
            for severity, count in (
                await session.execute(
                    select(Finding.severity, func.count()).group_by(Finding.severity)
                )
            ).all()
        )
        findings_by_workstream = dict(
            (ws, count)
            for ws, count in (
                await session.execute(
                    select(Finding.workstream, func.count()).group_by(Finding.workstream)
                )
            ).all()
        )
        sessions_by_status = dict(
            (status, count)
            for status, count in (
                await session.execute(
                    select(DevinSession.status, func.count()).group_by(DevinSession.status)
                )
            ).all()
        )
        total_findings = sum(findings_by_status.values())
        total_sessions = sum(sessions_by_status.values())
        prs_opened = (
            await session.execute(select(func.count()).where(DevinSession.pr_url.is_not(None)))
        ).scalar() or 0

        recent_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent_events_count = (
            await session.execute(select(func.count()).where(Event.at >= recent_cutoff))
        ).scalar() or 0

        mttr = await _mean_time_to_resolve(session)

    return {
        "totals": {
            "findings": total_findings,
            "sessions": total_sessions,
            "prs_opened": prs_opened,
            "recent_events_7d": recent_events_count,
        },
        "findings_by_status": findings_by_status,
        "findings_by_severity": findings_by_severity,
        "findings_by_workstream": findings_by_workstream,
        "sessions_by_status": sessions_by_status,
        "mean_time_to_resolve_hours": mttr,
    }


async def _mean_time_to_resolve(session: Any) -> float | None:
    stmt = select(Finding).where(Finding.resolved_at.is_not(None))
    deltas: list[float] = []
    for f in (await session.execute(stmt)).scalars():
        if f.resolved_at and f.first_seen_at:
            deltas.append((f.resolved_at - f.first_seen_at).total_seconds() / 3600)
    if not deltas:
        return None
    return round(sum(deltas) / len(deltas), 2)
