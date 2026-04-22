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
"""Turns a batch of findings into Devin sessions.

The dispatcher enforces three invariants:

- **Dedupe**: a ``(workstream, open_status)`` pair gets at most one session.
- **Concurrency cap**: no more than ``max_concurrent_sessions`` in flight.
- **Idempotent writes**: re-running is safe; existing findings are updated
  rather than duplicated.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

import structlog
from sqlalchemy import select, update

from .config import Settings
from .devin_client import DevinAPIError, DevinClient
from .models import DevinSession, Finding
from .prompt_builder import build_prompt
from .scanner import Finding as ScannerFinding
from .storage import Storage

_logger = structlog.get_logger(__name__)

_OPEN_STATUSES = ("pending", "running", "in_progress")


@dataclass
class DispatchResult:
    workstream: str
    finding_count: int
    session_id: int | None
    devin_session_id: str | None
    status: str
    dry_run: bool


class Dispatcher:
    def __init__(
        self,
        storage: Storage,
        settings: Settings,
        devin_client: DevinClient | None = None,
    ) -> None:
        self._storage = storage
        self._settings = settings
        self._client = devin_client

    async def upsert_findings(self, scanner_findings: Iterable[ScannerFinding]) -> int:
        """Persist findings; return the count written/updated."""

        count = 0
        async with self._storage.session() as session:
            for sf in scanner_findings:
                existing = await session.get(Finding, sf.id)
                if existing is None:
                    session.add(
                        Finding(
                            id=sf.id,
                            rule_id=sf.rule_id,
                            workstream=sf.workstream,
                            severity=sf.severity,
                            title=sf.title,
                            file_path=sf.file_path,
                            line=sf.line,
                            snippet=sf.snippet,
                            remediation=sf.remediation,
                        )
                    )
                else:
                    existing.last_seen_at = datetime.now(timezone.utc)
                    if existing.status == "resolved":
                        existing.status = "reopened"
                count += 1
            await session.commit()
        await self._storage.record_event("findings.upserted", "scanner", {"count": count})
        return count

    async def mark_missing_as_resolved(self, present_ids: set[str]) -> int:
        """Flip any open finding that's no longer in the scan to 'resolved'."""

        resolved = 0
        async with self._storage.session() as session:
            stmt = select(Finding).where(Finding.status.in_(("open", "reopened")))
            result = await session.execute(stmt)
            for f in result.scalars():
                if f.id not in present_ids:
                    f.status = "resolved"
                    f.resolved_at = datetime.now(timezone.utc)
                    resolved += 1
            await session.commit()
        if resolved:
            await self._storage.record_event("findings.resolved", "scanner", {"count": resolved})
        return resolved

    async def dispatch_pending(self) -> list[DispatchResult]:
        """Group open findings into workstreams and create Devin sessions."""

        results: list[DispatchResult] = []
        async with self._storage.session() as session:
            open_stmt = select(Finding).where(Finding.status.in_(("open", "reopened")))
            findings_by_ws: dict[str, list[Finding]] = {}
            for f in (await session.execute(open_stmt)).scalars():
                findings_by_ws.setdefault(f.workstream, []).append(f)

            in_flight_stmt = select(DevinSession).where(DevinSession.status.in_(_OPEN_STATUSES))
            in_flight = (await session.execute(in_flight_stmt)).scalars().all()
            in_flight_workstreams = {s.workstream for s in in_flight}

        for workstream, findings in sorted(findings_by_ws.items()):
            if workstream in in_flight_workstreams:
                _logger.info(
                    "dispatch.skip.in_flight",
                    workstream=workstream,
                    finding_count=len(findings),
                )
                continue
            if len(in_flight_workstreams) >= self._settings.max_concurrent_sessions:
                _logger.info(
                    "dispatch.skip.cap",
                    workstream=workstream,
                    cap=self._settings.max_concurrent_sessions,
                )
                break

            result = await self._create_session(workstream, findings)
            results.append(result)
            in_flight_workstreams.add(workstream)

        return results

    async def _create_session(self, workstream: str, findings: list[Finding]) -> DispatchResult:
        scanner_equivalents = [
            ScannerFinding(
                id=f.id,
                rule_id=f.rule_id,
                workstream=f.workstream,
                severity=f.severity,
                title=f.title,
                file_path=f.file_path,
                line=f.line,
                snippet=f.snippet,
                remediation=f.remediation,
            )
            for f in findings
        ]
        prompt = build_prompt(workstream, scanner_equivalents, self._settings.repo_slug)

        dry_run = self._settings.dry_run or self._client is None
        devin_session_id: str | None = None
        status = "pending"
        metadata: dict[str, object] = {"finding_ids": [f.id for f in findings]}

        if dry_run:
            devin_session_id = f"dry-run-{uuid.uuid4().hex[:12]}"
            status = "dry_run"
            metadata["dry_run"] = True
        else:
            assert self._client is not None
            try:
                response = await self._client.create_session(
                    prompt,
                    playbook_id=self._settings.devin_session_playbook,
                )
            except DevinAPIError as exc:
                status = "failed"
                metadata["error"] = str(exc)
                _logger.error(
                    "dispatch.create_session.failed",
                    workstream=workstream,
                    error=str(exc),
                )
            else:
                devin_session_id = response.session_id
                status = response.status or "running"
                metadata["raw"] = response.raw

        finding_ids = [f.id for f in findings]
        async with self._storage.session() as session:
            record = DevinSession(
                finding_id=findings[0].id if len(findings) == 1 else None,
                workstream=workstream,
                devin_session_id=devin_session_id,
                prompt=prompt,
                status=status,
                dry_run=dry_run,
                metadata_json=metadata,
            )
            session.add(record)
            if status != "failed":
                await session.execute(
                    update(Finding)
                    .where(Finding.id.in_(finding_ids))
                    .where(Finding.status.in_(("open", "reopened")))
                    .values(status="dispatched")
                )
            await session.commit()
            session_pk = record.id

        await self._storage.record_event(
            "session.created",
            "dispatcher",
            {
                "workstream": workstream,
                "session_pk": session_pk,
                "devin_session_id": devin_session_id,
                "status": status,
                "dry_run": dry_run,
                "finding_count": len(findings),
            },
        )
        _logger.info(
            "dispatch.session.created",
            workstream=workstream,
            session_pk=session_pk,
            devin_session_id=devin_session_id,
            status=status,
            dry_run=dry_run,
            finding_count=len(findings),
        )
        return DispatchResult(
            workstream=workstream,
            finding_count=len(findings),
            session_id=session_pk,
            devin_session_id=devin_session_id,
            status=status,
            dry_run=dry_run,
        )

    async def refresh_sessions(self) -> int:
        """Poll Devin for status updates on in-flight sessions."""

        if self._client is None:
            return 0
        updated = 0
        async with self._storage.session() as session:
            stmt = select(DevinSession).where(
                DevinSession.status.in_(_OPEN_STATUSES),
                DevinSession.dry_run.is_(False),
                DevinSession.devin_session_id.is_not(None),
            )
            rows = (await session.execute(stmt)).scalars().all()
            for row in rows:
                try:
                    assert row.devin_session_id is not None
                    response = await self._client.get_session(row.devin_session_id)
                except DevinAPIError as exc:
                    _logger.warning(
                        "refresh.failed",
                        session_pk=row.id,
                        error=str(exc),
                    )
                    continue
                if response.status and response.status != row.status:
                    row.status = response.status
                    updated += 1
                if response.url and row.pr_url != response.url:
                    row.pr_url = response.url
                    updated += 1
                if response.status in ("completed", "finished", "succeeded"):
                    row.completed_at = datetime.now(timezone.utc)
            await session.commit()
        if updated:
            await self._storage.record_event(
                "sessions.refreshed", "dispatcher", {"updated": updated}
            )
        return updated
