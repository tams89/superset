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
"""Builds a structured Devin session prompt for a workstream."""

from __future__ import annotations

from collections.abc import Iterable

from .scanner import Finding

_WORKSTREAM_TITLES: dict[str, str] = {
    "W1": "Async-query JWT hardening",
    "W2": "Event pipeline hardening",
    "W3": "Guest-token lifecycle in Celery",
    "W4": "Alerts/Reports egress SSRF guardrails",
    "W5": "Deserialization cleanup",
    "W6": "Asymmetric JWT migration",
}


def build_prompt(workstream: str, findings: Iterable[Finding], repo_slug: str) -> str:
    """Build a Devin session prompt that groups every finding in a workstream."""

    findings = list(findings)
    title = _WORKSTREAM_TITLES.get(workstream, workstream)
    lines: list[str] = []
    lines.append(f"Remediate workstream {workstream} ({title}) in {repo_slug}.")
    lines.append("")
    lines.append(
        "The vuln-remediation-bot scanned the repository and flagged the findings "
        "below. Open a single PR that fixes all of them using the approach in the "
        "`Remediation` section of each finding. Follow the repo's CLAUDE.md "
        "conventions, run `pre-commit run --all-files` before pushing, and use "
        "the PR template at `.github/PULL_REQUEST_TEMPLATE.md`."
    )
    lines.append("")
    lines.append("### Findings")
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"{index}. **{finding.rule_id}** ({finding.severity.upper()}) — {finding.title}"
        )
        lines.append(f"   - File: `{finding.file_path}:{finding.line}`")
        lines.append(f"   - Snippet: `{finding.snippet}`")
        lines.append("   - Remediation:")
        for rline in finding.remediation.splitlines():
            lines.append(f"     > {rline}")
    lines.append("")
    lines.append("### Deliverables")
    lines.append("- A single feature branch `devin/${timestamp}-" + workstream.lower() + "`.")
    lines.append("- Unit tests covering every new code path.")
    lines.append("- Updated `UPDATING.md` entry if behaviour changes.")
    lines.append("- PR opened against `master` with CI green.")
    lines.append("")
    lines.append("Report back with the PR URL so the remediation bot can track merge status.")
    return "\n".join(lines)
