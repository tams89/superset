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
"""Regex-based scanner for the event-driven vulnerability rule pack.

The scanner deliberately stays free of heavyweight dependencies (tree-sitter,
semgrep) so the bot can run anywhere Python does. The rule model is still
pattern+negate+window, which covers the detections we need for the audit and
is easy to extend.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    workstream: str
    severity: str
    globs: tuple[str, ...]
    pattern: re.Pattern[str]
    negate_pattern: re.Pattern[str] | None
    remediation: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Rule:
        return cls(
            id=data["id"],
            title=data["title"],
            workstream=data["workstream"],
            severity=data["severity"].lower(),
            globs=tuple(data["globs"]),
            pattern=re.compile(data["pattern"]),
            negate_pattern=(
                re.compile(data["negate_pattern"]) if data.get("negate_pattern") else None
            ),
            remediation=data["remediation"].strip(),
        )


@dataclass(frozen=True)
class Finding:
    id: str
    rule_id: str
    workstream: str
    severity: str
    title: str
    file_path: str
    line: int
    snippet: str
    remediation: str


def load_rules(path: Path) -> list[Rule]:
    """Load every *.yaml rule file under ``path`` and return a flat list."""

    rules: list[Rule] = []
    for rule_file in sorted(path.glob("*.yaml")):
        data = yaml.safe_load(rule_file.read_text())
        for raw in data.get("rules", []):
            rules.append(Rule.from_dict(raw))
    return rules


def _matches_glob(path: str, globs: tuple[str, ...]) -> bool:
    return any(fnmatch(path, g) or path.endswith(g) for g in globs)


def _window(text: str, match_start: int, match_end: int, radius: int = 400) -> str:
    start = max(0, match_start - radius)
    end = min(len(text), match_end + radius)
    return text[start:end]


def _finding_id(rule_id: str, file_path: str, line: int, snippet: str) -> str:
    """Deterministic finding ID so re-scans dedupe cleanly."""

    digest = hashlib.sha256(f"{rule_id}|{file_path}|{line}|{snippet}".encode()).hexdigest()
    return digest[:32]


def scan(repo_path: Path, rules: list[Rule]) -> list[Finding]:
    """Walk the repo, apply every rule, and return the set of findings."""

    findings: list[Finding] = []
    by_file: dict[Path, list[Rule]] = {}
    for rule in rules:
        for target in rule.globs:
            candidate = repo_path / target
            if candidate.is_file():
                by_file.setdefault(candidate, []).append(rule)

    if not by_file:
        for file_path in _walk_repo(repo_path):
            rel = str(file_path.relative_to(repo_path))
            applicable = [r for r in rules if _matches_glob(rel, r.globs)]
            if applicable:
                by_file[file_path] = applicable

    for file_path, file_rules in by_file.items():
        try:
            text = file_path.read_text(errors="ignore")
        except OSError:
            continue
        rel = str(file_path.relative_to(repo_path))
        for rule in file_rules:
            for m in rule.pattern.finditer(text):
                window = _window(text, m.start(), m.end())
                if rule.negate_pattern and rule.negate_pattern.search(window):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                snippet = _extract_line(text, m.start())
                findings.append(
                    Finding(
                        id=_finding_id(rule.id, rel, line, snippet),
                        rule_id=rule.id,
                        workstream=rule.workstream,
                        severity=rule.severity,
                        title=rule.title,
                        file_path=rel,
                        line=line,
                        snippet=snippet,
                        remediation=rule.remediation,
                    )
                )
    return findings


def _walk_repo(repo_path: Path) -> list[Path]:
    skip_dirs = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
    out: list[Path] = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for fname in files:
            p = Path(root) / fname
            if p.suffix in {".py", ".ts", ".tsx", ".js", ".yaml", ".yml"}:
                out.append(p)
    return out


def _extract_line(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:240]
