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

from pathlib import Path

from bot.scanner import load_rules, scan


def test_load_rules_parses_event_driven_pack(rules_path: Path) -> None:
    rules = load_rules(rules_path)
    rule_ids = {r.id for r in rules}
    assert "async-jwt-missing-exp" in rule_ids
    assert "webhook-ssrf-no-allowlist" in rule_ids
    assert "async-event-api-no-rate-limit" in rule_ids


def test_scan_finds_jwt_without_exp(sample_repo: Path, rules_path: Path) -> None:
    rules = load_rules(rules_path)
    findings = scan(sample_repo, rules)
    by_rule = {f.rule_id for f in findings}
    assert "async-jwt-missing-exp" in by_rule
    assert "webhook-ssrf-no-allowlist" in by_rule
    assert "guest-token-in-celery-payload" in by_rule


def test_scan_respects_negate_pattern(sample_repo: Path, rules_path: Path) -> None:
    fixed = sample_repo / "superset" / "async_events" / "async_query_manager.py"
    fixed.write_text(
        "import jwt\n"
        "def make_token(channel):\n"
        '    return jwt.encode({"channel": channel, "exp": 123}, "s", algorithm="HS256")\n'
    )
    rules = load_rules(rules_path)
    findings = scan(sample_repo, rules)
    by_rule = {f.rule_id for f in findings}
    assert "async-jwt-missing-exp" not in by_rule


def test_finding_id_is_stable(sample_repo: Path, rules_path: Path) -> None:
    rules = load_rules(rules_path)
    first = scan(sample_repo, rules)
    second = scan(sample_repo, rules)
    assert {f.id for f in first} == {f.id for f in second}
