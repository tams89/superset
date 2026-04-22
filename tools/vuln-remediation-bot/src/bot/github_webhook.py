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
"""HMAC verification for GitHub webhook payloads."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any


def verify_signature(secret: str, signature_header: str | None, body: bytes) -> bool:
    """Return True iff ``X-Hub-Signature-256`` matches HMAC-SHA256(secret, body).

    We intentionally avoid throwing on shape errors so callers can return a
    generic 401; leaking "no header" vs "bad sig" would make brute-forcing
    easier.
    """

    if not secret or not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    received = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)


def mark_pr_merge(payload: dict[str, Any]) -> tuple[str, str] | None:
    """Extract ``(pr_url, merge_commit_sha)`` from a ``pull_request.closed`` event.

    Returns None unless the PR was actually merged.
    """

    if payload.get("action") != "closed":
        return None
    pr = payload.get("pull_request") or {}
    if not pr.get("merged"):
        return None
    pr_url = pr.get("html_url")
    merge_commit = pr.get("merge_commit_sha")
    if not pr_url or not merge_commit:
        return None
    return pr_url, merge_commit
