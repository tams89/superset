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

import hashlib
import hmac

from bot.github_webhook import mark_pr_merge, verify_signature


def test_verify_signature_happy_path() -> None:
    secret = "s3cr3t"
    body = b'{"hello": "world"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_signature(secret, sig, body) is True


def test_verify_signature_rejects_tampered_body() -> None:
    secret = "s3cr3t"
    body = b'{"hello": "world"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert verify_signature(secret, sig, b"tampered") is False


def test_verify_signature_rejects_missing_header() -> None:
    assert verify_signature("s3cr3t", None, b"") is False


def test_mark_pr_merge_returns_url_on_merged() -> None:
    payload = {
        "action": "closed",
        "pull_request": {
            "merged": True,
            "html_url": "https://github.com/tams89/superset/pull/1",
            "merge_commit_sha": "deadbeef",
        },
    }
    assert mark_pr_merge(payload) == (
        "https://github.com/tams89/superset/pull/1",
        "deadbeef",
    )


def test_mark_pr_merge_ignores_unmerged() -> None:
    payload = {"action": "closed", "pull_request": {"merged": False}}
    assert mark_pr_merge(payload) is None
