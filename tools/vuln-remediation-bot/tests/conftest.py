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

import os
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest

from bot.config import Settings
from bot.storage import Storage


@pytest.fixture
def rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


@pytest.fixture
def sample_repo(tmp_path: Path) -> Path:
    """A fake repo tree that mirrors the paths the rule pack cares about."""

    (tmp_path / "superset" / "async_events").mkdir(parents=True)
    (tmp_path / "superset" / "async_events" / "async_query_manager.py").write_text(
        "import jwt\n"
        "def make_token(channel):\n"
        '    return jwt.encode({"channel": channel}, "secret", algorithm="HS256")\n'
        "def increment_id(id):\n"
        "    return id[:-1] + chr(ord(id[-1]) + 1)\n"
    )
    (tmp_path / "superset" / "async_events" / "api.py").write_text(
        "class AsyncEventsRestApi:\n    pass\n"
    )
    (tmp_path / "superset-websocket" / "src").mkdir(parents=True)
    (tmp_path / "superset-websocket" / "src" / "index.ts").write_text(
        "function read() {\n  jwt.verify(token, secret);\n  xrange(stream, from, to);\n"
        "  processStreamResults(data);\n}\n"
    )
    (tmp_path / "superset" / "reports" / "notifications").mkdir(parents=True)
    (tmp_path / "superset" / "reports" / "notifications" / "webhook.py").write_text(
        "import requests\ndef notify(url, body):\n    return requests.post(url, json=body)\n"
    )
    (tmp_path / "superset" / "tasks").mkdir(parents=True)
    (tmp_path / "superset" / "tasks" / "async_queries.py").write_text(
        'def run(ctx):\n    token = ctx["guest_token"]\n    return token\n'
    )
    (tmp_path / "superset" / "config.py").write_text('JWT_ALGORITHM = "HS256"\n')
    (tmp_path / "superset" / "extensions").mkdir(parents=True)
    (tmp_path / "superset" / "extensions" / "metastore_cache.py").write_text("import pickle\n")
    return tmp_path


@pytest.fixture
def settings(tmp_path: Path, rules_path: Path, sample_repo: Path) -> Settings:
    os.environ.pop("VULN_BOT_DEVIN_API_KEY", None)
    return Settings(
        repo_path=sample_repo,
        repo_slug="tams89/superset",
        database_url=f"sqlite+aiosqlite:///{tmp_path}/vuln_bot.db",
        rules_path=rules_path,
        dry_run=True,
        scheduler_enabled=False,
        devin_api_key=None,
    )


@pytest.fixture
async def storage(settings: Settings) -> AsyncGenerator[Storage, None]:
    store = Storage(settings.database_url)
    await store.init_models()
    try:
        yield store
    finally:
        await store.close()
