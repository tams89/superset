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
"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Service configuration.

    All values can be overridden via environment variables; see README for the
    full list. Only ``repo_path`` is required for a useful scan, and only
    ``devin_api_key`` is required to dispatch real Devin sessions.
    """

    model_config = SettingsConfigDict(
        env_prefix="VULN_BOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Target repository
    repo_path: Path = Field(
        default=Path("/home/ubuntu/repos/superset"),
        description="Filesystem path to the repo the scanner should inspect.",
    )
    repo_slug: str = Field(
        default="tams89/superset",
        description="GitHub 'owner/name' used when opening issues/PRs.",
    )
    default_base_branch: str = "master"

    # Storage
    database_url: str = "sqlite+aiosqlite:///./vuln_bot.db"

    # Devin API
    devin_api_base: str = "https://api.devin.ai/v1"
    devin_api_key: str | None = Field(default=None, description="Service user token.")
    devin_session_playbook: str | None = None
    dry_run: bool = Field(
        default=True,
        description=(
            "When true, the dispatcher records what it *would* send to the Devin API "
            "without making outbound calls. Useful for demos and local development."
        ),
    )
    max_concurrent_sessions: int = 3

    # GitHub webhook
    github_webhook_secret: str | None = None

    # Scheduler
    scan_interval_seconds: int = 6 * 60 * 60  # 6 hours
    scheduler_enabled: bool = True

    # Scanner rule pack
    rules_path: Path = Field(
        default=Path(__file__).parent.parent.parent / "rules",
        description="Directory containing rule YAML files.",
    )

    # Observability
    log_level: str = "INFO"


def get_settings() -> Settings:
    """Return a fresh Settings instance (tests patch environment per-test)."""

    return Settings()
