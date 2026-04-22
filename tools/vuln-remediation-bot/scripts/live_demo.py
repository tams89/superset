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
"""One-off live demo: scan the real repo, pick a single workstream, dispatch
one real Devin session, print the session URL."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from bot.config import get_settings
from bot.devin_client import DevinClient
from bot.dispatcher import Dispatcher
from bot.logging_setup import configure_logging
from bot.scanner import load_rules, scan
from bot.storage import Storage


async def main(workstream: str) -> int:
    configure_logging()
    settings = get_settings()
    if settings.dry_run or not settings.devin_api_key:
        print("Refusing: DRY_RUN must be false and DEVIN_API_KEY must be set.", file=sys.stderr)
        return 2

    storage = Storage(settings.database_url)
    await storage.init_models()
    client = DevinClient(settings.devin_api_key, settings.devin_api_base)
    try:
        dispatcher = Dispatcher(storage, settings, client)

        rules = load_rules(settings.rules_path)
        findings = [f for f in scan(settings.repo_path, rules) if f.workstream == workstream]
        if not findings:
            print(f"No open findings for {workstream}", file=sys.stderr)
            return 1

        await dispatcher.upsert_findings(findings)
        results = await dispatcher.dispatch_pending()
        out = [r.__dict__ for r in results]
        print(json.dumps(out, indent=2, default=str))
        return 0 if results else 1
    finally:
        await client.aclose()
        await storage.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workstream", default=os.environ.get("VULN_BOT_WORKSTREAM", "W4"))
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.workstream)))
