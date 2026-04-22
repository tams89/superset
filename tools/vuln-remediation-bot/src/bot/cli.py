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
"""Command-line entry point. Useful for one-shot scans and demos."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .config import Settings, get_settings
from .devin_client import DevinClient
from .dispatcher import Dispatcher
from .logging_setup import configure_logging
from .metrics import compute_metrics
from .scanner import load_rules, scan
from .storage import Storage


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vuln-bot")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan", help="Run the scanner and persist findings.")
    sub.add_parser("dispatch", help="Create Devin sessions for open findings.")
    sub.add_parser("refresh", help="Poll Devin for status updates.")
    sub.add_parser("metrics", help="Print aggregate metrics as JSON.")
    serve = sub.add_parser("serve", help="Run the HTTP service.")
    serve.add_argument("--host", default="0.0.0.0")  # noqa: S104
    serve.add_argument("--port", type=int, default=8099)

    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(settings.log_level)

    if args.command == "serve":
        import uvicorn

        uvicorn.run(
            "bot.main:app",
            host=args.host,
            port=args.port,
            log_level=settings.log_level.lower(),
        )
        return 0

    return asyncio.run(_run_async(args, settings))


async def _run_async(args: argparse.Namespace, settings: Settings) -> int:
    storage = Storage(settings.database_url)
    await storage.init_models()
    client = None
    if args.command in {"dispatch", "refresh"} and not settings.dry_run:
        if not settings.devin_api_key:
            print("VULN_BOT_DEVIN_API_KEY is required when DRY_RUN=false", file=sys.stderr)
            return 2
        client = DevinClient(settings.devin_api_key, settings.devin_api_base)
    dispatcher = Dispatcher(storage, settings, client)

    try:
        if args.command == "scan":
            rules = load_rules(settings.rules_path)
            findings = scan(settings.repo_path, rules)
            count = await dispatcher.upsert_findings(findings)
            resolved = await dispatcher.mark_missing_as_resolved({f.id for f in findings})
            print(json.dumps({"rules": len(rules), "found": count, "resolved": resolved}))
            return 0
        if args.command == "dispatch":
            results = await dispatcher.dispatch_pending()
            print(
                json.dumps(
                    [
                        {
                            "workstream": r.workstream,
                            "finding_count": r.finding_count,
                            "devin_session_id": r.devin_session_id,
                            "status": r.status,
                            "dry_run": r.dry_run,
                        }
                        for r in results
                    ]
                )
            )
            return 0
        if args.command == "refresh":
            updated = await dispatcher.refresh_sessions()
            print(json.dumps({"updated": updated}))
            return 0
        if args.command == "metrics":
            print(json.dumps(await compute_metrics(storage), indent=2))
            return 0
    finally:
        if client is not None:
            await client.aclose()
        await storage.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
