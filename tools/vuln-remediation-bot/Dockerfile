# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY rules ./rules

RUN pip install --upgrade pip && pip install .

EXPOSE 8099

ENV VULN_BOT_DATABASE_URL="sqlite+aiosqlite:////data/vuln_bot.db" \
    VULN_BOT_RULES_PATH="/app/rules"

VOLUME ["/data"]

CMD ["vuln-bot", "serve", "--host", "0.0.0.0", "--port", "8099"]
