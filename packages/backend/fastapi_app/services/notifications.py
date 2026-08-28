from __future__ import annotations

import os
from typing import Any

import httpx


async def send_webhook(channel: str, text: str, payload: dict[str, Any] | None = None) -> bool:
    env_name = "SLACK_WEBHOOK_URL" if channel == "slack" else "TEAMS_WEBHOOK_URL"
    url = os.getenv(env_name)
    if not url:
        return False
    body = {"text": text}
    if payload:
        body["aegis"] = payload
    async with httpx.AsyncClient(timeout=8.0) as client:
        response = await client.post(url, json=body)
        response.raise_for_status()
    return True
