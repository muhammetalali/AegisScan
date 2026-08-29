from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from typing import Any

from asgiref.sync import sync_to_async
from fastapi import WebSocket

from ..core.config import settings

logger = logging.getLogger(__name__)


@sync_to_async

def _load_session_state(user_id: Any) -> tuple[bool, int] | None:
    """Return the authoritative active/session-version state from Django."""
    from django.contrib.auth import get_user_model

    User = get_user_model()
    user = User.objects.filter(pk=user_id).values("is_active", "session_version").first()
    if not user:
        return None
    return bool(user["is_active"]), int(user["session_version"])


async def monitor_websocket_session(
    websocket: WebSocket,
    *,
    user_id: str,
    session_version: int,
) -> None:
    """Continuously enforce Django session revocation on an established WebSocket.

    JWT verification at handshake time is not sufficient for a long-lived socket:
    Django may revoke the user's session after the socket has already connected.
    This guard re-reads the authoritative session version periodically and closes
    the socket as soon as the version becomes stale or the account is inactive.
    """
    interval = max(1, int(settings.WS_SESSION_CHECK_INTERVAL_SECONDS))

    while True:
        await asyncio.sleep(interval)

        try:
            state = await _load_session_state(user_id)
        except Exception:
            logger.exception("WebSocket session revalidation failed for user %s", user_id)
            with suppress(Exception):
                await websocket.close(code=1011, reason="Authentication state unavailable")
            return

        if state is None:
            logger.warning("Closing WebSocket for deleted user %s", user_id)
            with suppress(Exception):
                await websocket.close(code=4001, reason="Authentication revoked")
            return

        active, current_version = state
        if not active or current_version != int(session_version):
            logger.info(
                "Revoking WebSocket for user %s: active=%s session_version=%s expected=%s",
                user_id,
                active,
                current_version,
                session_version,
            )
            with suppress(Exception):
                await websocket.send_json(
                    {
                        "type": "auth.revoked",
                        "reason": "session_revoked",
                    }
                )
            with suppress(Exception):
                await websocket.close(code=4001, reason="Authentication revoked")
            return


async def start_websocket_session_guard(
    websocket: WebSocket,
    user: dict[str, Any],
) -> asyncio.Task[None]:
    """Start live session-version enforcement for an authenticated socket."""
    return asyncio.create_task(
        monitor_websocket_session(
            websocket,
            user_id=str(user["id"]),
            session_version=int(user.get("session_version", 0)),
        ),
        name=f"ws-session-guard:{user['id']}",
    )


async def stop_websocket_session_guard(task: asyncio.Task[None]) -> None:
    """Stop a session guard when its WebSocket closes for another reason."""
    if task.done():
        with suppress(asyncio.CancelledError, Exception):
            task.result()
        return
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
