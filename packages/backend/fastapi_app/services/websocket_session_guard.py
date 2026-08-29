from __future__ import annotations

import logging
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
        await __import__("asyncio").sleep(interval)

        try:
            state = await _load_session_state(user_id)
        except Exception:
            logger.exception("WebSocket session revalidation failed for user %s", user_id)
            try:
                await websocket.close(code=1011, reason="Authentication state unavailable")
            except Exception:
                logger.debug("WebSocket already closed for user %s", user_id)
            return

        if state is None:
            logger.warning("Closing WebSocket for deleted user %s", user_id)
            try:
                await websocket.close(code=4001, reason="Authentication revoked")
            except Exception:
                logger.debug("WebSocket already closed for deleted user %s", user_id)
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
            try:
                await websocket.send_json(
                    {
                        "type": "auth.revoked",
                        "reason": "session_revoked",
                    }
                )
            except Exception:
                logger.debug("Could not send revocation event to user %s", user_id)
            try:
                await websocket.close(code=4001, reason="Authentication revoked")
            except Exception:
                logger.debug("WebSocket already closed for revoked user %s", user_id)
            return
