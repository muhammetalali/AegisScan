from urllib.parse import parse_qs

from channels.db import database_sync_to_async
from channels.middleware import BaseMiddleware
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError


class JWTAuthMiddleware(BaseMiddleware):
    """Authenticate Channels connections with the same JWT contract as DRF.

    Browser WebSocket clients cannot set an Authorization header. Prefer the
    Sec-WebSocket-Protocol bearer transport so the access token is not placed
    in the URL/query string. The query-string form remains a compatibility
    fallback and can be disabled in production with WS_ALLOW_QUERY_TOKEN=0.
    """

    async def __call__(self, scope, receive, send):
        token = self._token_from_subprotocol(scope)
        if not token and getattr(settings, "WS_ALLOW_QUERY_TOKEN", False):
            query_string = scope.get("query_string", b"").decode("utf-8")
            token = parse_qs(query_string).get("token", [None])[0]
        scope["user"] = await self._get_user(token)
        return await super().__call__(scope, receive, send)

    @staticmethod
    def _token_from_subprotocol(scope):
        protocols = scope.get("subprotocols") or []
        if len(protocols) >= 2 and protocols[0].lower() == "bearer":
            return protocols[1]
        return None

    @database_sync_to_async
    def _get_user(self, token):
        if not token:
            return AnonymousUser()
        try:
            authentication = JWTAuthentication()
            validated = authentication.get_validated_token(token)
            return authentication.get_user(validated)
        except (InvalidToken, TokenError):
            return AnonymousUser()


class SecurityHeadersMiddleware:
    """Apply defense-in-depth browser security headers to HTTP responses."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        # Restrict CSP to API responses. Admin/OpenAPI pages may legitimately
        # use their own script policies and should not be broken by a global CSP.
        if not settings.DEBUG and request.path.startswith("/api/"):
            response.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        return response
