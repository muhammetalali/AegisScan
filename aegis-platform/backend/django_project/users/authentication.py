from rest_framework.authentication import BaseAuthentication
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from django.conf import settings


class CookieJWTAuthentication(JWTAuthentication):
    """Authenticate DRF requests with the access JWT stored in an HttpOnly cookie."""

    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        generation = validated_token.get('auth_version')
        if (type(generation) is not int or generation != user.auth_version
                or user.two_factor_enabled):
            raise AuthenticationFailed('Authentication session revoked.')
        return user

    def authenticate(self, request):
        raw_token = request.COOKIES.get(settings.AUTH_ACCESS_COOKIE)
        if not raw_token:
            return super().authenticate(request)

        try:
            validated_token = self.get_validated_token(raw_token)
            return self.get_user(validated_token), validated_token
        except Exception as exc:
            raise AuthenticationFailed('Invalid or expired authentication cookie.') from exc


def revoke_outstanding_refresh_tokens(user) -> None:
    """Permanently invalidate a user's outstanding refresh JWTs before later reactivation.

    A disabled account is rejected by the current is_active authentication check,
    but unblacklisted refresh JWTs could work again if that account is reactivated
    before expiry. Reuse this one helper for administrative and self revocation.
    """
    from rest_framework_simplejwt.token_blacklist.models import (
        BlacklistedToken, OutstandingToken,
    )

    tokens = OutstandingToken.objects.filter(
        user=user, blacklistedtoken__isnull=True,
    ).iterator(chunk_size=500)
    for token in tokens:
        BlacklistedToken.objects.get_or_create(token=token)


class ScopedAPIKeyAuthentication(BaseAuthentication):
    """Accept issued API keys only on views that explicitly opt in.

    The authentication object is the persisted APIKey record, allowing the
    existing HasPermission contract to enforce both key and user scopes.
    Never install this class as a global DRF default until every endpoint has
    an audited key-scope permission contract.
    """

    def authenticate(self, request):
        import hashlib

        from django.utils import timezone
        from rest_framework.exceptions import AuthenticationFailed
        from django_project.users.models import APIKey
        from django_project.audit.services import client_ip_from_request

        material = request.META.get('HTTP_X_API_KEY')
        if material is None:
            return None
        if not isinstance(material, str) or not material.startswith('aegis_') or not 8 <= len(material) <= 256:
            raise AuthenticationFailed('Invalid API key')
        digest = hashlib.sha256(material.encode('utf-8')).hexdigest()
        key = APIKey.objects.select_related('user').filter(
            key_hash=digest, is_active=True, user__is_active=True,
            user__two_factor_enabled=False,
        ).first()
        if key is None or (key.expires_at is not None and key.expires_at <= timezone.now()):
            raise AuthenticationFailed('Invalid API key')
        # Never log raw bearer material. This metadata is deliberately limited.
        APIKey.objects.filter(pk=key.pk).update(
            last_used_at=timezone.now(), last_used_ip=client_ip_from_request(request),
        )
        return key.user, key

    def authenticate_header(self, request):
        return 'X-API-Key'

def bump_auth_version(user) -> None:
    """Atomically revoke issued access JWTs across all devices and API protocols.

    Call within the same database transaction as status/password changes. The
    new auth generation invalidates even short-lived access tokens on later
    reactivation, while separate blacklist state revokes outstanding refreshes.
    """
    from django.db.models import F
    type(user).objects.filter(pk=user.pk).update(auth_version=F('auth_version') + 1)
    user.refresh_from_db(fields=['auth_version'])
