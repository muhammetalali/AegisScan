from django.conf import settings
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User


class TokenRevocationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="revocation@example.com",
            password="Password123!",
            first_name="Revocation",
            last_name="Test",
        )
        self.client = APIClient()

    def _issue_refresh(self):
        return RefreshToken.for_user(self.user)

    def _set_refresh_cookie(self, refresh: RefreshToken) -> None:
        self.client.cookies[settings.AUTH_REFRESH_COOKIE] = str(refresh)

    def test_password_change_blacklists_outstanding_refresh_tokens(self):
        refresh = self._issue_refresh()
        jti = str(refresh["jti"])

        self.user.set_password("NewPassword123!")
        self.user.save(update_fields=["password"])

        token = OutstandingToken.objects.get(jti=jti)
        self.assertTrue(BlacklistedToken.objects.filter(token=token).exists())

    def test_deactivation_blacklists_outstanding_refresh_tokens(self):
        refresh = self._issue_refresh()
        jti = str(refresh["jti"])

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        token = OutstandingToken.objects.get(jti=jti)
        self.assertTrue(BlacklistedToken.objects.filter(token=token).exists())

    def test_disabling_2fa_blacklists_outstanding_refresh_tokens(self):
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = "JBSWY3DPEHPK3PXP"
        self.user.save(update_fields=["two_factor_enabled", "two_factor_secret"])
        refresh = self._issue_refresh()
        jti = str(refresh["jti"])

        self.user.two_factor_enabled = False
        self.user.two_factor_secret = ""
        self.user.save(update_fields=["two_factor_enabled", "two_factor_secret"])

        token = OutstandingToken.objects.get(jti=jti)
        self.assertTrue(BlacklistedToken.objects.filter(token=token).exists())

    def test_refresh_rejected_when_session_version_changes(self):
        refresh = self._issue_refresh()
        jti = str(refresh["jti"])
        self._set_refresh_cookie(refresh)

        self.user.session_version += 1
        self.user.save(update_fields=["session_version"])

        response = self.client.post("/api/v1/auth/refresh/", {}, format="json")

        self.assertEqual(response.status_code, 401)
        self.assertIn("Refresh token has been revoked", str(response.data))
        token = OutstandingToken.objects.get(jti=jti)
        self.assertFalse(BlacklistedToken.objects.filter(token=token).exists())

    def test_refresh_body_token_is_not_accepted(self):
        refresh = self._issue_refresh()

        response = self.client.post(
            "/api/v1/auth/refresh/",
            {"refresh": str(refresh)},
            format="json",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["detail"], "Refresh token is required")
