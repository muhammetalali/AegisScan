import pytest
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from .models import User


@pytest.mark.django_db
def test_login_issues_cookie_credentials_and_me_uses_cookie():
    user = User.objects.create_user(email="cookie-test@example.invalid", password="StrongTestPassword!123")
    client = APIClient(enforce_csrf_checks=True)

    csrf_response = client.get("/api/v1/auth/csrf/")
    assert csrf_response.status_code == 200
    csrf_token = client.cookies["csrftoken"].value

    login = client.post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "StrongTestPassword!123"},
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert login.status_code == 200
    assert "access" not in login.data
    assert "refresh" not in login.data
    assert "aegis_access" in client.cookies
    assert "aegis_refresh" in client.cookies
    assert client.cookies["aegis_access"]["httponly"] is True
    assert client.cookies["aegis_refresh"]["httponly"] is True

    me = client.get("/api/v1/users/me/")
    assert me.status_code == 200
    assert me.data["email"] == user.email


@pytest.mark.django_db
def test_refresh_rotates_cookie_and_logout_blacklists_refresh_cookie():
    user = User.objects.create_user(email="cookie-refresh@example.invalid", password="StrongTestPassword!123")
    client = APIClient(enforce_csrf_checks=True)
    csrf_token = client.get("/api/v1/auth/csrf/").cookies["csrftoken"].value

    login = client.post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "StrongTestPassword!123"},
        HTTP_X_CSRFTOKEN=csrf_token,
    )
    assert login.status_code == 200
    old_refresh = client.cookies["aegis_refresh"].value

    refresh = client.post("/api/v1/auth/refresh/", {}, HTTP_X_CSRFTOKEN=csrf_token)
    assert refresh.status_code == 200
    assert "access" not in refresh.data
    assert "refresh" not in refresh.data
    new_refresh = client.cookies["aegis_refresh"].value
    assert new_refresh != old_refresh

    before = BlacklistedToken.objects.count()
    logout = client.post("/api/v1/users/logout/", {}, HTTP_X_CSRFTOKEN=csrf_token)
    assert logout.status_code == 200
    assert BlacklistedToken.objects.count() > before
