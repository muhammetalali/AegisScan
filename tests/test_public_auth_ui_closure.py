from pathlib import Path

ROOT = Path(__file__).parents[1]
PAGES = ROOT / "aegis-platform/frontend/src/pages/auth"


def test_recovery_ui_does_not_claim_unconfigured_email_reset():
    recovery = (PAGES / "ForgotPassword.tsx").read_text(encoding="utf-8")
    assert "Placeholder" not in recovery
    assert "غير مفعّلة حاليًا" in recovery
    assert "Email password recovery is not enabled" in recovery
    assert '<Link to="/login"' in recovery
    assert "<form" not in recovery
    assert "apiHelpers.post" not in recovery


def test_signin_links_to_safe_access_assistance():
    login = (PAGES / "Login.tsx").read_text(encoding="utf-8")
    assert '<Link to="/forgot-password"' in login
    assert "Need help accessing your account?" in login


def test_register_no_longer_links_to_nonexistent_legal_routes():
    register = (PAGES / "Register.tsx").read_text(encoding="utf-8")
    assert 'to="/terms"' not in register
    assert 'to="/privacy"' not in register
    assert "اطلب معلومات شروط الاستخدام والخصوصية" in register
    assert "2FA متاح" not in register
    assert "جلسة محمية" in register
