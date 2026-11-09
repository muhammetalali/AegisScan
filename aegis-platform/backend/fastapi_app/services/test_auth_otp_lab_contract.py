"""Offline fail-closed contract tests; no network, database, or credentials."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).with_name("auth_otp_lab_contract.py")
spec = importlib.util.spec_from_file_location("auth_otp_lab_contract_under_test", path)
auth = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = auth
spec.loader.exec_module(auth)

ATTEMPT = "573d1658-e455-4c96-b13f-1c38669eae2e"
SESSION = "a961adad-abd5-4dbe-a7b5-cb3bbed4f962"
OTHER_SESSION = "aa48fd31-acf6-4099-931b-2e5f1935c1fb"
ORIGIN = "https://challenge.cyberpedia.site"


def make():
    return auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=ORIGIN)


def advance(to_step="otp"):
    state, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form></form>")
    state, _ = auth.observe(state, step="primary_login", http_status=200,
                            body=b'{"ok":true,"redirect":"/otp"}',
                            session_binding_ref=SESSION)
    if to_step == "otp":
        return state
    state, _ = auth.observe(state, step="otp_submit", http_status=200,
                            body=b'{"ok":true,"redirect":"/success"}',
                            session_binding_ref=SESSION)
    return state


class AuthOTPContractTests(unittest.TestCase):
    def test_requires_canonical_attempt_and_bounded_budget(self):
        for ref in ("invalid", ATTEMPT.upper(), "", None):
            with self.subTest(ref=ref), self.assertRaises(auth.AuthLabContractError):
                auth.AuthAttempt(attempt_ref=ref, authorized_origin=ORIGIN)
        for budget in (0, 26, True):
            with self.subTest(budget=budget), self.assertRaises(auth.AuthLabContractError):
                auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=ORIGIN, max_observations=budget)

    def test_rejects_unapproved_origins(self):
        for origin in (
            "http://challenge.cyberpedia.site",
            "https://challenge.cyberpedia.site/admin", "https://a:b@challenge.cyberpedia.site",
            "https://challenge.cyberpedia.site?x=1", "https://challenge.cyberpedia.site:8443",
            "https://challenge.cyberpedia.site\n", "",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(auth.AuthLabContractError):
                    auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=origin)

    def test_rejects_unordered_steps(self):
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(make(), step="otp_submit", http_status=200, body=b"{}", session_binding_ref=SESSION)
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(make(), step="undefined", http_status=200, body=b"{}")

    def test_two_stage_positive_remains_observation_only(self):
        pending = advance()
        self.assertEqual(pending.stage, auth.Stage.OTP_PENDING)
        verified = advance("verified")
        self.assertEqual(verified.stage, auth.Stage.OTP_VERIFIED)
        observed, summary = auth.observe(
            verified, step="protected_fetch", request_path="/success",
            session_binding_ref=SESSION, http_status=200, body=b"<h1>Congratulations</h1>"
        )
        self.assertEqual(observed.stage, auth.Stage.PROTECTED_OBSERVED)
        self.assertEqual(summary["result"], "protected_response_observed")
        self.assertFalse(summary["lab_solved"])
        self.assertFalse(summary["independent_success_screen_proven"])
        self.assertNotIn("Congratulations", str(summary))

    def test_negative_primary_auth_keeps_state(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        next_state, summary = auth.observe(
            login, step="primary_login", http_status=401,
            body=b'{"ok":false,"message":"invalid"}',
            session_binding_ref=SESSION,
        )
        self.assertEqual(next_state.stage, auth.Stage.LOGIN_SEEN)
        self.assertEqual(summary["result"], "denied")
        self.assertFalse(summary["lab_solved"])

    def test_denied_primary_login_does_not_bind_a_failed_session(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        denied, _ = auth.observe(login, step="primary_login", http_status=401,
                                 body=b'{"ok":false}', session_binding_ref=SESSION)
        self.assertIsNone(denied.session_binding_ref)
        accepted, _ = auth.observe(
            denied, step="primary_login", http_status=200,
            body=b'{"ok":true,"redirect":"/otp"}', session_binding_ref=OTHER_SESSION,
        )
        self.assertEqual(accepted.session_binding_ref, OTHER_SESSION)
        self.assertEqual(accepted.stage, auth.Stage.OTP_PENDING)

    def test_success_response_rejects_nonfinite_json(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(login, step="primary_login", http_status=200,
                         body=b'{"ok":true,"redirect":"/otp","error":NaN}',
                         session_binding_ref=SESSION)

    def test_negative_otp_preserves_pending(self):
        pending = advance()
        later, summary = auth.observe(
            pending, step="otp_submit", http_status=403,
            body=b'{"ok":false}', session_binding_ref=SESSION,
        )
        self.assertEqual(later.stage, auth.Stage.OTP_PENDING)
        self.assertEqual(summary["result"], "denied")

    def test_success_requires_boolean_true_not_truthy(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        for value in (1, "true", [], {}, None):
            with self.subTest(value=value):
                data = json.dumps({"ok": value, "redirect": "/otp"}).encode()
                state, info = auth.observe(login, step="primary_login", http_status=200,
                                           body=data, session_binding_ref=SESSION)
                self.assertEqual(state.stage, auth.Stage.LOGIN_SEEN)
                self.assertEqual(info["result"], "indeterminate")

    def test_rejects_off_origin_or_ambiguous_redirects(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        cases = [
            "//evil.invalid", "https://evil.invalid/",
            "https://challenge.cyberpedia.site.evil.invalid/",
            "/../success", "/a/./success", "/a//success",
            "/%2e%2e/admin", "/otp?token=secret", "/otp#fragment",
            "\\evil", "javascript:alert(1)", "/secret\n",
            "https://a:b@challenge.cyberpedia.site/otp",
        ]
        for redirect in cases:
            with self.subTest(redirect=redirect):
                with self.assertRaises(auth.AuthLabContractError):
                    auth.observe(
                        login, step="primary_login", http_status=200,
                        body=json.dumps({"ok": True, "redirect": redirect}).encode(),
                        session_binding_ref=SESSION,
                    )

    def test_session_fixation_or_swap_blocks_progress(self):
        pending = advance()
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(pending, step="otp_submit", http_status=200,
                         body=b'{"ok":true,"redirect":"/success"}',
                         session_binding_ref=OTHER_SESSION)
        self.assertEqual(pending.stage, auth.Stage.OTP_PENDING)

    def test_pre_otp_probe_requires_sealed_path_and_never_completes_mfa(self):
        seeded = auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=ORIGIN,
                                  pre_otp_probe_path="/protected")
        seen, _ = auth.observe(seeded, step="login_form", http_status=200, body=b"<form>")
        pending, _ = auth.observe(
            seen, step="primary_login", http_status=200,
            body=b'{"ok":true,"redirect":"/otp"}', session_binding_ref=SESSION,
        )
        weak, weak_summary = auth.observe(
            pending, step="pre_otp_protected_fetch", http_status=200,
            body=b"<h1>Synthetic protected content</h1>",
            session_binding_ref=SESSION, request_path="/protected",
        )
        self.assertEqual(weak.stage, auth.Stage.OTP_PENDING)
        self.assertEqual(weak_summary["result"], "pre_otp_protected_http_200_observed")
        self.assertFalse(weak_summary["lab_solved"])
        self.assertFalse(weak_summary["independent_success_screen_proven"])
        self.assertNotIn("Synthetic protected content", str(weak_summary))
        patched, patched_summary = auth.observe(
            pending, step="pre_otp_protected_fetch", http_status=403,
            body=b'{"ok":false}', session_binding_ref=SESSION,
            request_path="/protected",
        )
        self.assertEqual(patched.stage, auth.Stage.OTP_PENDING)
        self.assertEqual(patched_summary["result"], "pre_otp_protected_denial_observed")
        self.assertEqual(patched_summary["status_code"], 403)

    def test_pre_otp_probe_rejects_unsealed_or_other_identity_or_path(self):
        unsealed = advance()
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(
                unsealed, step="pre_otp_protected_fetch", http_status=200,
                body=b"success", session_binding_ref=SESSION,
                request_path="/protected",
            )
        seeded = auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=ORIGIN,
                                  pre_otp_probe_path="/protected")
        seen, _ = auth.observe(seeded, step="login_form", http_status=200, body=b"<form>")
        pending, _ = auth.observe(seen, step="primary_login", http_status=200,
                                  body=b'{"ok":true,"redirect":"/otp"}',
                                  session_binding_ref=SESSION)
        for opts in (
            {"request_path": "/admin", "session_binding_ref": SESSION},
            {"request_path": "/protected", "session_binding_ref": OTHER_SESSION},
            {"request_path": "/protected?foo=bar", "session_binding_ref": SESSION},
            {"request_path": "https://evil.invalid/", "session_binding_ref": SESSION},
        ):
            with self.subTest(opts=opts), self.assertRaises(auth.AuthLabContractError):
                auth.observe(pending, step="pre_otp_protected_fetch",
                             http_status=200, body=b"<h1/>", **opts)
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(seen, step="pre_otp_protected_fetch",
                         http_status=200, body=b"<h1/>",
                         request_path="/protected", session_binding_ref=SESSION)
        with self.assertRaises(auth.AuthLabContractError):
            auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=ORIGIN,
                             pre_otp_probe_path="//evil.invalid")

    def test_otp_required_before_fetch_and_path_must_match(self):
        pending = advance()
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(pending, step="protected_fetch", http_status=200,
                         body=b"<h1>Success</h1>", session_binding_ref=SESSION,
                         request_path="/success")
        verified = advance("verified")
        for path in ("/admin", "/success?x=1", "https://evil.invalid/", "/a/../success"):
            with self.subTest(path=path), self.assertRaises(auth.AuthLabContractError):
                auth.observe(verified, step="protected_fetch", request_path=path,
                             session_binding_ref=SESSION, http_status=200, body=b"<h1/>")

    def test_bounded_response_and_duplicate_keys_fail_closed(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        for body in (b'{"ok":true,"ok":false,"redirect":"/otp"}',
                     b'{"ok":true,"redirect":"/otp"}' + b" " * 70000,
                     b'\xff', b'[]'):
            with self.subTest(length=len(body)), self.assertRaises(auth.AuthLabContractError):
                auth.observe(login, step="primary_login", http_status=200,
                             body=body, session_binding_ref=SESSION)

    def test_no_raw_secrets_persisted_in_summary(self):
        login, _ = auth.observe(make(), step="login_form", http_status=200, body=b"<form>")
        body = b'{"ok":false,"password":"hidden-value","session":"secret-value"}'
        state, summary = auth.observe(login, step="primary_login", http_status=401,
                                      body=body, session_binding_ref=SESSION)
        self.assertEqual(summary["response_sha256"], hashlib.sha256(body).hexdigest())
        self.assertNotIn("hidden-value", str(summary))
        self.assertNotIn("secret-value", str(summary))
        self.assertFalse(summary["raw_response_persisted"])

    def test_attempt_budget_is_finite(self):
        state = auth.AuthAttempt(attempt_ref=ATTEMPT, authorized_origin=ORIGIN, max_observations=1)
        state, _ = auth.observe(state, step="login_form", http_status=200, body=b"<form>")
        with self.assertRaises(auth.AuthLabContractError):
            auth.observe(state, step="primary_login", http_status=200,
                         body=b'{"ok":true,"redirect":"/otp"}', session_binding_ref=SESSION)

    def test_does_not_expose_network_or_persistence_api(self):
        self.assertFalse(hasattr(auth, "send_http_request"))
        self.assertFalse(hasattr(auth, "store_password"))
        self.assertFalse(hasattr(auth, "mark_lab_solved"))


if __name__ == "__main__":
    unittest.main()
