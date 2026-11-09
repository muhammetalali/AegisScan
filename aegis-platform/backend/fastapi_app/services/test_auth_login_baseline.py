"""No-network invariants for the server-built anonymous login probe."""
from __future__ import annotations

import unittest

from fastapi_app.services.auth_login_baseline import (
    AUTH_BASELINE_ID, AUTH_BASELINE_PATH, login_request_arguments,
    summarize_login_result,
)

TARGET = "https://challenge.cyberpedia.site/"


def payload_for(wire: str, *, status=200, body="<form id='login'></form>", wrapper=True):
    response = f"HTTP/1.1 {status} OK\r\nContent-Type: text/html\r\nSet-Cookie: SESSION=do-not-save\r\n\r\n{body}"
    if wrapper:
        response = (
            "HttpRequestResponse{httpRequest=" + wire
            + ", httpResponse=" + response
            + ", messageAnnotations=Annotations{comment='', highlightColor=NONE}}"
        )
    return {"mcp_result": {"content": [{"type": "text", "text": response}]},
            "transport_metadata": {"transport": "contract-only"}}


class AnonymousLoginBaseline(unittest.TestCase):
    def test_exact_get_login_is_built_without_credentials(self):
        args = login_request_arguments(TARGET)
        self.assertEqual(AUTH_BASELINE_ID, "auth-login-baseline-v1")
        self.assertEqual(AUTH_BASELINE_PATH, "/login")
        self.assertEqual(args["targetHostname"], "challenge.cyberpedia.site")
        self.assertTrue(args["usesHttps"])
        self.assertEqual(args["targetPort"], 443)
        self.assertTrue(args["content"].startswith("GET /login HTTP/1.1\r\n"))
        self.assertIn("Host: challenge.cyberpedia.site\r\n", args["content"])
        self.assertIn("Accept: text/html\r\n", args["content"])
        self.assertNotIn("Authorization:", args["content"])
        self.assertNotIn("Cookie:", args["content"])
        self.assertNotIn("password", args["content"].lower())

    def test_non_origin_and_credentialed_target_denied(self):
        for target in (
            "", "ftp://challenge.cyberpedia.site/",
            TARGET + "admin", TARGET + "?x=1",
            "https://user:pass@challenge.cyberpedia.site/",
            "https://challenge.cyberpedia.site/\n",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                login_request_arguments(target)

    def test_result_is_bounded_redacted_and_never_proves_a_bypass(self):
        args = login_request_arguments(TARGET)
        result = summarize_login_result(
            payload_for(args["content"]), request_arguments=args,
        )
        self.assertTrue(result["login_form_observed"])
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["definition_id"], AUTH_BASELINE_ID)
        self.assertEqual(result["path"], AUTH_BASELINE_PATH)
        self.assertFalse(result["lab_solved"])
        self.assertFalse(result["mfa_bypassed"])
        self.assertFalse(result["success_screen_proven"])
        self.assertFalse(result["raw_request_response_persisted"])
        self.assertNotIn("SESSION", str(result))
        self.assertNotIn("do-not-save", str(result))

    def test_empty_transport_metadata_proves_no_provider_identity(self):
        args = login_request_arguments(TARGET)
        payload = payload_for(args["content"])
        payload["transport_metadata"] = {}
        summary = summarize_login_result(payload, request_arguments=args)
        self.assertEqual(summary["transport_metadata"], {})
        self.assertFalse(summary["lab_solved"])
        self.assertFalse(summary["mfa_bypassed"])

    def test_health_probe_uses_same_redaction_boundary(self):
        from fastapi_app.services.burp_http_probe import summarize_health_result
        good = {
            "mcp_result": {"content": [{
                "type": "text",
                "text": 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                        '\r\n{"fixture":"bac-target","status":"ok"}',
            }]},
            "transport_metadata": {"transport": "sse", "retry_count": 0},
        }
        result = summarize_health_result(good)
        self.assertTrue(result["transport_probe_passed"])
        self.assertEqual(result["transport_metadata"], good["transport_metadata"])
        for metadata in (
            {"transport": "sse", "Authorization": "Bearer secret"},
            {"transport": "sse", "retry_count": 1},
            {"transport": ["secret"]},
        ):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                summarize_health_result({**good, "transport_metadata": metadata})

    def test_rejects_untrusted_metadata_before_durable_evidence(self):
        args = login_request_arguments(TARGET)
        for mutation in (
            {"transport": "sse", "Cookie": "secret_session"},
            {"transport": "sse", "Authorization": "Bearer secret"},
            {"transport": "sse", "server_info_sha256": "rawsecret"},
            {"transport": "sse", "server_name": "burp-suite;token=secret"},
            {"transport": "sse", "retry_count": True},
            {"transport": "sse", "retry_count": 1},
            {"transport": "sse", "server_reported_version": "1.0.0;secret"},
            {"transport": "sse", "protocol_version": "secret_protocol"},
            {"transport": "https://secret.invalid"},
            {"transport": []},
            {"transport": {"secret": "credential"}},
            ["not", "a", "mapping"],
        ):
            with self.subTest(metadata=str(mutation)[:75]):
                response = payload_for(args["content"])
                response["transport_metadata"] = mutation
                with self.assertRaises(ValueError):
                    summarize_login_result(response, request_arguments=args)

    def test_realistic_burp_transport_metadata_is_bounded_and_preserved(self):
        args = login_request_arguments(TARGET)
        transport = {
            "transport": "sse", "protocol_version": "2024-11-05",
            "server_info_sha256": "a" * 64, "tools_sha256": "b" * 64,
            "tool_schema_sha256": "c" * 64,
            "server_name": "burp-suite",
            "server_reported_version": "1.1.2",
            "edition": "not_reported", "retry_count": 0,
        }
        response = payload_for(args["content"])
        response["transport_metadata"] = transport
        summary = summarize_login_result(response, request_arguments=args)
        self.assertEqual(summary["transport_metadata"], transport)
        self.assertFalse(summary["lab_solved"])
        self.assertNotIn("do-not-save", str(summary))

    def test_plain_http_response_is_supported_but_not_a_success_verdict(self):
        args = login_request_arguments(TARGET)
        result = summarize_login_result(
            payload_for(args["content"], status=404, body="not found", wrapper=False),
            request_arguments=args,
        )
        self.assertFalse(result["login_form_observed"])
        self.assertEqual(result["status_code"], 404)
        self.assertFalse(result["lab_solved"])

    def test_request_response_mismatch_is_rejected(self):
        args = login_request_arguments(TARGET)
        bad = payload_for(args["content"].replace("GET /login", "GET /admin"))
        with self.assertRaises(ValueError):
            summarize_login_result(bad, request_arguments=args)
        with self.assertRaises(ValueError):
            summarize_login_result(
                payload_for(args["content"]), request_arguments={"content": "GET /admin HTTP/1.1\r\n\r\n"},
            )

    def test_truncated_or_oversized_response_is_rejected(self):
        args = login_request_arguments(TARGET)
        for bad in (
            {"mcp_result": {"content": []}},
            {"mcp_result": {"content": [{"type": "text", "text": "HTTP/1.1 200 OK"}]}},
            payload_for(args["content"], body="<form>" + ("A" * 1_050_000)),
            payload_for(args["content"], status=600),
        ):
            with self.subTest(case=str(bad)[:40]), self.assertRaises(ValueError):
                summarize_login_result(bad, request_arguments=args)


if __name__ == "__main__":
    unittest.main()
