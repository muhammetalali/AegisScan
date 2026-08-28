from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


_PLACEHOLDERS = {
    "your-instance",
    "your-instance.atlassian.net",
    "your-instance.service-now.com",
    "example.com",
    "localhost.example",
}


@dataclass(frozen=True)
class ProviderConfiguration:
    provider: str
    enabled: bool
    valid: bool
    errors: tuple[str, ...]


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    if not normalized:
        return False
    if normalized in _PLACEHOLDERS:
        return True
    return any(token in normalized for token in ("your-instance", "your-instance.", "example.com"))


def _valid_https_base(value: str, provider: str) -> tuple[bool, str | None]:
    raw = value.strip().rstrip("/")
    parsed = urlparse(raw)
    if not raw:
        return False, f"{provider} base URL is missing"
    if _is_placeholder(parsed.netloc or parsed.path):
        return False, f"{provider} base URL is still a placeholder"
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return False, f"{provider} base URL must be an absolute HTTP(S) URL"
    if parsed.path not in {"", "/"}:
        return False, f"{provider} base URL must not contain an API path"
    return True, None


def validate_itsm_configuration() -> dict[str, ProviderConfiguration]:
    jira_values = {key: (os.getenv(key) or "").strip() for key in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY")}
    jira_started = any(jira_values.values())
    jira_errors: list[str] = []
    if jira_started:
        missing = [key for key, value in jira_values.items() if not value]
        jira_errors.extend(f"missing {key}" for key in missing)
        if jira_values["JIRA_BASE_URL"]:
            _, error = _valid_https_base(jira_values["JIRA_BASE_URL"], "Jira")
            if error:
                jira_errors.append(error)
        if jira_values["JIRA_PROJECT_KEY"] and _is_placeholder(jira_values["JIRA_PROJECT_KEY"]):
            jira_errors.append("Jira project key is still a placeholder")

    sn_values = {key: (os.getenv(key) or "").strip() for key in ("SERVICENOW_BASE_URL", "SERVICENOW_API_TOKEN", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD")}
    sn_started = any(sn_values.values())
    sn_errors: list[str] = []
    if sn_started:
        if not sn_values["SERVICENOW_BASE_URL"]:
            sn_errors.append("missing SERVICENOW_BASE_URL")
        else:
            _, error = _valid_https_base(sn_values["SERVICENOW_BASE_URL"], "ServiceNow")
            if error:
                sn_errors.append(error)
        token_auth = bool(sn_values["SERVICENOW_API_TOKEN"])
        basic_auth = bool(sn_values["SERVICENOW_USERNAME"] and sn_values["SERVICENOW_PASSWORD"])
        if not token_auth and not basic_auth:
            sn_errors.append("configure SERVICENOW_API_TOKEN or SERVICENOW_USERNAME + SERVICENOW_PASSWORD")
        if sn_values["SERVICENOW_IDEMPOTENCY_FIELD"] if "SERVICENOW_IDEMPOTENCY_FIELD" in sn_values else False:
            pass

    return {
        "jira": ProviderConfiguration("jira", jira_started, jira_started and not jira_errors, tuple(jira_errors)),
        "servicenow": ProviderConfiguration("servicenow", sn_started, sn_started and not sn_errors, tuple(sn_errors)),
    }


def startup_validation() -> tuple[bool, dict[str, ProviderConfiguration]]:
    states = validate_itsm_configuration()
    invalid_enabled = any(state.enabled and not state.valid for state in states.values())
    return not invalid_enabled, states


def configuration_error(provider: str) -> str | None:
    state = validate_itsm_configuration()[provider]
    if not state.enabled or state.valid:
        return None
    return "; ".join(state.errors)
