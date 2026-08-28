from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


_PLACEHOLDER_TOKENS = (
    "your-instance",
    "example.com",
    "changeme",
    "replace-me",
)


@dataclass(frozen=True)
class ProviderConfiguration:
    provider: str
    enabled: bool
    valid: bool
    errors: tuple[str, ...]


def _is_placeholder(value: str) -> bool:
    normalized = value.strip().lower()
    return bool(normalized) and any(token in normalized for token in _PLACEHOLDER_TOKENS)


def _valid_base_url(value: str, provider: str) -> str | None:
    raw = value.strip().rstrip("/")
    parsed = urlparse(raw)
    if not raw:
        return f"{provider} base URL is missing"
    if _is_placeholder(parsed.netloc or parsed.path):
        return f"{provider} base URL is still a placeholder"
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return f"{provider} base URL must be an absolute HTTP(S) URL"
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return f"{provider} base URL must be an origin only (no API path/query/fragment)"
    return None


def validate_itsm_configuration() -> dict[str, ProviderConfiguration]:
    jira = {key: (os.getenv(key) or "").strip() for key in ("JIRA_BASE_URL", "JIRA_API_TOKEN", "JIRA_USER_EMAIL", "JIRA_PROJECT_KEY")}
    jira_enabled = any(jira.values())
    jira_errors: list[str] = []
    if jira_enabled:
        jira_errors.extend(f"missing {key}" for key, value in jira.items() if not value)
        if jira["JIRA_BASE_URL"]:
            if error := _valid_base_url(jira["JIRA_BASE_URL"], "Jira"):
                jira_errors.append(error)
        if jira["JIRA_PROJECT_KEY"] and _is_placeholder(jira["JIRA_PROJECT_KEY"]):
            jira_errors.append("Jira project key is still a placeholder")

    sn = {key: (os.getenv(key) or "").strip() for key in ("SERVICENOW_BASE_URL", "SERVICENOW_API_TOKEN", "SERVICENOW_USERNAME", "SERVICENOW_PASSWORD")}
    sn_enabled = any(sn.values())
    sn_errors: list[str] = []
    if sn_enabled:
        if not sn["SERVICENOW_BASE_URL"]:
            sn_errors.append("missing SERVICENOW_BASE_URL")
        else:
            if error := _valid_base_url(sn["SERVICENOW_BASE_URL"], "ServiceNow"):
                sn_errors.append(error)
        if not sn["SERVICENOW_API_TOKEN"] and not (sn["SERVICENOW_USERNAME"] and sn["SERVICENOW_PASSWORD"]):
            sn_errors.append("configure SERVICENOW_API_TOKEN or SERVICENOW_USERNAME + SERVICENOW_PASSWORD")

    return {
        "jira": ProviderConfiguration("jira", jira_enabled, not jira_errors, tuple(jira_errors)),
        "servicenow": ProviderConfiguration("servicenow", sn_enabled, not sn_errors, tuple(sn_errors)),
    }


def startup_validation() -> tuple[bool, dict[str, ProviderConfiguration]]:
    states = validate_itsm_configuration()
    return not any(state.enabled and not state.valid for state in states.values()), states


def configuration_error(provider: str) -> str | None:
    state = validate_itsm_configuration()[provider]
    return "; ".join(state.errors) if state.enabled and not state.valid else None
