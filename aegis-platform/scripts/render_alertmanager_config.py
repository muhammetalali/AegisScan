#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import os
import stat
from pathlib import Path
from urllib.parse import urlparse

TOKEN = "__ALERT_WEBHOOK_URL__"


def validate_url(value: str, allow_http: bool = False) -> str:
    parsed = urlparse(value.strip())
    allowed = {"https"} | ({"http"} if allow_http else set())
    if (
        parsed.scheme not in allowed
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError(
            "ALERT_WEBHOOK_URL must be an absolute HTTPS URL without credentials or fragment"
        )
    host = parsed.hostname.strip().lower()
    blocked = host == "metadata.google.internal"
    loopback = host == "localhost"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        blocked = (
            blocked
            or address.is_link_local
            or address.is_unspecified
            or address.is_multicast
        )
        loopback = loopback or address.is_loopback
    if parsed.scheme == "http":
        if not allow_http or not loopback or blocked:
            raise ValueError(
                "HTTP alert webhooks are permitted only for explicit loopback tests"
            )
    elif loopback or blocked:
        raise ValueError(
            "production alert webhook must not use loopback, link-local, "
            "unspecified, multicast, or metadata endpoints"
        )
    return value.strip()


def render(template: Path, output: Path, webhook_url: str, allow_http: bool = False) -> None:
    url = validate_url(webhook_url, allow_http)
    source = template.read_text(encoding="utf-8")
    if source.count(TOKEN) != 1:
        raise ValueError("alertmanager template must contain exactly one webhook token")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".partial")
    temporary.write_text(source.replace(TOKEN, url), encoding="utf-8")
    temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.replace(temporary, output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--allow-http-for-test", action="store_true")
    args = parser.parse_args()
    webhook = os.environ.get("ALERT_WEBHOOK_URL", "")
    if not webhook:
        parser.error("ALERT_WEBHOOK_URL is required")
    render(args.template, args.output, webhook, args.allow_http_for_test)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
