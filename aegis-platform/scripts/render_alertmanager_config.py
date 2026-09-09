#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path
from urllib.parse import urlparse

TOKEN = "__ALERT_WEBHOOK_URL__"


def validate_url(value: str, allow_http: bool = False) -> str:
    parsed = urlparse(value)
    allowed = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme not in allowed or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("ALERT_WEBHOOK_URL must be an absolute HTTPS URL without credentials or fragment")
    return value


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
