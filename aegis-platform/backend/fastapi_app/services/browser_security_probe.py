#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

SCHEMA = 'aegis.browser-security.v1'


class BrowserDomParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.target_host = (urlparse(base_url).hostname or '').lower()
        self.title_parts: list[str] = []
        self.in_title = False
        self.in_script = False
        self.inline_script_count = 0
        self.script_count = 0
        self.iframe_count = 0
        self.form_count = 0
        self.password_field_count = 0
        self.meta_csp_present = False
        self.base_tag_present = False
        self.resource_urls: list[str] = []
        self.form_actions: list[str] = []
        self.rel_values: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {name.lower(): value or '' for name, value in attrs}
        if tag == 'title':
            self.in_title = True
        elif tag == 'script':
            self.script_count += 1
            self.in_script = True
            src = attr_map.get('src')
            if src:
                self.resource_urls.append(urljoin(self.base_url, src))
        elif tag in {'img', 'iframe', 'frame', 'embed', 'object', 'audio', 'video', 'source', 'track'}:
            src = attr_map.get('src') or attr_map.get('data')
            if src:
                self.resource_urls.append(urljoin(self.base_url, src))
            if tag in {'iframe', 'frame'}:
                self.iframe_count += 1
        elif tag == 'link':
            href = attr_map.get('href')
            if href:
                self.resource_urls.append(urljoin(self.base_url, href))
            rel = attr_map.get('rel')
            if rel:
                self.rel_values.update(part.strip().lower() for part in rel.split() if part.strip())
        elif tag == 'form':
            self.form_count += 1
            action = attr_map.get('action')
            if action:
                self.form_actions.append(urljoin(self.base_url, action))
        elif tag == 'input' and attr_map.get('type', '').lower() == 'password':
            self.password_field_count += 1
        elif tag == 'meta':
            equiv = attr_map.get('http-equiv', '').lower()
            if equiv == 'content-security-policy':
                self.meta_csp_present = True
        elif tag == 'base':
            self.base_tag_present = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == 'title':
            self.in_title = False
        elif tag == 'script':
            self.in_script = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title_parts.append(data.strip())
        elif self.in_script and data.strip():
            self.inline_script_count += 1

    def snapshot(self, dom: str, truncated: bool, browser: str, virtual_time_budget_ms: int, max_dom_bytes: int) -> dict[str, Any]:
        target_scheme = urlparse(self.base_url).scheme.lower()
        target_host = self.target_host
        resource_hosts: set[str] = set()
        third_party_hosts: set[str] = set()
        mixed_content: list[str] = []
        for value in self.resource_urls:
            parsed = urlparse(value)
            host = (parsed.hostname or '').lower()
            if host:
                resource_hosts.add(host)
                if target_host and host != target_host:
                    third_party_hosts.add(host)
            if target_scheme == 'https' and parsed.scheme == 'http':
                mixed_content.append(value[:2048])
        insecure_form_actions = [
            value[:2048]
            for value in self.form_actions
            if urlparse(value).scheme == 'http'
        ]
        return {
            'schema': SCHEMA,
            'browser': browser,
            'target_url': self.base_url,
            'dom_sha256': hashlib.sha256(dom.encode('utf-8', errors='ignore')).hexdigest(),
            'dom_bytes': len(dom.encode('utf-8', errors='ignore')),
            'dom_truncated': truncated,
            'navigation_policy': {
                'javascript_disabled': True,
                'third_party_dns_blocked': True,
                'virtual_time_budget_ms': virtual_time_budget_ms,
                'max_dom_bytes': max_dom_bytes,
            },
            'observations': [
                {
                    'kind': 'browser-dom-security-snapshot',
                    'title': ' '.join(part for part in self.title_parts if part)[:512],
                    'script_count': self.script_count,
                    'inline_script_count': self.inline_script_count,
                    'iframe_count': self.iframe_count,
                    'form_count': self.form_count,
                    'password_field_count': self.password_field_count,
                    'meta_csp_present': self.meta_csp_present,
                    'base_tag_present': self.base_tag_present,
                    'resource_host_count': len(resource_hosts),
                    'third_party_resource_hosts': sorted(third_party_hosts)[:100],
                    'mixed_content_urls': mixed_content[:100],
                    'insecure_form_actions': insecure_form_actions[:100],
                    'link_rel_values': sorted(self.rel_values)[:100],
                }
            ],
        }


def _browser_binary() -> str:
    for candidate in ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'):
        value = shutil.which(candidate)
        if value:
            return value
    raise RuntimeError('No supported headless browser binary is installed on the scanner worker')


def _host_resolver_rule(url: str) -> str:
    host = (urlparse(url).hostname or '').strip().lower()
    if not host or any(ch in host for ch in ',\r\n\x00'):
        raise ValueError('Invalid browser target host')
    return f'MAP * ~NOTFOUND, EXCLUDE {host}'


def capture_dom(url: str, virtual_time_budget_ms: int, max_dom_bytes: int) -> tuple[str, bool, str]:
    browser = _browser_binary()
    with tempfile.TemporaryDirectory(prefix='aegis-browser-profile-') as profile:
        argv = [
            browser,
            '--headless=new',
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-gpu',
            '--disable-dev-shm-usage',
            '--disable-extensions',
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-sync',
            '--disable-translate',
            '--disable-component-update',
            '--disable-features=MediaRouter,OptimizationHints,AutofillServerCommunication',
            '--blink-settings=imagesEnabled=false',
            '--disable-javascript',
            '--mute-audio',
            '--no-first-run',
            '--no-default-browser-check',
            f'--host-resolver-rules={_host_resolver_rule(url)}',
            f'--user-data-dir={profile}',
            f'--virtual-time-budget={virtual_time_budget_ms}',
            '--dump-dom',
            url,
        ]
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            timeout=max(15, min(90, (virtual_time_budget_ms // 1000) + 20)),
            check=False,
            env={**os.environ, 'NO_COLOR': '1'},
        )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or 'headless browser failed').strip()[:2000])
    dom = completed.stdout or ''
    encoded = dom.encode('utf-8', errors='ignore')
    truncated = len(encoded) > max_dom_bytes
    if truncated:
        dom = encoded[:max_dom_bytes].decode('utf-8', errors='ignore')
    return dom, truncated, browser


def analyze_dom(url: str, dom: str, truncated: bool, browser: str = 'test-browser', virtual_time_budget_ms: int = 3000, max_dom_bytes: int = 262144) -> dict[str, Any]:
    parser = BrowserDomParser(url)
    parser.feed(dom)
    parser.close()
    return parser.snapshot(dom, truncated, browser, virtual_time_budget_ms, max_dom_bytes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AegisScan governed browser security snapshot probe')
    parser.add_argument('url')
    parser.add_argument('--virtual-time-budget-ms', type=int, default=3000)
    parser.add_argument('--max-dom-bytes', type=int, default=262144)
    args = parser.parse_args(argv)
    if args.virtual_time_budget_ms < 1000 or args.virtual_time_budget_ms > 10000:
        raise SystemExit('virtual-time-budget-ms must be between 1000 and 10000')
    if args.max_dom_bytes < 65536 or args.max_dom_bytes > 1048576:
        raise SystemExit('max-dom-bytes must be between 65536 and 1048576')
    parsed = urlparse(args.url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise SystemExit('Only absolute http/https URLs are supported')
    dom, truncated, browser = capture_dom(args.url, args.virtual_time_budget_ms, args.max_dom_bytes)
    print(json.dumps(analyze_dom(args.url, dom, truncated, browser, args.virtual_time_budget_ms, args.max_dom_bytes), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'schema': SCHEMA, 'error': str(exc)[:2000], 'observations': []}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
