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
import urllib.error
import urllib.request
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urljoin, urlparse

SCHEMA = 'aegis.browser-security.v1'
BrowserChoice = Literal['auto', 'chromium', 'firefox']


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

    def snapshot(
        self,
        dom: str,
        truncated: bool,
        browser: str,
        browser_family: str,
        virtual_time_budget_ms: int,
        max_dom_bytes: int,
        capture_method: str,
        browser_log: str,
        render_evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
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
        insecure_form_actions = [value[:2048] for value in self.form_actions if urlparse(value).scheme == 'http']
        observations: list[dict[str, Any]] = [{
            'kind': 'browser-dom-security-snapshot',
            'browser_family': browser_family,
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
        }]
        if render_evidence:
            observations.append({
                'kind': 'browser-render-verification',
                'browser_family': browser_family,
                **render_evidence,
            })
        return {
            'schema': SCHEMA,
            'browser': browser,
            'browser_family': browser_family,
            'target_url': self.base_url,
            'dom_sha256': hashlib.sha256(dom.encode('utf-8', errors='ignore')).hexdigest(),
            'dom_bytes': len(dom.encode('utf-8', errors='ignore')),
            'dom_truncated': truncated,
            'runtime': {
                'virtual_time_budget_ms': virtual_time_budget_ms,
                'max_dom_bytes': max_dom_bytes,
                'capture_method': capture_method,
                'browser_log': browser_log[-12000:],
            },
            'observations': observations,
        }


def _browser_binary(preferred: BrowserChoice) -> tuple[str, str]:
    candidates: dict[str, tuple[str, ...]] = {
        'chromium': ('chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable'),
        'firefox': ('firefox-esr', 'firefox'),
    }
    if preferred not in {'chromium', 'firefox'}:
        raise ValueError(f'Explicit browser required, got {preferred}')
    for candidate in candidates[preferred]:
        value = shutil.which(candidate)
        if value:
            return value, preferred
    raise RuntimeError(f'No supported browser binary is installed for preference: {preferred}')


def _bounded_dom(raw: bytes, max_dom_bytes: int) -> tuple[str, bool]:
    truncated = len(raw) > max_dom_bytes
    data = raw[:max_dom_bytes] if truncated else raw
    return data.decode('utf-8', errors='ignore'), truncated


def _fetch_dom(url: str, max_dom_bytes: int, timeout_seconds: int) -> tuple[str, bool]:
    request = urllib.request.Request(url, headers={'User-Agent': 'AegisScan-BrowserSecurity/1.0'})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read(max_dom_bytes + 1)
    except urllib.error.URLError as exc:
        raise RuntimeError(f'Firefox navigation succeeded but DOM fetch failed: {exc}') from exc
    return _bounded_dom(raw, max_dom_bytes)


def _capture_with_chromium(
    browser: str,
    url: str,
    virtual_time_budget_ms: int,
    max_dom_bytes: int,
    profile: str,
) -> tuple[str, bool, str, str, dict[str, Any] | None]:
    argv = [
        browser,
        '--headless=new',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--no-first-run',
        '--no-default-browser-check',
        f'--user-data-dir={profile}',
        f'--virtual-time-budget={virtual_time_budget_ms}',
        '--dump-dom',
        url,
    ]
    completed = subprocess.run(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        shell=False,
        timeout=max(30, (max(0, virtual_time_budget_ms) // 1000) + 30),
        check=False,
        env={**os.environ, 'NO_COLOR': '1'},
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr.decode('utf-8', errors='ignore') or 'headless Chromium failed')[-12000:])
    dom, truncated = _bounded_dom(completed.stdout or b'', max_dom_bytes)
    return dom, truncated, 'chromium-dump-dom', completed.stderr.decode('utf-8', errors='ignore'), None


def _capture_with_firefox(
    browser: str,
    url: str,
    virtual_time_budget_ms: int,
    max_dom_bytes: int,
    profile: str,
) -> tuple[str, bool, str, str, dict[str, Any] | None]:
    screenshot_path = Path(profile) / 'aegis-firefox-check.png'
    completed = subprocess.run(
        [browser, '--headless', '--screenshot', str(screenshot_path), url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
        timeout=max(30, (max(0, virtual_time_budget_ms) // 1000) + 30),
        check=False,
        env={**os.environ, 'HOME': profile, 'TMPDIR': profile, 'MOZ_HEADLESS': '1', 'NO_COLOR': '1'},
    )
    if completed.returncode != 0 or not screenshot_path.is_file():
        raise RuntimeError((completed.stderr or completed.stdout or 'headless Firefox failed')[-12000:])
    screenshot = screenshot_path.read_bytes()
    dom, truncated = _fetch_dom(url, max_dom_bytes, max(10, (max(0, virtual_time_budget_ms) // 1000) + 10))
    log = '\n'.join(part for part in (completed.stdout, completed.stderr) if part)
    return dom, truncated, 'firefox-headless-render-plus-dom-fetch', log, {
        'rendered': True,
        'screenshot_sha256': hashlib.sha256(screenshot).hexdigest(),
        'screenshot_bytes': len(screenshot),
    }


def capture_dom(
    url: str,
    virtual_time_budget_ms: int,
    max_dom_bytes: int,
    browser_choice: Literal['chromium', 'firefox'],
) -> tuple[str, bool, str, str, str, str, dict[str, Any] | None]:
    browser, family = _browser_binary(browser_choice)
    with tempfile.TemporaryDirectory(prefix=f'aegis-{family}-profile-') as profile:
        if family == 'firefox':
            dom, truncated, method, log, render_evidence = _capture_with_firefox(
                browser, url, virtual_time_budget_ms, max_dom_bytes, profile
            )
        else:
            dom, truncated, method, log, render_evidence = _capture_with_chromium(
                browser, url, virtual_time_budget_ms, max_dom_bytes, profile
            )
    return dom, truncated, browser, family, method, log, render_evidence


def analyze_dom(
    url: str,
    dom: str,
    truncated: bool,
    browser: str = 'test-browser',
    virtual_time_budget_ms: int = 3000,
    max_dom_bytes: int = 262144,
    browser_family: str = 'test',
    capture_method: str = 'unit-test',
    browser_log: str = '',
    render_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    parser = BrowserDomParser(url)
    parser.feed(dom)
    parser.close()
    return parser.snapshot(
        dom,
        truncated,
        browser,
        browser_family,
        virtual_time_budget_ms,
        max_dom_bytes,
        capture_method,
        browser_log,
        render_evidence,
    )


def _run_browser(
    url: str,
    virtual_time_budget_ms: int,
    max_dom_bytes: int,
    browser_choice: Literal['chromium', 'firefox'],
) -> dict[str, Any]:
    dom, truncated, browser, family, method, log, render_evidence = capture_dom(
        url,
        virtual_time_budget_ms,
        max_dom_bytes,
        browser_choice,
    )
    return analyze_dom(
        url,
        dom,
        truncated,
        browser,
        virtual_time_budget_ms,
        max_dom_bytes,
        family,
        method,
        log,
        render_evidence,
    )


def _combine_runs(url: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    observations: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for run in runs:
        observations.extend(run.get('observations', []))
        summaries.append({
            'browser': run.get('browser'),
            'browser_family': run.get('browser_family'),
            'dom_sha256': run.get('dom_sha256'),
            'dom_bytes': run.get('dom_bytes'),
            'dom_truncated': run.get('dom_truncated'),
            'runtime': run.get('runtime'),
        })
    return {
        'schema': SCHEMA,
        'target_url': url,
        'browser_engines': [str(run.get('browser_family')) for run in runs],
        'browser_runs': summaries,
        'observations': observations,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='AegisScan multi-browser security snapshot probe')
    parser.add_argument('url')
    parser.add_argument('--browser', choices=('auto', 'chromium', 'firefox'), default='auto')
    parser.add_argument('--virtual-time-budget-ms', type=int, default=3000)
    parser.add_argument('--max-dom-bytes', type=int, default=262144)
    args = parser.parse_args(argv)
    if args.virtual_time_budget_ms < 0:
        raise SystemExit('virtual-time-budget-ms must be >= 0')
    if args.max_dom_bytes <= 0:
        raise SystemExit('max-dom-bytes must be > 0')
    parsed = urlparse(args.url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
        raise SystemExit('Only absolute http/https URLs are supported')

    choices: tuple[Literal['chromium', 'firefox'], ...]
    choices = ('chromium', 'firefox') if args.browser == 'auto' else (args.browser,)
    runs = [_run_browser(args.url, args.virtual_time_budget_ms, args.max_dom_bytes, choice) for choice in choices]
    print(json.dumps(_combine_runs(args.url, runs), sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'schema': SCHEMA, 'error': str(exc)[-12000:], 'observations': []}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2)
