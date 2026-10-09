#!/usr/bin/env python3
"""Read-only real-Firefox smoke for public AegisScan auth routes.

No credentials or mutations; all data is displayed as bounded metadata.
"""
import json
import os
import time
import urllib.error
import urllib.request

ROOT = os.environ.get("AEGIS_BROWSER_BASE", "https://aegis-prod.aegis.internal")
DRIVER = "http://127.0.0.1:4999"


def webdriver(method, path, payload=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        DRIVER + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=40) as response:
        result = json.load(response)
    value = result.get("value")
    if isinstance(value, dict) and value.get("error"):
        raise RuntimeError(str(value["error"]))
    return value


def smoke():
    session = webdriver(
        "POST",
        "/session",
        {"capabilities": {"alwaysMatch": {
            "browserName": "firefox",
            "acceptInsecureCerts": True,
            "moz:firefoxOptions": {"args": ["-headless"]},
        }}},
    )["sessionId"]
    try:
        results = []
        for path in ("/login", "/register", "/forgot-password", "/terms", "/privacy", "/dashboard"):
            webdriver("POST", f"/session/{session}/url", {"url": ROOT + path})
            time.sleep(0.7)
            metadata = webdriver("POST", f"/session/{session}/execute/sync", {
                "script": """return {
                  url: location.href, path: location.pathname,
                  title: document.title, inputCount: document.querySelectorAll('input').length,
                  buttonCount: document.querySelectorAll('button').length,
                  linkTargets: [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')).slice(0,30),
                  mainText: (document.querySelector('main') || document.body).innerText.slice(0,400)
                }""",
                "args": [],
            })
            # Wait for SPA lazy-route hydration rather than treating its initial
            # loading skeleton as a tested view.
            for _ in range(20):
                if metadata['inputCount'] or metadata['linkTargets'] or len(metadata['mainText']) > 120:
                    break
                time.sleep(0.45)
                metadata = webdriver("POST", f"/session/{session}/execute/sync", {
                    "script": """return {
                      url: location.href, path: location.pathname,
                      title: document.title, inputCount: document.querySelectorAll('input').length,
                      buttonCount: document.querySelectorAll('button').length,
                      linkTargets: [...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')).slice(0,30),
                      mainText: (document.querySelector('main') || document.body).innerText.slice(0,400)
                    }""", "args": [],
                })
            metadata["requested_path"] = path
            results.append(metadata)
            print(json.dumps(metadata, ensure_ascii=False), flush=True)
        assert any(r["requested_path"] == "/login" and r["inputCount"] >= 2 for r in results)
        assert any(r["requested_path"] == "/register" and r["inputCount"] == 0 and "مالك الشركة" in r["mainText"] for r in results)
        assert next(r for r in results if r["requested_path"] == "/dashboard")["path"] == "/login"
    finally:
        webdriver("DELETE", f"/session/{session}")


if __name__ == "__main__":
    smoke()
