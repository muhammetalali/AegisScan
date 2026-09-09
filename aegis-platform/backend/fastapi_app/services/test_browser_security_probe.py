from __future__ import annotations

from fastapi_app.services.browser_security_probe import SCHEMA, analyze_dom


def test_browser_security_probe_emits_security_observations_without_secret_values() -> None:
    sensitive_value = 'secret-browser-password-value'
    payload = analyze_dom(
        'https://app.example.test/login',
        f'''
        <html>
          <head>
            <title>Secure Login</title>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
            <link rel="preload stylesheet" href="/app.css">
            <script src="https://cdn.example.invalid/app.js"></script>
          </head>
          <body>
            <form action="http://app.example.test/login" method="post">
              <input type="password" name="password" value="{sensitive_value}">
            </form>
            <iframe src="https://analytics.example.invalid/frame"></iframe>
            <img src="http://app.example.test/insecure.png">
            <script>console.log('inline')</script>
          </body>
        </html>
        ''',
        truncated=False,
        browser='/usr/bin/chromium',
        browser_family='chromium',
        capture_method='chromium-dump-dom',
        browser_log='console and browser logs stay visible',
        virtual_time_budget_ms=2000,
        max_dom_bytes=131072,
    )
    assert payload['schema'] == SCHEMA
    assert payload['browser_family'] == 'chromium'
    assert payload['dom_sha256']
    assert payload['runtime'] == {
        'virtual_time_budget_ms': 2000,
        'max_dom_bytes': 131072,
        'capture_method': 'chromium-dump-dom',
        'browser_log': 'console and browser logs stay visible',
    }
    observation = payload['observations'][0]
    assert observation['kind'] == 'browser-dom-security-snapshot'
    assert observation['title'] == 'Secure Login'
    assert observation['script_count'] == 2
    assert observation['inline_script_count'] == 1
    assert observation['iframe_count'] == 1
    assert observation['form_count'] == 1
    assert observation['password_field_count'] == 1
    assert observation['meta_csp_present'] is True
    assert 'cdn.example.invalid' in observation['third_party_resource_hosts']
    assert 'analytics.example.invalid' in observation['third_party_resource_hosts']
    assert observation['mixed_content_urls'] == ['http://app.example.test/insecure.png']
    assert observation['insecure_form_actions'] == ['http://app.example.test/login']
    assert 'stylesheet' in observation['link_rel_values']
    assert sensitive_value not in str(payload)


def test_browser_security_probe_records_firefox_metadata() -> None:
    payload = analyze_dom(
        'https://app.example.test/',
        '<html><head><title>Firefox</title></head><body></body></html>',
        truncated=False,
        browser='/usr/bin/firefox-esr',
        browser_family='firefox',
        capture_method='firefox-headless-load-plus-dom-fetch',
        browser_log='firefox log line',
    )
    assert payload['browser_family'] == 'firefox'
    assert payload['runtime']['capture_method'] == 'firefox-headless-load-plus-dom-fetch'
    assert payload['runtime']['browser_log'] == 'firefox log line'
    assert payload['observations'][0]['title'] == 'Firefox'
