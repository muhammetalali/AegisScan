from fastapi_app.services.native_output_normalizer import normalize_native_output


def test_ffuf_json_is_normalized_to_bounded_web_observations():
    raw = '{"results":[{"url":"https://example.test/admin","status":403,"length":123,"words":5,"lines":2}]}'
    result = normalize_native_output('web.ffuf', raw)
    assert result['schema'] == 'aegis.native-observations.v1'
    assert result['count'] == 1
    assert result['observations'][0] == {
        'kind': 'web-endpoint',
        'url': 'https://example.test/admin',
        'status': 403,
        'length': 123,
        'words': 5,
        'lines': 2,
    }


def test_gobuster_output_is_normalized():
    result = normalize_native_output('web.gobuster', '/admin (Status: 301) [Size: 169]\n')
    assert result['count'] == 1
    assert result['observations'][0]['path'] == '/admin'
    assert result['observations'][0]['status'] == 301


def test_security_headers_are_normalized_to_control_observations():
    raw = (
        'HTTP/1.1 200 OK\r\n'
        'Content-Security-Policy: default-src \'self\'\r\n'
        'X-Content-Type-Options: nosniff\r\n'
        'Referrer-Policy: no-referrer\r\n'
        'Server: fixture\r\n'
        '\r\n'
    )
    result = normalize_native_output('web.security-headers', raw)
    assert result['count'] == 1
    observation = result['observations'][0]
    assert observation['kind'] == 'web-response-headers'
    assert observation['status'] == 200
    assert observation['headers']['content-security-policy'] == "default-src 'self'"
    assert observation['present_security_headers'] == [
        'content-security-policy',
        'referrer-policy',
        'x-content-type-options',
    ]
    assert 'strict-transport-security' in observation['missing_security_headers']


def test_browser_security_json_is_normalized_without_raw_dom_or_secret_values():
    raw = '''{
      "schema": "aegis.browser-security.v1",
      "target_url": "https://app.example.test/login",
      "dom_sha256": "abc123",
      "observations": [{
        "kind": "browser-dom-security-snapshot",
        "title": "Login",
        "script_count": 1,
        "inline_script_count": 0,
        "iframe_count": 0,
        "form_count": 1,
        "password_field_count": 1,
        "meta_csp_present": true,
        "third_party_resource_hosts": ["cdn.example.invalid"],
        "mixed_content_urls": [],
        "insecure_form_actions": []
      }]
    }'''
    result = normalize_native_output('browser.dom-snapshot', raw)
    assert result['schema'] == 'aegis.native-observations.v1'
    assert result['count'] == 1
    observation = result['observations'][0]
    assert observation['kind'] == 'browser-dom-security-snapshot'
    assert observation['password_field_count'] == 1
    assert observation['third_party_resource_hosts'] == ['cdn.example.invalid']
    assert 'secret-browser-password-value' not in str(result)
    assert 'dom_sha256' not in observation


def test_browser_security_error_is_normalized_to_bounded_observation():
    result = normalize_native_output(
        'browser.dom-snapshot',
        '{"schema":"aegis.browser-security.v1","error":"navigation failed","observations":[]}',
    )
    assert result['count'] == 1
    assert result['observations'][0] == {'kind': 'browser-error', 'summary': 'navigation failed'}


def test_exiftool_json_keeps_only_json_scalar_metadata():
    raw = '[{"SourceFile":"/tmp/a.jpg","FileSize":"12 kB","Nested":{"ignored":true}}]'
    result = normalize_native_output('forensics.exiftool', raw)
    assert result['count'] == 1
    attrs = result['observations'][0]['attributes']
    assert attrs['FileSize'] == '12 kB'
    assert 'Nested' not in attrs
