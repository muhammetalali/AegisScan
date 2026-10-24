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

def test_rustscan_open_ports_and_nmap_services_are_normalized():
    raw = (
        'Open 127.0.0.1:18080\n'
        '18080/tcp open  http  Python http.server 3.12\n'
    )
    result = normalize_native_output('network.rustscan', raw)
    assert result['count'] == 2
    assert result['observations'][0] == {
        'kind': 'network-open-port',
        'host': '127.0.0.1',
        'port': 18080,
        'protocol': 'tcp',
        'service': '',
        'version': '',
    }
    assert result['observations'][1]['kind'] == 'network-service'
    assert result['observations'][1]['port'] == 18080
    assert result['observations'][1]['service'] == 'http'


def test_amass_scope_output_is_normalized_without_banner_hosts():
    raw = (
        'The Amass Discord server can be found here: https://discord.com/example\n'
        'Session Scope\n'
        'FQDN:\n'
        'api.example.test\n'
        'www.example.test\n'
    )
    result = normalize_native_output('recon.amass', raw)
    assert result['count'] == 2
    assert result['observations'] == [
        {'kind': 'discovered-hostname', 'hostname': 'api.example.test'},
        {'kind': 'discovered-hostname', 'hostname': 'www.example.test'},
    ]


def test_feroxbuster_jsonl_responses_are_normalized():
    raw = (
        '{"type":"response","url":"http://127.0.0.1:18080/admin","path":"/admin",'
        '"wildcard":false,"status":200,"method":"GET","content_length":12,'
        '"line_count":1,"word_count":1}\n'
        '{"type":"configuration","wordlist":["/opt/aegis-wordlists/web-common.txt"]}\n'
    )
    result = normalize_native_output('web.feroxbuster', raw)
    assert result['count'] == 1
    observation = result['observations'][0]
    assert observation['kind'] == 'web-endpoint'
    assert observation['url'].endswith('/admin')
    assert observation['status'] == 200
    assert observation['length'] == 12


def test_nikto_260_embedded_json_is_normalized_to_security_findings():
    raw = (
        '- Nikto v2.6.0\n'
        '[{"host":"example.test","ip":"192.0.2.10","port":443,'
        '"vulnerabilities":[{"id":"999001","references":["CVE-2099-0001"],'
        '"method":"GET","url":"/admin","msg":"Administrative endpoint is exposed"}]}]'
    )
    result = normalize_native_output('web.nikto', raw)
    assert result['count'] == 1
    observation = result['observations'][0]
    assert observation['kind'] == 'web-vulnerability'
    assert observation['rule_id'] == 'nikto.999001'
    assert observation['title'] == 'Administrative endpoint is exposed'
    assert observation['severity'] == 'medium'
    assert observation['location'] == '/admin'


def test_trivy_config_json_is_normalized_to_iac_findings():
    raw = '''{
      "SchemaVersion": 2,
      "Results": [{
        "Target": "main.tf",
        "Class": "config",
        "Type": "terraform",
        "Misconfigurations": [{
          "Type": "Terraform Security Check",
          "ID": "AVD-AWS-0086",
          "AVDID": "AVD-AWS-0086",
          "Title": "Bucket has public ACL",
          "Description": "Public ACLs expose data.",
          "Message": "Bucket has public access",
          "Resolution": "Use a private ACL.",
          "Severity": "HIGH",
          "Status": "FAIL",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/avd-aws-0086",
          "References": ["https://example.test/reference"],
          "CauseMetadata": {"StartLine": 4, "Resource": "aws_s3_bucket.bad"}
        }]
      }]
    }'''
    result = normalize_native_output('code.trivy-config', raw)
    assert result['count'] == 1
    observation = result['observations'][0]
    assert observation['kind'] == 'iac-security-finding'
    assert observation['rule_id'] == 'AVD-AWS-0086'
    assert observation['severity'] == 'high'
    assert observation['location'] == 'main.tf:4'
    assert observation['resource'] == 'aws_s3_bucket.bad'


def test_nikto_vercel_deployment_missing_retains_raw_diagnostics_without_medium_false_positives():
    import json
    from fastapi_app.services.native_finding_projection import native_observation_finding_specs

    report = [{
        'host': 'reserved.example.invalid', 'ip': '192.0.2.40', 'port': 443,
        'vulnerabilities': [
            {'id': '999979', 'method': 'GET', 'url': '/doc',
             'msg': 'IP address found in the x-vercel-id header. The IP is "a1::9".'},
            {'id': '999100', 'method': 'GET', 'url': '/doc',
             'msg': "Uncommon header(s) 'refresh' found, with contents: 0;url=/doc."},
            {'id': '999100', 'method': 'GET', 'url': '/doc',
             'msg': "Uncommon header(s) 'x-vercel-error' found, with contents: DEPLOYMENT_NOT_FOUND."},
            {'id': '013587', 'method': 'GET', 'url': '/doc',
             'msg': 'Suggested security header missing: content-security-policy.'},
            {'id': '013587', 'method': 'GET', 'url': '/doc',
             'msg': 'Suggested security header missing: permissions-policy.'},
        ],
    }]
    result = normalize_native_output('web.nikto', json.dumps(report))
    assert result['count'] == 6
    assert sum(o['kind'] == 'web-target-diagnostic' for o in result['observations']) == 5
    specs = native_observation_finding_specs(
        result, observation_kind='web-vulnerability',
        category='web-vulnerability-assessment',
    )
    assert len(specs) == 1
    assert specs[0].severity == 'info'
    assert specs[0].rule_id == 'nikto.target-unavailable.vercel-deployment-not-found'
    assert 'not a confirmed vulnerability' in specs[0].title


def test_nikto_distinct_security_headers_and_uncommon_headers_never_collapse_identity():
    import json
    from fastapi_app.services.native_finding_projection import native_observation_finding_specs

    report = [{
        'host': 'reserved.example.invalid', 'port': 443,
        'vulnerabilities': [
            {'id': '013587', 'method': 'GET', 'url': '/valid',
             'msg': 'Suggested security header missing: content-security-policy.'},
            {'id': '013587', 'method': 'GET', 'url': '/valid',
             'msg': 'Suggested security header missing: referrer-policy.'},
            {'id': '999100', 'method': 'GET', 'url': '/valid',
             'msg': "Uncommon header(s) 'x-audit-key' found, with contents: value-one."},
            {'id': '999100', 'method': 'GET', 'url': '/valid',
             'msg': "Uncommon header(s) 'refresh' found, with contents: 0;url=/valid."},
        ],
    }]
    normalized = normalize_native_output('web.nikto', json.dumps(report))
    specs = native_observation_finding_specs(
        normalized, observation_kind='web-vulnerability',
        category='web-vulnerability-assessment',
    )
    assert len(specs) == 4
    assert len({s.identity_key for s in specs}) == 4
    assert {s.severity for s in specs} == {'low', 'info'}
    assert {'nikto.013587.content-security-policy',
            'nikto.013587.referrer-policy',
            'nikto.999100.x-audit-key',
            'nikto.999100.refresh'} == {s.rule_id for s in specs}


def test_nikto_vercel_error_on_one_probe_does_not_hide_independent_actionable_finding():
    import json
    from fastapi_app.services.native_finding_projection import native_observation_finding_specs

    raw = json.dumps([{
        'host': 'reserved.example.invalid', 'port': 443,
        'vulnerabilities': [
            {'id': '999100', 'method': 'GET', 'url': '/',
             'msg': "Uncommon header(s) 'x-vercel-error' found, with contents: DEPLOYMENT_NOT_FOUND."},
            {'id': '999001', 'method': 'GET', 'url': '/admin',
             'msg': 'Administrative endpoint is exposed'},
        ],
    }])
    result = normalize_native_output('web.nikto', raw)
    specs = native_observation_finding_specs(
        result, observation_kind='web-vulnerability',
        category='web-vulnerability-assessment',
    )
    assert len(specs) == 2
    assert {spec.severity for spec in specs} == {'info', 'medium'}
    assert 'nikto.999001' in {spec.rule_id for spec in specs}

