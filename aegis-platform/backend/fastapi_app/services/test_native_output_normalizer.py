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


def test_exiftool_json_keeps_only_json_scalar_metadata():
    raw = '[{"SourceFile":"/tmp/a.jpg","FileSize":"12 kB","Nested":{"ignored":true}}]'
    result = normalize_native_output('forensics.exiftool', raw)
    assert result['count'] == 1
    attrs = result['observations'][0]['attributes']
    assert attrs['FileSize'] == '12 kB'
    assert 'Nested' not in attrs
