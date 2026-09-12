from pathlib import Path


ROOT = Path(__file__).parents[1] / 'aegis-platform/backend'


def test_audit_writes_use_the_canonical_append_service():
    violations = []
    for path in ROOT.rglob('*.py'):
        if 'migrations' in path.parts:
            continue
        text = path.read_text(encoding='utf-8')
        if 'AuditLog.objects.create(' in text:
            violations.append(str(path.relative_to(ROOT)))
    assert violations == []
