from __future__ import annotations

import json
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from compliance.models import ComplianceFramework, ComplianceControl

pytestmark = pytest.mark.django_db


def _catalog(framework_type: str) -> dict:
    return {
        'framework_type': framework_type,
        'name': f'Test {framework_type}',
        'version': 'test-1',
        'source': 'licensed-fixture',
        'controls': [{
            'control_id': 'TEST-001',
            'title': 'Controlled test control',
            'description': 'Controlled framework fixture',
            'priority': 'high',
            'references': [f'fixture://{framework_type}/TEST-001'],
        }],
    }


def test_framework_catalog_supports_required_enterprise_frameworks(tmp_path: Path):
    required = [
        ComplianceFramework.FrameworkType.ISO_27001,
        ComplianceFramework.FrameworkType.SOC2,
        ComplianceFramework.FrameworkType.NIST_CSF,
        ComplianceFramework.FrameworkType.NIST_800_53,
        ComplianceFramework.FrameworkType.PCI_DSS,
    ]
    for framework_type in required:
        catalog = tmp_path / f'{framework_type}.json'
        catalog.write_text(json.dumps(_catalog(framework_type)), encoding='utf-8')
        call_command('import_framework_catalog', file=str(catalog))
        framework = ComplianceFramework.objects.get(framework_type=framework_type, version='test-1')
        assert framework.controls_count == 1
        control = ComplianceControl.objects.get(framework=framework, control_id='TEST-001')
        assert control.metadata['catalog_source'] == 'licensed-fixture'


def test_import_framework_catalog_is_idempotent(tmp_path: Path):
    catalog = tmp_path / 'catalog.json'
    catalog.write_text(json.dumps(_catalog(ComplianceFramework.FrameworkType.ISO_27001)), encoding='utf-8')
    call_command('import_framework_catalog', file=str(catalog))
    call_command('import_framework_catalog', file=str(catalog))
    framework = ComplianceFramework.objects.get(framework_type='iso_27001', version='test-1')
    assert ComplianceControl.objects.filter(framework=framework).count() == 1


def test_import_framework_catalog_rejects_invalid_payload(tmp_path: Path):
    catalog = tmp_path / 'invalid.json'
    catalog.write_text(json.dumps({'framework_type': 'iso_27001'}), encoding='utf-8')
    with pytest.raises(CommandError):
        call_command('import_framework_catalog', file=str(catalog))
