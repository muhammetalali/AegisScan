from __future__ import annotations

import json
from pathlib import Path

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from compliance.models import ComplianceControl, ComplianceFramework

pytestmark = pytest.mark.django_db


def test_import_framework_catalog_is_transactional(tmp_path: Path):
    catalog=tmp_path/'catalog.json'
    catalog.write_text(json.dumps({'framework_type':'iso_27001','name':'ISO/IEC 27001','version':'2022-test','source':'licensed-fixture','controls':[{'control_id':'A.5.1','title':'Policies for information security','description':'Controlled test control','priority':'high','references':['fixture://iso/A.5.1']}]})
    call_command('import_framework_catalog',file=str(catalog))
    framework=ComplianceFramework.objects.get(framework_type='iso_27001',version='2022-test')
    assert framework.controls_count==1
    control=ComplianceControl.objects.get(framework=framework,control_id='A.5.1')
    assert control.metadata['catalog_source']=='licensed-fixture'
    call_command('import_framework_catalog',file=str(catalog))
    assert ComplianceControl.objects.filter(framework=framework).count()==1


def test_import_framework_catalog_rejects_invalid_payload(tmp_path: Path):
    catalog=tmp_path/'invalid.json'; catalog.write_text(json.dumps({'framework_type':'iso_27001'}))
    with pytest.raises(CommandError): call_command('import_framework_catalog',file=str(catalog))
