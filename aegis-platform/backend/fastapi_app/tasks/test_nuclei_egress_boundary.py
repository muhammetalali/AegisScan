from __future__ import annotations

from types import SimpleNamespace

from fastapi_app.tasks import finding_validation


def test_nuclei_finding_revalidation_disables_redirects(monkeypatch, tmp_path):
    template = tmp_path / 'template.yaml'
    template.write_text(
        'id: synthetic\ninfo:\n  name: synthetic\n  author: test\n  severity: info\n',
        encoding='utf-8',
    )
    command = []

    def run(args, **kwargs):
        command.extend(args)
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setenv('NUCLEI_TEMPLATES_DIR', str(tmp_path))
    monkeypatch.setattr(finding_validation.shutil, 'which', lambda _name: '/usr/local/bin/nuclei')
    monkeypatch.setattr(finding_validation.subprocess, 'run', run)

    finding_validation._run_nuclei_template(
        'https://approved.example',
        str(template),
        timeout=15,
    )

    assert '-dr' in command
    assert command[command.index('-u') + 1] == 'https://approved.example'
