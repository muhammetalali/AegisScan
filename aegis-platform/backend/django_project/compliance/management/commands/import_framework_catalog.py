import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from compliance.models import ComplianceControl, ComplianceFramework


class Command(BaseCommand):
    help = 'Import a licensed/authoritative compliance framework catalog from JSON'

    def add_arguments(self, parser):
        parser.add_argument('--file', required=True, help='JSON catalog file')
        parser.add_argument('--replace', action='store_true', help='Replace controls for the specified framework version')

    def handle(self, *args, **options):
        source = Path(options['file'])
        if not source.exists():
            raise CommandError(f'Catalog file does not exist: {source}')
        try:
            payload = json.loads(source.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as exc:
            raise CommandError(f'Invalid catalog JSON: {exc}') from exc
        for required in ('framework_type', 'name', 'version', 'source', 'controls'):
            if required not in payload:
                raise CommandError(f'Catalog missing required field: {required}')
        framework_type = str(payload['framework_type']).strip()
        if framework_type not in dict(ComplianceFramework.FrameworkType.choices):
            raise CommandError(f'Unsupported framework_type: {framework_type}')
        controls = payload['controls']
        if not isinstance(controls, list) or not controls:
            raise CommandError('Catalog controls must be a non-empty array')
        if len(controls) > 10000:
            raise CommandError('Catalog contains more than 10,000 controls')
        for item in controls:
            if not isinstance(item, dict) or not item.get('control_id') or not item.get('title') or not item.get('description'):
                raise CommandError('Each control requires control_id, title and description')
        with transaction.atomic():
            framework, _ = ComplianceFramework.objects.update_or_create(
                framework_type=framework_type,
                version=str(payload['version']),
                defaults={
                    'name': str(payload['name']),
                    'description': str(payload.get('description') or ''),
                    'is_active': bool(payload.get('is_active', True)),
                    'is_system': bool(payload.get('is_system', True)),
                    'controls_count': len(controls),
                },
            )
            if options['replace']:
                ComplianceControl.objects.filter(framework=framework).delete()
            created = 0
            for item in controls:
                _, was_created = ComplianceControl.objects.update_or_create(
                    framework=framework,
                    control_id=str(item['control_id']),
                    defaults={
                        'title': str(item['title']),
                        'description': str(item['description']),
                        'priority': str(item.get('priority') or ComplianceControl.Priority.HIGH),
                        'category': str(item.get('category') or ''),
                        'related_controls': item.get('related_controls') or [],
                        'references': item.get('references') or [],
                        'implementation_guidance': str(item.get('implementation_guidance') or ''),
                        'testing_procedure': str(item.get('testing_procedure') or ''),
                        'remediation_deadline_days': int(item.get('remediation_deadline_days') or 30),
                        'metadata': {'catalog_source': payload['source'], 'catalog_version': str(payload['version']), **(item.get('metadata') or {})},
                    },
                )
                created += int(was_created)
            framework.controls_count = framework.controls.count()
            framework.save(update_fields=['controls_count', 'updated_at'])
        self.stdout.write(self.style.SUCCESS(f'Imported {len(controls)} controls ({created} new) into {framework.name} v{framework.version} from {payload["source"]}'))
