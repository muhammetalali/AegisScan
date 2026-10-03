from __future__ import annotations

import json
import sys

from django.core.management.base import BaseCommand, CommandError

from fastapi_app.services.web_lab_lifecycle import (
    WebLabLifecycleError,
    due_web_lab_instances,
    get_web_lab_instance,
    host_instance_projection,
    list_web_lab_instances,
    mark_instance_cleaned,
    mark_instance_expired,
    mark_instance_failed,
    register_provisioned_instance,
    verify_lifecycle_chain,
)
from enterprise.web_lab_models import WebLabInstance


class Command(BaseCommand):
    help = 'Trusted operator authority for Web Lab lifecycle records; this command never controls Docker.'

    def add_arguments(self, parser):
        sub = parser.add_subparsers(dest='action', required=True)

        provision = sub.add_parser('provision')
        provision.add_argument('--actor-id', required=True)
        provision.add_argument('--asset-id', required=True)
        provision.add_argument('--lab-definition-id', default='bac-orders-v1')
        provision.add_argument('--container-name', required=True)
        provision.add_argument('--ttl-seconds', required=True, type=int)
        provision.add_argument('--idempotency-key', required=True)
        provision.add_argument('--supersedes-instance-id')

        expire = sub.add_parser('expire')
        expire.add_argument('--actor-id', required=True)
        expire.add_argument('--instance-id', required=True)
        expire.add_argument('--idempotency-key', required=True)

        status = sub.add_parser('status')
        status.add_argument('--actor-id', required=True)
        status.add_argument('--instance-id', required=True)

        cleanup = sub.add_parser('cleanup')
        cleanup.add_argument('--actor-id', required=True)
        cleanup.add_argument('--instance-id', required=True)
        cleanup.add_argument('--observed-container-id', required=True)
        cleanup.add_argument('--reason', required=True, choices=['manual', 'reset', 'expired', 'failed'])
        cleanup.add_argument('--idempotency-key', required=True)

        failed = sub.add_parser('fail')
        failed.add_argument('--actor-id', required=True)
        failed.add_argument('--instance-id', required=True)
        failed.add_argument('--observed-container-id', required=True)
        failed.add_argument('--failure-code', required=True)
        failed.add_argument('--idempotency-key', required=True)

        host = sub.add_parser('host-status')
        host.add_argument('--actor-id', required=True)
        host.add_argument('--instance-id', required=True)

        verify = sub.add_parser('verify-chain')
        verify.add_argument('--actor-id', required=True)
        verify.add_argument('--instance-id', required=True)

        due = sub.add_parser('due')
        due.add_argument('--actor-id', required=True)
        due.add_argument('--project-id', required=True)
        due.add_argument('--limit', type=int, default=100)

        listing = sub.add_parser('list')
        listing.add_argument('--actor-id', required=True)
        listing.add_argument('--project-id', required=True)
        listing.add_argument('--asset-id')
        listing.add_argument('--lab-definition-id')
        listing.add_argument('--limit', type=int, default=25)

    def handle(self, *args, **options):
        action = options['action']
        try:
            if action == 'provision':
                try:
                    inspection = json.load(sys.stdin)
                except (ValueError, TypeError) as exc:
                    raise WebLabLifecycleError(
                        'Provision requires one trusted inspection JSON document on stdin.') from exc
                result = register_provisioned_instance(
                    actor_id=options['actor_id'], asset_id=options['asset_id'],
                    lab_definition_id=options['lab_definition_id'], inspection=inspection,
                    container_name=options['container_name'], ttl_seconds=options['ttl_seconds'],
                    idempotency_key=options['idempotency_key'],
                    supersedes_instance_id=options.get('supersedes_instance_id'),
                )
            elif action == 'expire':
                result = mark_instance_expired(
                    actor_id=options['actor_id'], instance_id=options['instance_id'],
                    idempotency_key=options['idempotency_key'])
            elif action == 'cleanup':
                result = mark_instance_cleaned(
                    actor_id=options['actor_id'], instance_id=options['instance_id'],
                    observed_container_id=options['observed_container_id'],
                    idempotency_key=options['idempotency_key'], reason=options['reason'])
            elif action == 'fail':
                result = mark_instance_failed(
                    actor_id=options['actor_id'], instance_id=options['instance_id'],
                    observed_container_id=options['observed_container_id'],
                    failure_code=options['failure_code'], idempotency_key=options['idempotency_key'])
            elif action == 'status':
                result = get_web_lab_instance(
                    actor_id=options['actor_id'], instance_id=options['instance_id'])
            elif action == 'host-status':
                public = get_web_lab_instance(
                    actor_id=options['actor_id'], instance_id=options['instance_id'])
                row = WebLabInstance.objects.get(pk=public['lifecycle_ref'])
                result = host_instance_projection(row)
            elif action == 'verify-chain':
                result = verify_lifecycle_chain(
                    actor_id=options['actor_id'], instance_id=options['instance_id'])
            elif action == 'due':
                result = due_web_lab_instances(
                    actor_id=options['actor_id'], project_id=options['project_id'],
                    limit=options['limit'])
            elif action == 'list':
                result = list_web_lab_instances(
                    actor_id=options['actor_id'], project_id=options['project_id'],
                    asset_id=options.get('asset_id'), lab_definition_id=options.get('lab_definition_id'),
                    limit=options['limit'])
            else:  # pragma: no cover
                raise WebLabLifecycleError('Unsupported lifecycle action.')
        except WebLabLifecycleError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False))
