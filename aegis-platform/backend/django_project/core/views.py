from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse

import redis


def _redis_url() -> str:
    return settings.REDIS_URL


def health_check(request):
    checks = {
        'database': False,
        'cache': False,
        'redis': False,
    }
    errors = {}

    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        checks['database'] = True
    except Exception as exc:
        errors['database'] = str(exc)

    try:
        cache.set('health_check', 'ok', 10)
        checks['cache'] = cache.get('health_check') == 'ok'
        if not checks['cache']:
            errors['cache'] = 'cache round-trip did not return the expected value'
    except Exception as exc:
        errors['cache'] = str(exc)

    client = None
    try:
        client = redis.from_url(_redis_url(), socket_connect_timeout=3, socket_timeout=3)
        checks['redis'] = client.ping() is True
        if not checks['redis']:
            errors['redis'] = 'redis ping returned false'
    except Exception as exc:
        errors['redis'] = str(exc)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    healthy = all(checks.values())
    payload = {
        'status': 'healthy' if healthy else 'unhealthy',
        'checks': checks,
        'version': '1.0.0',
    }
    if errors:
        payload['errors'] = errors

    return JsonResponse(payload, status=200 if healthy else 503)


def readiness_check(request):
    checks = {
        'database': False,
        'migrations': False,
    }
    errors = {}

    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        checks['database'] = True
    except Exception as exc:
        errors['database'] = str(exc)

    try:
        from django.db.migrations.executor import MigrationExecutor

        executor = MigrationExecutor(connection)
        plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
        checks['migrations'] = len(plan) == 0
        if plan:
            errors['migrations'] = f'{len(plan)} migration operation(s) pending'
    except Exception as exc:
        errors['migrations'] = str(exc)

    ready = all(checks.values())
    payload = {
        'ready': ready,
        'checks': checks,
    }
    if errors:
        payload['errors'] = errors

    return JsonResponse(payload, status=200 if ready else 503)
