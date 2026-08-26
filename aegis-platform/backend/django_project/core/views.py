from django.http import JsonResponse
from django.db import connection
from django.core.cache import cache
import redis

def health_check(request):
    checks = {
        'database': False,
        'cache': False,
        'redis': False,
    }
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        checks['database'] = True
    except Exception:
        pass

    try:
        cache.set('health_check', 'ok', 10)
        checks['cache'] = cache.get('health_check') == 'ok'
    except Exception:
        pass

    try:
        r = redis.from_url('redis://localhost:6379/0')
        r.ping()
        checks['redis'] = True
    except Exception:
        pass

    healthy = all(checks.values())
    status_code = 200 if healthy else 503

    return JsonResponse({
        'status': 'healthy' if healthy else 'unhealthy',
        'checks': checks,
        'version': '1.0.0',
    }, status=status_code)

def readiness_check(request):
    checks = {
        'database': False,
        'migrations': False,
    }
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
        checks['database'] = True
    except Exception:
        pass

    try:
        from django.db.migrations.executor import MigrationExecutor
        executor = MigrationExecutor(connection)
        plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
        checks['migrations'] = len(plan) == 0
    except Exception:
        pass

    ready = all(checks.values())
    status_code = 200 if ready else 503

    return JsonResponse({
        'ready': ready,
        'checks': checks,
    }, status=status_code)