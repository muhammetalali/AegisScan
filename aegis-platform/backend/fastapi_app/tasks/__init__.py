"""Celery task package.

Importing any task submodule must first initialize AegisScan's canonical Celery
application.  Scanner tasks use :func:`celery.shared_task`; without this
bootstrap, a web process can bind those task proxies to Celery's implicit
default app before ``fastapi_app.celery_app`` is imported.  Once scanner work is
isolated onto a dedicated queue, that silently publishes work to an unconsumed
queue and leaves persisted scans stuck in ``queued``.

We intentionally do *not* import task modules here.  Celery still discovers them
through the canonical app's ``imports`` configuration, while every producer that
imports ``fastapi_app.tasks.<module>`` first receives the same broker and routing
configuration as the workers.
"""

from fastapi_app.celery_app import celery_app as _celery_app

# Celery's current app is thread-local.  Setting the canonical application as the
# process default ensures shared-task proxies resolve to AegisScan's configured
# app even when producer code executes in a different thread/context.
_celery_app.set_default()
