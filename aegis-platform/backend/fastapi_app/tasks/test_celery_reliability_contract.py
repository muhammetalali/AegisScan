from fastapi_app.celery_app import celery_app


def test_celery_worker_loss_redelivery_contract():
    assert celery_app.conf.task_acks_late is True
    assert celery_app.conf.task_reject_on_worker_lost is True
    assert celery_app.conf.task_track_started is True
    assert celery_app.conf.worker_prefetch_multiplier == 1
