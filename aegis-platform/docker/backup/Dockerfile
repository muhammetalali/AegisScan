FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir 'boto3>=1.35,<2' 'cryptography>=42,<47'

WORKDIR /app
COPY scripts/backup_postgres.sh /app/scripts/backup_postgres.sh
COPY scripts/verify_postgres_restore.sh /app/scripts/verify_postgres_restore.sh
COPY scripts/remote_backup.py /app/scripts/remote_backup.py
COPY scripts/remote_backup_service.py /app/scripts/remote_backup_service.py

RUN groupadd --gid 10001 aegis-backup \
    && useradd --uid 10001 --gid aegis-backup --no-create-home --shell /usr/sbin/nologin aegis-backup \
    && chmod 0755 /app/scripts/backup_postgres.sh /app/scripts/verify_postgres_restore.sh \
        /app/scripts/remote_backup.py /app/scripts/remote_backup_service.py

USER 10001:10001
ENTRYPOINT ["python", "/app/scripts/remote_backup_service.py"]
CMD ["schedule"]
