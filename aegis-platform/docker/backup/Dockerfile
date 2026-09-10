FROM postgres:16-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/aegis-venv/bin:$PATH

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/aegis-venv \
    && /opt/aegis-venv/bin/pip install --no-cache-dir 'boto3>=1.35,<2' 'cryptography>=42,<47' \
    && test "$(pg_dump --version | awk '{print $3}' | cut -d. -f1)" = "16" \
    && test "$(pg_restore --version | awk '{print $3}' | cut -d. -f1)" = "16"

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
ENTRYPOINT ["python3", "/app/scripts/remote_backup_service.py"]
CMD ["schedule"]
