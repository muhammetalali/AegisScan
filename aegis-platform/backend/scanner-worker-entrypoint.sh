#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "scanner-worker-entrypoint must start as uid 0 for capability handoff" >&2
    exit 126
fi

if ! command -v capsh >/dev/null 2>&1; then
    echo "scanner-worker-entrypoint requires capsh for CAP_NET_RAW handoff" >&2
    exit 126
fi

# Docker starts this bootstrap with only NET_RAW + SETUID/SETGID/SETPCAP.
# SETPCAP must remain available until CAP_NET_RAW has been moved into the
# ambient set for the post-drop worker. After that, Celery runs as the
# unprivileged aegis user with only CAP_NET_RAW effective/permitted/ambient;
# NET_ADMIN remains exclusively in the scanner_egress namespace owner.
exec capsh \
    --keep=1 \
    --caps=cap_setpcap,cap_setuid,cap_setgid,cap_net_raw+eip \
    --inh=cap_net_raw \
    --user=aegis \
    --caps=cap_setpcap,cap_net_raw+eip \
    --addamb=cap_net_raw \
    --caps=cap_net_raw+eip \
    --drop=cap_setuid,cap_setgid,cap_setpcap \
    -- -c 'exec celery -A fastapi_app.celery_app worker -l info -c "${SCANNER_WORKER_CONCURRENCY:-2}" -Q scanners'
