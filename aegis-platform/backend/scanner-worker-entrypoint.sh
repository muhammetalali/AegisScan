#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "scanner-worker-entrypoint must start as uid 0 for capability handoff" >&2
    exit 126
fi

# Docker starts this bootstrap with only NET_RAW + the three capabilities
# required to drop identity/capability state. no-new-privileges is already
# enforced by the container runtime. We retain exactly NET_RAW across the
# uid transition, remove bootstrap capabilities from the bounding set, then
# exec Celery as the unprivileged aegis user with NET_RAW ambient/effective.
exec capsh \
    --keep=1 \
    --inh=cap_net_raw \
    --user=aegis \
    --caps=cap_setpcap,cap_net_raw+eip \
    --drop=cap_setuid,cap_setgid,cap_setpcap \
    --caps=cap_net_raw+eip \
    --addamb=cap_net_raw \
    -- -c 'exec celery -A fastapi_app.celery_app worker -l info -c "${SCANNER_WORKER_CONCURRENCY:-2}" -Q scanners'
