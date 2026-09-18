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

if ! command -v setpriv >/dev/null 2>&1; then
    echo "scanner-worker-entrypoint requires setpriv to lock no_new_privs after capability handoff" >&2
    exit 126
fi

if [ -n "${AEGIS_SEMGREP_WORKSPACE_ROOT:-}" ]; then
    if [ "${AEGIS_SEMGREP_WORKSPACE_ROOT}" != "/var/lib/aegis-semgrep" ]; then
        echo "AEGIS_SEMGREP_WORKSPACE_ROOT must be /var/lib/aegis-semgrep" >&2
        exit 126
    fi
    mkdir -p /var/lib/aegis-semgrep
    chown 10001:10001 /var/lib/aegis-semgrep
    chmod 0700 /var/lib/aegis-semgrep
fi

# M6 Nmap retirement is fail-closed at worker startup. Historical parity/reference
# containers omit AEGIS_NMAP_LEGACY_DISABLED and therefore pass without imposing
# production-only trust pins. Production sets the retirement lock and must satisfy
# the governed provider, loopback, authentication, provenance, and image contracts
# before any scanner task process is started.
python -m fastapi_app.services.nmap_retirement_preflight

# M6 Nuclei retirement uses the same startup boundary. Historical parity/reference
# containers omit AEGIS_NUCLEI_LEGACY_DISABLED. Production sets the retirement
# lock and must pin the loopback governed web provider before the worker starts.
python -m fastapi_app.services.nuclei_retirement_preflight

# M6 Semgrep retirement is enforced before Celery can accept scanner tasks.
# Historical parity/reference containers omit AEGIS_SEMGREP_LEGACY_DISABLED.
# Production must pin the governed code provider and retirement workspace.
python -m fastapi_app.services.semgrep_retirement_preflight

# Docker starts this bootstrap with only NET_RAW + SETUID/SETGID/SETPCAP.
# SETPCAP must remain available until CAP_NET_RAW has been moved into the
# ambient set and the temporary bootstrap caps have been removed from the
# bounding set. Only after that bounded handoff do we set no_new_privs, so the
# final Celery process runs as the unprivileged aegis user with exactly
# CAP_NET_RAW effective/permitted/inheritable/bounding/ambient and cannot gain
# privileges through a later exec. NET_ADMIN remains exclusively in the
# scanner_egress namespace owner.
exec capsh \
    --keep=1 \
    --caps=cap_setpcap,cap_setuid,cap_setgid,cap_net_raw+eip \
    --inh=cap_net_raw \
    --user=aegis \
    --caps=cap_setpcap,cap_net_raw+eip \
    --addamb=cap_net_raw \
    --drop=cap_setuid,cap_setgid,cap_setpcap \
    --caps=cap_net_raw+eip \
    -- -c 'exec setpriv --no-new-privs -- celery -A fastapi_app.celery_app worker -l info -c "${SCANNER_WORKER_CONCURRENCY:-2}" -Q scanners'
