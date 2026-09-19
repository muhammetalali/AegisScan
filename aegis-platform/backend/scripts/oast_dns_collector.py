from __future__ import annotations

import os
import signal
import sys

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_project.settings')

import django

django.setup()

from fastapi_app.services.oast_dns_collector import start_dns_collector


def main() -> int:
    host = os.getenv('OAST_DNS_BIND_HOST', '0.0.0.0').strip() or '0.0.0.0'
    try:
        port = int(os.getenv('OAST_DNS_BIND_PORT', '53535'))
    except ValueError as exc:
        raise SystemExit('OAST_DNS_BIND_PORT must be an integer') from exc
    server = start_dns_collector(host, port)

    def stop(_signum, _frame):
        server.shutdown()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f'OAST_DNS_COLLECTOR_LISTENING={server.server_address[0]}:{server.server_address[1]}', flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
