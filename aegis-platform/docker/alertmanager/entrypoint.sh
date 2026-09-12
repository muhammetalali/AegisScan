#!/bin/sh
set -eu

case "${AEGIS_ALLOW_HTTP_ALERT_WEBHOOK:-false}" in
  1|true|TRUE|yes|YES|on|ON)
    allow_http_flag="--allow-http-for-test"
    ;;
  0|false|FALSE|no|NO|off|OFF|"")
    allow_http_flag=""
    ;;
  *)
    echo "AEGIS_ALLOW_HTTP_ALERT_WEBHOOK must be a boolean value" >&2
    exit 2
    ;;
esac

umask 077
python3 /usr/local/lib/aegis/render_alertmanager_config.py \
  --template /etc/aegis-alertmanager/alertmanager.yml.tpl \
  --output /tmp/alertmanager.yml \
  ${allow_http_flag}

exec /usr/local/bin/alertmanager \
  --config.file=/tmp/alertmanager.yml \
  --storage.path=/alertmanager \
  --web.listen-address=0.0.0.0:9093
