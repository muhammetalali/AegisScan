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
enterprise_ca="${AEGIS_ENTERPRISE_CA_BUNDLE:-}"
if [ -n "$enterprise_ca" ]; then
  case "$enterprise_ca" in
    /*) ;;
    *) echo "AEGIS_ENTERPRISE_CA_BUNDLE must be an absolute path" >&2; exit 2 ;;
  esac
  [ -r "$enterprise_ca" ] || { echo "enterprise CA bundle is not readable" >&2; exit 2; }
  cat /etc/ssl/certs/ca-certificates.crt "$enterprise_ca" > /tmp/aegis-ca-bundle.pem
  chmod 0600 /tmp/aegis-ca-bundle.pem
  export SSL_CERT_FILE=/tmp/aegis-ca-bundle.pem
fi

token_file=/run/secrets/alert-receiver-token
if [ -s "$token_file" ]; then
  export ALERT_WEBHOOK_AUTH_TOKEN_FILE="$token_file"
else
  unset ALERT_WEBHOOK_AUTH_TOKEN_FILE 2>/dev/null || true
fi

python3 /usr/local/lib/aegis/render_alertmanager_config.py \
  --template /etc/aegis-alertmanager/alertmanager.yml.tpl \
  --output /tmp/alertmanager.yml \
  ${allow_http_flag}

exec /usr/local/bin/alertmanager \
  --config.file=/tmp/alertmanager.yml \
  --storage.path=/alertmanager \
  --web.listen-address=0.0.0.0:9093
