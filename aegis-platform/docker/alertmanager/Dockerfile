FROM prom/alertmanager:v0.34.0 AS upstream

FROM python:3.12-alpine

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10003 aegis-monitoring \
    && adduser -S -D -H -u 10003 -G aegis-monitoring aegis-monitoring \
    && mkdir -p /alertmanager /etc/aegis-alertmanager \
    && chown -R 10003:10003 /alertmanager /etc/aegis-alertmanager

COPY --from=upstream /bin/alertmanager /usr/local/bin/alertmanager
COPY --from=upstream /bin/amtool /usr/local/bin/amtool
COPY scripts/render_alertmanager_config.py /usr/local/lib/aegis/render_alertmanager_config.py
COPY monitoring/alertmanager.yml.tpl /etc/aegis-alertmanager/alertmanager.yml.tpl
COPY docker/alertmanager/entrypoint.sh /usr/local/bin/aegis-alertmanager-entrypoint

RUN chmod 0755 /usr/local/bin/alertmanager /usr/local/bin/amtool /usr/local/bin/aegis-alertmanager-entrypoint \
    && chmod 0644 /usr/local/lib/aegis/render_alertmanager_config.py /etc/aegis-alertmanager/alertmanager.yml.tpl

USER 10003:10003
ENTRYPOINT ["/usr/local/bin/aegis-alertmanager-entrypoint"]
