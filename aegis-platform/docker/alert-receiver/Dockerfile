FROM python:3.12-alpine

RUN addgroup -S -g 10003 aegis-alerts \
    && adduser -S -D -H -u 10003 -G aegis-alerts aegis-alerts \
    && mkdir -p /var/lib/aegis-alert-receiver \
    && chown -R 10003:10003 /var/lib/aegis-alert-receiver

COPY scripts/production_alert_receiver.py /usr/local/bin/aegis-alert-receiver
RUN chmod 0755 /usr/local/bin/aegis-alert-receiver

USER 10003:10003
ENTRYPOINT ["python3", "/usr/local/bin/aegis-alert-receiver"]
