global:
  resolve_timeout: 5m
route:
  receiver: aegis-production
  group_by: [alertname, service, severity]
  group_wait: 15s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - matchers: ['severity="critical"']
      receiver: aegis-production
      repeat_interval: 15m
receivers:
  - name: aegis-production
    webhook_configs:
      - url: '__ALERT_WEBHOOK_URL__'
        send_resolved: true
