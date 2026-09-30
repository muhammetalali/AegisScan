global:
  resolve_timeout: 5m
route:
  receiver: aegis-production
  group_by: [alertname, service, severity]
  group_wait: 15s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - matchers: ['alertname="AegisProductionAlertDeliveryAcceptance"']
      receiver: aegis-production
      group_by: [alertname, service, severity, release_sha, acceptance_id]
      group_wait: 1s
      group_interval: 5s
      repeat_interval: 15m
    - matchers: ['severity="critical"']
      receiver: aegis-production
      repeat_interval: 15m
receivers:
  - name: aegis-production
__ALERT_WEBHOOK_CONFIG__
