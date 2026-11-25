# Sentry webhook samples

The NAN-5898 dogfood edge relay envelope `{sentry_resource, sentry_timestamp,
payload}` (Sentry sends the resource and send time as Sentry-Hook-Resource /
Sentry-Hook-Timestamp headers). Payload shapes follow
https://docs.sentry.io/organization/integrations/integration-platform/webhooks/.

| File | Branch |
|------|--------|
| `issue_created.json` | issue.created: Detection Finding, Create |
| `issue_resolved.json` | issue.resolved: Detection Finding, Close, Resolved |
| `event_alert_triggered.json` | event_alert.triggered: Detection Finding, alert rule as analytic, event clock |
| `metric_alert_critical.json` | metric_alert.critical: Detection Finding, date_detected clock |
| `installation_deleted.json` | installation.deleted: API Activity, Delete by a user |
| `malformed.json` | truncated JSON: Base Event fallback |
