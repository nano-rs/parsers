# Sentry webhook samples

One delivery per file: Sentry's JSON body exactly as signed (the resource is
not in the body; the parser reads it from `data.*`).
`envelope_issue_created.json` is the same delivery in a relay envelope
`{sentry_resource, sentry_timestamp, payload}`, which is also accepted. Shapes
follow https://docs.sentry.io/integrations/integration-platform/webhooks/.

| File | Branch |
|------|--------|
| `issue_created.json` | issue.created: Detection Finding, Create, time = firstSeen |
| `issue_resolved.json` | issue.resolved: Detection Finding, Close, no clock (time received) |
| `event_alert_triggered.json` | event_alert.triggered: Detection Finding, alert rule as analytic, event clock |
| `metric_alert_critical.json` | metric_alert.critical: Detection Finding, date_detected clock |
| `installation_deleted.json` | installation.deleted: API Activity, Delete by a user, time received |
| `envelope_issue_created.json` | relay envelope form |
| `malformed.json` | truncated JSON: Base Event fallback |
| `metric_alert_resolved.json` | metric_alert.resolved: Close, time = date_closed |
| `error_created_datetime_only.json` | error.created: Detection Finding, time from datetime (no numeric timestamp) |
