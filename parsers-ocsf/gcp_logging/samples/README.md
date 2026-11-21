# Google Cloud Logging samples

Project IDs use `example-project`, numbers 123456789012, IPs documentation
ranges. Shapes follow the LogEntry reference:
https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry

| File | Branch | Source |
|------|--------|--------|
| `text_payload_docs_pubsub.json` | textPayload, legacy `log` field, labels | decoded LogEntry from https://cloud.google.com/logging/docs/export/pubsub |
| `pubsub_push_wrapper.json` | Pub/Sub push wrapper, base64 `message.data` | wrapper fields per https://cloud.google.com/pubsub/docs/push and the page above |
| `cloud_run_request_200.json` | httpRequest (HTTP Activity), trace, spanId | Cloud Run request log fields: https://cloud.google.com/run/docs/logging and HttpRequest: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#HttpRequest |
| `load_balancer_armor_deny_403.json` | LB httpRequest + LoadBalancerLogEntry, Cloud Armor deny | fields from https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring and https://cloud.google.com/armor/docs/request-logging |
| `load_balancer_backend_502.json` | LB 502, remoteIp with port, referer | same |
| `gke_container_json_payload.json` | k8s_container jsonPayload (Base Event, pass-through) | GKE log fields: https://cloud.google.com/kubernetes-engine/docs/concepts/about-logs |
| `gke_stderr_text_error.json` | k8s_container stderr textPayload, ERROR | same |
| `gce_syslog_default_severity.json` | gce_instance syslog, no severity | Ops Agent syslog: https://cloud.google.com/logging/docs/agent/ops-agent/configuration |
| `cloud_function_operation_critical.json` | operation, trace on a Base Event, CRITICAL | LogEntryOperation in the LogEntry reference |
| `audit_log_on_generic_lane.json` | AuditLog protoPayload (API Activity) | AuditLog: https://cloud.google.com/logging/docs/audit/understanding-audit-logs |
| `app_engine_request_log_proto.json` | non-audit protoPayload (RequestLog) | https://cloud.google.com/appengine/docs/standard/reference/request-response-headers and RequestLog proto |
| `json_without_logentry_fields.json` | JSON that is not a LogEntry (fallback) | synthetic |
| `malformed.json` | not JSON (fallback) | synthetic |
