# Google Cloud Logging samples

Project IDs use `example-project`, numbers 123456789012, IPs documentation
ranges. Shapes follow the LogEntry reference:
https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry

| File | Branch | Source |
|------|--------|--------|
| `text_payload_docs_pubsub.json` | textPayload, legacy `log` field, labels | decoded LogEntry from https://cloud.google.com/logging/docs/export/pubsub |
| `pubsub_push_wrapper.json` | Pub/Sub push wrapper, base64 `message.data`; the decoded entry's jsonPayload (with a secret key, kept as-is), labels and resource labels spill, the base64 body does not | wrapper fields per https://cloud.google.com/pubsub/docs/push and the page above |
| `cloud_run_request_200.json` | httpRequest (HTTP Activity), trace, spanId | Cloud Run request log fields: https://cloud.google.com/run/docs/logging and HttpRequest: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry#HttpRequest |
| `load_balancer_armor_deny_403.json` | LB httpRequest + LoadBalancerLogEntry, Cloud Armor deny | fields from https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring and https://cloud.google.com/armor/docs/request-logging |
| `load_balancer_backend_502.json` | LB 502, remoteIp with port, referer | same |
| `gke_container_json_payload.json` | k8s_container jsonPayload (Base Event, pass-through) | GKE log fields: https://cloud.google.com/kubernetes-engine/docs/concepts/about-logs |
| `gke_stderr_text_error.json` | k8s_container stderr textPayload, ERROR | same |
| `gce_syslog_default_severity.json` | gce_instance syslog, no severity | Ops Agent syslog: https://cloud.google.com/logging/docs/agent/ops-agent/configuration |
| `cloud_function_operation_critical.json` | operation, trace on a Base Event, CRITICAL | LogEntryOperation in the LogEntry reference |
| `audit_log_on_generic_lane.json` | AuditLog protoPayload (API Activity) | AuditLog: https://cloud.google.com/logging/docs/audit/understanding-audit-logs |
| `app_engine_request_log_proto.json` | non-audit protoPayload (RequestLog) | https://cloud.google.com/appengine/docs/standard/reference/request-response-headers and RequestLog proto |
| `lb_bare_ipv6_endpoints.json` | review regression: bare IPv6 remoteIp / serverIp (`2001:db8::2:8080` is one address, not address + port) | constructed from the HttpRequest reference |
| `lb_bracketed_ipv6_with_port.json` | `[v6]:port` remoteIp / serverIp | constructed |
| `audit_iap_with_http_request_denied.json` | review regression: AuditLog with httpRequest stays API Activity; `granted: false` with no status.code is a failure | IAP audit fields: https://cloud.google.com/iap/docs/audit-log-howto |
| `json_without_logentry_fields.json` | JSON that is not a LogEntry (fallback) | synthetic |
| `malformed.json` | not JSON (fallback) | synthetic |
| `pubsub_push_wrapper_key_collision.json` | review regression: decoded LogEntry has a key the wrapper also has (`subscription`); the wrapper is kept whole, nothing is overwritten | constructed |
| `pubsub_push_collision_secret_kept.json` | review regression: an unmerged Pub/Sub body carrying a credential spills as-is (base64 `message.data`), never overwritten | constructed |
| `pubsub_push_collision_textpayload_secret.json` | review regression: a colliding Pub/Sub entry is not mapped from its unmerged body ; it falls back with the base64 body spilled as-is | constructed |
| `pubsub_push_object_data_secret.json`, `pubsub_push_array_data_secret.json` | review regression: an already-decoded object `data` and an array `data` spill as-is | constructed |

## Sending these logs over Splunk HEC

Send each log to nano as an HEC **string** event (`"event": "<the log, as text>"`),
or post it to nano's `/ingest` endpoint. Both work today.

Do not send these logs as HEC **object** events (`"event": { ... }`). For an
object event, nano currently removes some fields (such as `timestamp` and
`host`) before this parser runs, and it may hand the parser only the event's
`message` field. The event can then get the wrong time or lose fields. A fix is
planned in nano (.36).

For Cloud Logging, a Pub/Sub push envelope sent as an HEC object event reaches the parser as its inner `message` only, so the log entry is not decoded.

## Pub/Sub pull relay samples

`relay_*.json`: raw LogEntry lines as a pull relay delivers them (Cloud
Logging sink -> Pub/Sub pull subscription -> a forwarder such as Vector ->
nano's `/ingest`, one LogEntry per line, no Pub/Sub envelope).

| File | Branch |
|------|--------|
| `relay_l7_lb_rule_request.json` | external Application LB request (HTTP Activity) |
| `relay_gke_api_pino_stdout.json` | GKE container stdout, pino jsonPayload (Base Event) |
| `relay_k8s_event_warning.json` | Kubernetes event (Base Event, WARNING) |
| `relay_cloudsql_postgres_connection.json` | Cloud SQL postgres.log textPayload (Base Event) |
| `relay_cloud_nat_allocation.json` | Cloud NAT flow (Base Event; connection fields spill) |
