# Traefik samples

Every IP and host was replaced with documentation values (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24, example.com); field layout, status codes,
sizes and durations are as published.

| File | Branch | Source |
|------|--------|--------|
| `clf_304_router_service.json` | `common` access log | Elastic integrations Traefik fixture: https://github.com/elastic/integrations/blob/main/packages/traefik/data_stream/access/_dev/test/pipeline/test-format-common.log |
| `clf_200_http2_dash_referer.json` | unquoted `-` referer, HTTP/2.0 | same fixture |
| `clf_404_backend_not_found_ipv6.json` | IPv6 client, "backend not found" | same fixture |
| `clf_dash_status.json` | `-` status and size | same fixture |
| `generic_clf_no_router.json` | `genericCLF` (no router/service/duration) | same fixture (line truncated to the genericCLF field set) |
| `common_minimal_clf.json` | bare Common Log Format | same fixture |
| `clf_formatter_test_user.json` | client user, `-` request count | Traefik formatter test: https://github.com/traefik/traefik/blob/v3.1.0/pkg/middlewares/accesslog/logger_formatters_test.go |
| `clf_query_string_502.json` | 502 with query string | derived from the `common` template in https://doc.traefik.io/traefik/reference/install-configuration/observability/logs-and-accesslogs/ |
| `json_404_backend_not_found_headers.json` | `json` access log with header fields (v1/v2 Backend* names) | https://github.com/elastic/integrations/blob/main/packages/traefik/data_stream/access/_dev/test/pipeline/test-format-json.log |
| `json_200_backend_url_object.json` | BackendURL object | same fixture |
| `json_ping_internal.json` | `ping@internal` router | same fixture |
| `json_404_kubernetescrd_no_clienthost.json` | ServiceURL object, no ClientHost | same fixture |
| `json_304_origin_header.json` | custom origin/downstream headers | same fixture (one CloudFront id header dropped) |
| `json_ipv6_clienthost.json` | IPv6 `[::1]:port` client | same fixture |
| `json_v3_tls_trace_post.json` | TLSVersion/TLSCipher, trace_id/span_id (v3) | derived from the field list in the Traefik access-log reference above |
| `app_json_v3_provider_error.json` | v3 zerolog JSON application log | Traefik community: https://community.traefik.io/t/constant-error-messages-when-providers-docker-httpclienttimeout-is-set-in-static-config/26045 |
| `app_json_v2_info.json` | v2 logrus JSON application log | message from https://community.traefik.io/t/provider-connection-error-context-deadline-exceeded/20568, rendered in the JSON layout |
| `app_logfmt_v2_error.json` | v2 `common` (logfmt) application log | https://community.traefik.io/t/provider-connection-error-context-deadline-exceeded/20568 |
| `app_console_v3_warn.json` | v3 console application log | derived from the v3 JSON line above, in the console layout |
| `malformed.json` | garbage (Base Event fallback) | synthetic |
