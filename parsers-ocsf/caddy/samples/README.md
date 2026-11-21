# Caddy samples

Every IP, host and user was replaced with documentation values; a bearer
token in the reverse-proxy error sample was replaced with a placeholder.
`ts` values keep microsecond precision: `vector vrl --print-object` rounds
longer floats, which the field-coverage checker would read as an altered
source value.

| File | Branch | Source |
|------|--------|--------|
| `access_200_h2_tls_docs.json` | access log, HTTP/2 over TLS 1.3 | Caddy docs, Logging: https://caddyserver.com/docs/logging (source: https://github.com/caddyserver/website/blob/master/src/docs/markdown/logging.md) |
| `access_404_http11_query.json` | 404, query string, host:port, Referer | derived from the docs example |
| `access_nop_status0_common_log.json` | pre-2.5 `remote_addr`, `common_log`, status 0 (NOP) | Caddy community: https://caddy.community/t/http-status-code-0-in-caddy-logs-for-a-reverse-proxy-with-template/18685 |
| `error_502_reverse_proxy_eof.json` | `http.log.error`, 502, err_id/err_trace | https://caddy.community/t/reverseproxy-statuserror-reverseproxy-go-1269/25869 |
| `access_502_error_level_basic_auth.json` | 5xx access logged at error level, user_id | derived from the thread above and https://caddy.community/t/caddy-access-logs-log-client-errors-at-level-error/22711 |
| `access_post_tls12_trusted_proxy.json` | RFC 3339 `ts`, TLS 1.2 cipher, client_ip != remote_ip | derived from the docs example (time_format iso8601, trusted_proxies) |
| `server_using_config.json` | server log, no logger | https://caddy.community/t/certificate-is-there-but-ssl-always-fail/30408 |
| `server_caddyfile_not_formatted_warn.json` | warn level | same thread |
| `server_admin_endpoint_started.json` | `admin` logger, array field | same thread |
| `server_auto_https_redirects.json` | `http.auto_https` logger | same thread |
| `tls_served_challenge_cert.json` | `tls` logger | https://caddy.community/t/error-obtaining-certificate-after-caddy-restart/11335 |
| `tls_obtain_success.json` | `tls.obtain` success | message as reported in Caddy community threads (e.g. the one above) |
| `reverse_proxy_aborting_error.json` | `http.handlers.reverse_proxy` error | https://caddy.community/t/debugging-aborting-with-incomplete-response/15312 |
| `malformed.json` | not JSON (Base Event fallback) | synthetic |
