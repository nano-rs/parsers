# HAProxy samples

One file per format branch. Every IP, host and name was replaced with
documentation values (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
2001:db8::/32, example.com / example.org); timers, counters, flags and
layout are as published.

| File | Branch | Source |
|------|--------|--------|
| `http_200_captured_header.json` | `option httplog`, captured request header | HAProxy 2.8 configuration manual, section 8.2.3 (HTTP log format): https://github.com/haproxy/haproxy/blob/v2.8.0/doc/configuration.txt |
| `https_tls_block.json` | `option httpslog` TLS fields | same manual, section 8.2.4 (HTTPS log format) |
| `http_logasap_absolute_url.json` | `logasap` (`+` timers/bytes), absolute URL, pipe-separated captures | same manual, section 8.8 (capturing HTTP headers) |
| `http_502_proxy_blocked_no_syslog.json` | `PH--` proxy-generated 502, no syslog header | same manual, section 8.9 (examples of logs) |
| `http_408_client_timeout.json` | `<NOSRV>`, `-1` timers, empty request | same manual, section 8.9 |
| `http_503_retries_head.json` | `SC--` after retries, HEAD | same manual, section 8.9 |
| `http_304_pipe_headers.json` | captured headers with empty slots | Elastic integrations HAProxy test fixture: https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-haproxy.log |
| `http_options_host_token.json` | extra token after server (custom httplog), `-:port` client | same fixture |
| `http_503_nosrv_no_headers.json` | no captures at all | https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-httplog-no-headers.log |
| `http_503_request_header_only.json` | request captures only | same fixture |
| `http_400_badreq.json` | `<BADREQ>` | https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-haproxy-bad-req.log |
| `http_post_syslog_pri_ipv6.json` | RFC 3164 PRI, IPv6 client | derived from the manual's HTTP format (8.2.3) with a PRI header and an IPv6 client |
| `tcp_normal_close.json` | `option tcplog`, normal close | manual section 8.2.2 (TCP log format) |
| `tcp_server_connect_fail.json` | `SC` connect failure | https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-tcplog.log |
| `tcp_client_timeout_bare.json` | `cD` timeout, no syslog header | same fixture |
| `tcp_colon_names_bare.json` | backend/server names containing `:` | same fixture |
| `error_ssl_handshake.json` | default `error-log-format` | manual section 8.2.5 (error log format); also https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-error.log |
| `default_connect_from.json` | default log format ("Connect from") | manual section 8.2.1; https://github.com/elastic/integrations/blob/main/packages/haproxy/data_stream/log/_dev/test/pipeline/test-default.log |
| `malformed.json` | startup notice, not a traffic line (Base Event fallback) | HAProxy startup message |
