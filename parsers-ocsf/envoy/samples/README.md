# Envoy / Istio access log samples

Sources:

- Elastic `istio` integration pipeline test fixtures (Istio default TEXT format
  and the JSON access log):
  https://github.com/elastic/integrations/blob/main/packages/istio/data_stream/access_logs/_dev/test/pipeline/test-access-logs.log,
  https://github.com/elastic/integrations/blob/main/packages/istio/data_stream/access_logs/_dev/test/pipeline/test-access-failed.log and
  https://github.com/elastic/integrations/blob/main/packages/istio/data_stream/access_logs/_dev/test/pipeline/test-access-json-logs.log
  (`istio_text_inbound_200`, `istio_text_ingress_xff`, `istio_text_outbound_200`,
  `istio_text_ipv6`, `istio_text_418_teapot`, `istio_text_503_uh_no_healthy_upstream`,
  `istio_text_404_nr_route_not_found`, `istio_text_400_dpe_codec_error`,
  `istio_text_503_uf_upstream_reset`, `istio_text_0_dc_downstream_disconnect`,
  `json_reviews_200`, `json_ipv6_client`, `json_400_dpe_codec_error`).
- Istio access log docs, the default format and its JSON keys:
  https://istio.io/latest/docs/tasks/observability/logs/access-log/
  (`istio_text_tcp_*`, `istio_text_403_rbac_denied`, `json_tcp_traffic`: the
  same operators for a TCP proxy entry and an RBAC denial,
  `rbac_access_denied_matched_policy[...]` as Envoy's RBAC filter writes it).
- Envoy access log docs, the default format string and its example line:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/observability/access_log/usage
  (`envoy_default_post_204`, and `envoy_default_get_query` and
  `envoy_default_502_uc` in the same format). `json_mtls_principals` adds the
  `%DOWNSTREAM_PEER_URI_SAN%` and `%UPSTREAM_PEER_URI_SAN%` operators from the same
  page to an Istio JSON record.
- `junk.json` is an Envoy application (not access) log line: fallback branch.

Request ids are replaced with `00000000-0000-…` values and public addresses with
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32).
Cluster-internal 10.x / 127.x / 172.17.x addresses are kept as written.
