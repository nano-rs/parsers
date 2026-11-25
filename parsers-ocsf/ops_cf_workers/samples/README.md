# Cloudflare Workers trace event samples

Logpush `workers_trace_events` records, copied from nano-main
`tools/ops-tenant/parsers/ops_cf_workers/samples` (the lake-era ops parser this
one replaces), plus `fetch_ok_query_string_kept.json`: the full request URL,
query string included, is kept (the lake parser dropped it; parsers never
withhold values).
