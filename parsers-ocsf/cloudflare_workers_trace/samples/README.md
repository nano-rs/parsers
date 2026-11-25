# Cloudflare Workers trace event samples

Logpush `workers_trace_events` records
(https://developers.cloudflare.com/logs/logpush/logpush-job/datasets/account/workers_trace_events/),
with example script names and hosts. Some jobs ship `Event` and `Logs`, some
leave them out; `shipped_fields_*` are records from a job without them, one
with `timestamp_format: rfc3339`. `fetch_ok_query_string_kept.json` shows the
full request URL, query string included, is kept.
