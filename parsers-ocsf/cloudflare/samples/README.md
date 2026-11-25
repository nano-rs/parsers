# Cloudflare samples

`firewall_event_graphql_*.json`: zone security events polled from the GraphQL
Analytics API (`firewallEventsAdaptive`, available on the Pro plan) and renamed
to the Logpush `firewall_events` field names by the poller that forwards them
(Logpush for firewall events needs an Enterprise zone). The GraphQL spellings of the action (`managed_challenge`) and of the
query (leading `?`) are what this parser must handle. The other branches are
covered by the inline `samples:` in parser.yaml.

| File | Branch |
|------|--------|
| `firewall_event_graphql_waf_block_sqli.json` | managed WAF block, query string kept in url_string |
| `firewall_event_graphql_managed_challenge_api.json` | rate-limit managed challenge (Denied / Challenge) |
| `firewall_event_graphql_bic_block.json` | Browser Integrity Check block without a rule id (no firewall_rule) |
| `logpush_firewall_challenge.json` | Logpush `challenge`: Denied / Challenge (23; was 19, which is Alert in 1.9) |
| `logpush_firewall_log_query_with_question_mark.json` | Logpush `log`: Observed / Logged (was Allowed); a `?` inside the query is kept |
| `http_request_null_bot_score_and_request_bytes.json` | HTTP request with `BotScore` and `ClientRequestBytes` null: no risk_score, only traffic.bytes_in |
| `logpush_firewall_bare_question_mark_query.json` | `ClientRequestQuery` of a bare `?`: no empty `query_string` |
