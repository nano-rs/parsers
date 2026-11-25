# Cloudflare samples

`firewall_event_graphql_*.json`: zone security events polled from the GraphQL
Analytics API (`firewallEventsAdaptive`, available on the Pro plan) and renamed
to the Logpush `firewall_events` field names by the NAN-5898 dogfood edge
relay. The GraphQL spellings of the action (`managed_challenge`) and of the
query (leading `?`) are what this parser must handle. The other branches are
covered by the inline `samples:` in parser.yaml.

| File | Branch |
|------|--------|
| `firewall_event_graphql_waf_block_sqli.json` | managed WAF block, query string kept in url_string |
| `firewall_event_graphql_managed_challenge_api.json` | rate-limit managed challenge (Denied / Challenge) |
| `firewall_event_graphql_bic_block.json` | Browser Integrity Check block without a rule id (no firewall_rule) |
