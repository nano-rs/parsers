# Cloudflare account audit log samples

Records of the v1 `GET /accounts/{account_id}/audit_logs` API, unchanged
(https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/).
E-mails are redacted or example values (`[redacted]@...` is not a valid address, so it lands on
`name` only), IPs are documentation ranges.

| File | Branch |
|------|--------|
| `login_failed.json` | login, result false: Authentication, Failure, reason |
| `login_success_ipv6.json` | login over IPv6 with a well-formed e-mail |
| `api_token_created.json` | api_token create: API Activity, token name as resource name |
| `dns_record_deleted.json` | DNS_record delete over the API (token actor, no e-mail) |
| `waf_rule_updated.json` | ruleset update with newValue / oldValue |
| `member_added.json` | account_member add |
| `malformed.json` | truncated JSON: Base Event fallback |
