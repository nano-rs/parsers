# Doppler activity log samples

Records of `logs` from `GET https://api.doppler.com/v3/logs`, one per file
(https://docs.doppler.com/reference/activity_logs-list). The record shape comes
from a read-only call to the API; the `text` of `secrets_added_updated.json`
follows a real record, the other texts follow the same pattern but are assumed.
Names and e-mails are example or redacted values.

| File | Branch |
|------|--------|
| `secrets_added_updated.json` | "Modified secrets ...": Update, config + project resources |
| `secrets_removed.json` | a removed secret name |
| `service_token_created.json` | "Created service token ...": Create |
| `api_page_not_a_record.json` | a whole API page sent as one line: Base Event fallback (send each record) |
| `malformed.json` | not JSON: Base Event fallback |
