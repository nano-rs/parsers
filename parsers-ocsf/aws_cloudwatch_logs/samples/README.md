# AWS CloudWatch Logs samples

Account IDs use 123456789012 / 210987654321 and IPs documentation ranges.

| File | Form | Source |
|------|------|--------|
| `envelope_single_docs_cloudtrail.json` | subscription envelope, one event, truncated (non-JSON) message | AWS docs, Log group-level subscription filters: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html (first logEvent of the example) |
| `envelope_batch_docs_three_events.json` | envelope with three logEvents (kept whole, fallback marker) | same page, verbatim structure |
| `envelope_single_lambda_json.json` | envelope, Lambda JSON log format | Lambda JSON log keys from https://docs.aws.amazon.com/lambda/latest/dg/nodejs-logging.html |
| `control_message_health_check.json` | CONTROL_MESSAGE | message type described in the subscription-filter page above; body as seen in https://www.repost.aws/ja/questions/QUMX33R00RQ7u_1LLBCR5WCw |
| `unnested_lambda_report.json` | `unnest(.logEvents)` form, REPORT line | Lambda docs: https://docs.aws.amazon.com/lambda/latest/dg/monitoring-cloudwatchlogs-view.html |
| `unnested_lambda_runtime_info.json` | unnested, tab-delimited runtime line | same page (Lambda's `\r` line separators written as `\n`: `vector vrl --print-object` prints a raw CR, which splits the checker's output lines) |
| `unnested_vpc_flow_text.json` | unnested, VPC flow text in an arbitrary group | default-format record from https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html |
| `centralized_org_fields.json` | `@aws.account` / `@aws.region` system fields | field names from the subscription-filter page above |
| `get_log_events_start.json` | GetLogEvents event (timestamp, message, ingestionTime) | Lambda docs page above (verbatim event) |
| `filter_log_events_api_gateway_json.json` | FilterLogEvents event (logStreamName, eventId), API Gateway JSON access log | shape from https://docs.aws.amazon.com/cli/latest/reference/logs/filter-log-events.html |
| `forwarder_flat_warn_json.json` | flat forwarder form (logGroup, logStream, id, timestamp, message) | derived from the envelope fields |
| `export_line_s3_nginx.json` | S3 export line (`<RFC 3339> <message>`) | export layout: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/S3Export.html |
| `export_line_s3_json.json` | S3 export line with a JSON message | same |
| `envelope_single_json_secret_array_zero.json` | review regression: one-event envelope with a JSON message holding a secret key, arrays and values equal to mapped ones (`0`, `4`, `"AWS"`); no `unmapped.log_events`, every field under `unmapped.message_json.*`, the secret kept as-is | constructed |
| `envelope_empty_log_events.json` | review regression: `logEvents: []` (fallback "envelope without log events") | constructed |
| `malformed.json` | not a CloudWatch shape (Base Event fallback) | synthetic |
| `forwarder_preexisting_message_json.json` | review regression: an input key `message_json` is kept, never overwritten by the parsed JSON message | constructed |
| `forwarder_unmovable_json_secret_kept.json` | review regression: a JSON message that cannot be moved (input `message_json`) carrying a credential stays whole: echoed in `message` and spilled as-is | constructed |
| `envelope_batch_json_secret_kept.json` | review regression: a multi-event batch whose events carry a credential is kept whole: `logEvents` spills as-is | constructed |
| `envelope_single_json_array_secret.json`, `forwarder_json_array_secret.json`, `export_line_json_array_secret.json` | review regression: a JSON-array message carrying a credential is moved to `message_json`, every value as-is | constructed |
| `forwarder_bom_json_secret.json` | review regression: a JSON message behind a UTF-8 BOM is moved like any other | constructed |
| `forwarder_bom_unmovable_json_secret_kept.json` | review regression: a BOM JSON message that cannot be moved (input `message_json`) is kept as-is in `message` | constructed |
| `forwarder_python_bracket_text.json` | a Python Lambda `[INFO]` line stays text: not mistaken for JSON | constructed |
| `forwarder_unmovable_number_array_secret_kept.json`, `forwarder_truncated_null_array_secret_kept.json`, `export_line_truncated_number_array_secret_kept.json` | review regression: a JSON array opening with a number or `null` that cannot be moved (input `message_json`, or truncated) is kept as-is in `message` | constructed |
| `forwarder_bracketed_timestamp_text.json` | review regression: a Python/Log4j `[2026-11-21 10:00:00,123] INFO` line stays text (not a JSON array) | constructed |
| `forwarder_unmovable_null_array_kept.json` | a valid JSON array that cannot be moved (input `message_json`) is kept as-is in `message` | constructed |
