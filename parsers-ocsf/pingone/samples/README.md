# PingOne audit activity samples

Sources:

- Elastic `ping_one` integration pipeline test fixture,
  https://github.com/elastic/integrations/blob/main/packages/ping_one/data_stream/audit/_dev/test/pipeline/test-pipeline-audit.log
  (`group_deleted`, `member_of_group_created`, `password_check_failed`,
  `password_check_succeeded`, `password_reset`, `policy_created`,
  `role_assignment_created`, `secret_read`, `user_access_allowed`,
  `user_created`, `user_deleted`, `user_updated`).
- PingOne Platform API audit reporting events reference (the activity data
  model and the action.type list), https://developer.pingidentity.com/pingone-api/platform/reference/audit-reporting-events.html.
  `user_access_denied`, `otp_check_failed` and `user_locked` are built on that
  data model for action types the fixture does not carry (`USER.ACCESS_DENIED`,
  `OTP.CHECK_FAILED`, `PASSWORD.LOCKED`), with `result.status` `FAILED`.
- `junk.json` is a non-JSON line for the fallback branch.

Identifiers are replaced: environment ids with the zero UUID, other UUIDs with
`00000000-0000-4000-8000-…`, addresses with 198.51.100.0/24 and 203.0.113.0/24,
users with example.com addresses.
