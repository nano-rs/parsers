# JumpCloud Directory Insights samples

Sources:

- Elastic `jumpcloud` integration pipeline test fixture,
  https://github.com/elastic/integrations/blob/main/packages/jumpcloud/data_stream/events/_dev/test/pipeline/test-events.json
  (`user_login_attempt`, `admin_login_attempt`, `mdm_command_result`, the last
  trimmed of its profile list).
- JumpCloud Directory Insights API reference (OpenAPI with the per-service
  attribute tables and event type lists),
  https://docs.jumpcloud.com/api/insights/directory/1.0/index.html and
  https://docs.jumpcloud.com/new/api/insights/directory/index.yaml.
  `admin_login_attempt_failed` is the documented example response with
  `success` false; `sso_auth`, `radius_auth_failed`, `ldap_bind`,
  `systems_user_login`, `systemuser_update`, `passwordmanager_enable` use the
  documented example values of each service's attribute table; `user_create`,
  `user_lockout`, `user_admin_granted` and `group_create` use documented
  directory event types with the documented `resource` / `initiated_by` shapes.
- `junk.json` is a truncated array for the fallback branch.

Identifiers are replaced: the organization with 24 zeros, addresses with
documentation ranges, users with example.com addresses.
