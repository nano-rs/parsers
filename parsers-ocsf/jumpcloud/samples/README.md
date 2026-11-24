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
- `user_login_attempt_failed_coords_only` carries integer geoip coordinates
  without a country or region (no `location` is emitted; the coordinates spill).
- `mdm_command_result_with_client_ip.json` is a Base Event with `client_ip` and
  `geoip`: Base Event has no `src_endpoint`, so they stay in unmapped.
- `user_update_display_name_only.json` names its user resource by display name
  only: no OCSF `user` (it needs a name or uid); the resource spills.
- `policy_update_type_only.json` is an API Activity whose resource has only a
  type: no `resources[]` entry (it needs a name or uid); the type spills.
- `user_login_attempt_invalid_ip.json` carries a `client_ip` that is not an
  address: no `src_endpoint.ip` (ip_t), the value stays in unmapped.
- `junk.json` is a truncated array for the fallback branch.

Identifiers are replaced: the organization with 24 zeros, addresses with
documentation ranges, users with example.com addresses.
