# Zscaler Private Access (LSS JSON) samples

Sources:

- Elastic `zscaler_zpa` integration pipeline test fixtures:
  - https://github.com/elastic/integrations/blob/main/packages/zscaler_zpa/data_stream/user_activity/_dev/test/pipeline/test-user-activity.log
    (`user_activity_lss_client_active`, `user_activity_active`, `user_activity_open`)
  - https://github.com/elastic/integrations/blob/main/packages/zscaler_zpa/data_stream/user_status/_dev/test/pipeline/test-user-status.log
    (`user_status_lss_client`, `user_status_authenticated`, `user_status_ip_anchoring`)
  - https://github.com/elastic/integrations/blob/main/packages/zscaler_zpa/data_stream/app_connector_status/_dev/test/pipeline/test-app-connector-status.log
    (`app_connector_status_control`, `app_connector_status_log`)
- Session status and InternalReason codes as listed by Google SecOps' ZPA
  parser documentation, https://docs.cloud.google.com/chronicle/docs/ingestion/default-parsers/zscaler-zpa.
  `user_activity_rejected_by_policy` (`BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY`),
  `user_activity_closed_from_client` (`BRK_MT_CLOSED_FROM_CLIENT`),
  `user_status_disconnected` (`ZPN_STATUS_DISCONNECTED`) and
  `user_status_auth_failed` (`ZPN_STATUS_AUTH_FAILED`) are the fixture records
  with those documented codes.
- `user_activity_setup_fail_app_not_found` (`BRK_MT_SETUP_FAIL_APP_NOT_FOUND`),
  `user_activity_zia_blocked_by_inspection` (`ZIA_MT_BLOCKED_BY_INSPECTION`) and
  `user_activity_terminated_idle_timeout` (`BRK_MT_TERMINATED_IDLE_TIMEOUT`) are
  the same fixture record with those codes: Fail with an unknown action,
  Refuse + Denied, and a successful Close.
- `non_zpa_json_object` is a JSON object with no LSS field (fallback branch).
- `user_activity_placeholder_ips` has `ServerIP` and `ConnectorIP` set to "-":
  neither becomes an `ip_t` attribute (the server address comes from `Host`).
- `user_status_placeholder_ips` has `PublicIP` 0.0.0.0 and `PrivateIP` "-": no
  `src_endpoint` (it would have no address); the values stay in unmapped.
- `junk.json` is a non-JSON line for the fallback branch.

Addresses are replaced with documentation ranges, users with example.com, the
customer name with "Example Corp".
