# MongoDB samples

Sources:

- MongoDB manual, Log Messages (examples for connection accepted / end connection,
  client metadata and slow query):
  https://www.mongodb.com/docs/manual/reference/log-messages/
  (`log_22943_connection_accepted`, `log_22944_connection_ended`,
  `log_51800_client_metadata`, `log_51803_slow_query_find`; the slow query is
  trimmed of some lock and queue counters).
- MongoDB server source, the authentication log lines and their attributes:
  5.0+ `Successfully authenticated` / `Failed to authenticate` (ids 5286306 /
  5286307) in https://github.com/mongodb/mongo/blob/master/src/mongo/db/auth/authentication_session.cpp,
  4.4 `Authentication succeeded` / `Authentication failed` (ids 20250 / 20249) in
  https://github.com/mongodb/mongo/blob/v4.4/src/mongo/db/auth/sasl_commands.cpp
  (`log_5286306_*`, `log_5286307_*`, `log_20250_*`, `log_20249_*`). The error
  texts are from MongoDB Jira SERVER-51457 and SERVER-100979.
- Elastic `mongodb` integration fixture (4.4 startup),
  https://github.com/elastic/integrations/blob/main/packages/mongodb/data_stream/log/_dev/test/pipeline/test-mongodb-ubuntu-4-4-4.log
  (`log_4615611_starting`, `log_23403_build_info`, `log_22943_connection_accepted_44`
  in the 4.4 attribute layout), and the Elastic `mongodb_atlas` fixtures
  https://github.com/elastic/integrations/blob/main/packages/mongodb_atlas/data_stream/mongod_database/_dev/test/pipeline/test-mongod-database.json
  (`log_22120_access_control_warning`, `log_98765_query_error`) and
  https://github.com/elastic/integrations/blob/main/packages/mongodb_atlas/data_stream/mongod_audit/_dev/test/pipeline/test-mongod-audit.json
  (`audit_authenticate`, `audit_logout`, `audit_authcheck_denied`,
  `audit_client_metadata`; `junk` is that fixture's non-JSON line).
- Written in the documented audit message layout (event actions and `param`
  documents), https://www.mongodb.com/docs/manual/reference/audit-message/
  (`audit_authenticate_failed`, `audit_create_user`, `audit_grant_roles`,
  `audit_drop_collection` with the `$numberLong` clock, `audit_shutdown` over a
  unix socket, `audit_replset_reconfig`, and the 4.4 `log_20565_now_exiting`,
  `log_51803_slow_query_update_44`, `log_51803_slow_query_aggregate_error` records).

Audit `uuid` binaries are zeroed, hosts renamed, and public addresses replaced
with documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
