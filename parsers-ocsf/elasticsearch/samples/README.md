# Elasticsearch / OpenSearch samples

Sources:

- Elastic `elasticsearch` integration pipeline test fixtures:
  https://github.com/elastic/integrations/blob/main/packages/elasticsearch/data_stream/audit/_dev/test/pipeline/test-audit-logs.log
  (`audit_access_granted`, `audit_anonymous_access_denied_trace`,
  `audit_authentication_success_body`),
  https://github.com/elastic/integrations/blob/main/packages/elasticsearch/data_stream/server/_dev/test/pipeline/test-server-logs.log
  (`server_ecs_info`) and
  https://github.com/elastic/integrations/tree/main/packages/elasticsearch/data_stream/slowlog/_dev/test/pipeline
  (`slowlog_ecs_search`, `slowlog_ecs_indexing`).
- Elasticsearch reference, audit event types (one example per action):
  https://www.elastic.co/guide/en/elasticsearch/reference/current/audit-event-types.html
  (`audit_access_denied`, `audit_anonymous_access_denied`,
  `audit_authentication_failed`, `audit_authentication_success`,
  `audit_realm_authentication_failed`, `audit_connection_denied`,
  `audit_run_as_denied`, `audit_put_user`, `audit_tampered_request`).
- Written in the Elasticsearch 7.x JSON server log and search slow log layout
  documented at https://www.elastic.co/guide/en/elasticsearch/reference/7.17/logging.html
  and https://www.elastic.co/guide/en/elasticsearch/reference/7.17/index-modules-slowlog.html
  (`server_v7_started`, `slowlog_v7_search`). `server_ecs_started`,
  `server_ecs_stopped`, `server_ecs_warn_disk` and `server_ecs_error_exception`
  are 8.x lines in the same ECS layout as the fixtures.
- OpenSearch security plugin audit log, written from the documented categories in
  https://github.com/opensearch-project/documentation-website/blob/main/_security/audit-logs/index.md
  and the field names
  from https://github.com/opensearch-project/security/blob/main/src/main/java/org/opensearch/security/auditlog/impl/AuditMessage.java
  (`opensearch_*`).
- `junk.json` is a pre-7.0 plain-text log line: fallback branch.

Cluster and node ids are replaced with `AAAA…` values, node names genericized,
public addresses replaced with documentation ranges. Records that carry a
`message` key are stored in the `{"message": "<raw line>"}` wrapper.
