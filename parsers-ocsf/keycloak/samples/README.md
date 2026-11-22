# Keycloak event samples

Sources:

- Elastic `keycloak` integration pipeline test fixtures,
  https://github.com/elastic/integrations/blob/main/packages/keycloak/data_stream/log/_dev/test/pipeline/test-log.log
  (every `text_*` sample except `text_quoted_login_error_kc26`) and
  https://github.com/elastic/integrations/blob/main/packages/keycloak/data_stream/log/_dev/test/pipeline/test-ecs-log.log
  (the JSON log envelope of `json_log_login_ecs` and `json_log_non_event`).
- Keycloak source: the jboss-logging listener line format (quoted values,
  realmName), https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/events/log/JBossLoggingEventListenerProvider.java
  (`text_quoted_login_error_kc26`, and the event line inside `json_log_login_ecs`);
  the REST representations EventRepresentation and AdminEventRepresentation,
  https://github.com/keycloak/keycloak/tree/main/core/src/main/java/org/keycloak/representations/idm
  (every other `json_*` sample); event type names from
  https://github.com/keycloak/keycloak/blob/main/server-spi-private/src/main/java/org/keycloak/events/EventType.java.
- `json_log_native_login_error_redaction` is Keycloak's native Quarkus JSON
  log layout (`timestamp`, `level`, `loggerName`) around a quoted event line. Its
  `client_secret` detail is a synthetic redaction probe, not a Keycloak field.
- `junk.json` is truncated JSON; `text_non_event_line` and `json_log_non_event`
  are Keycloak log lines that are not events (fallback branch).

UUIDs are replaced with `00000000-0000-…` values, addresses with documentation
ranges, users with example.com addresses.
