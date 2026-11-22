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
- `json_log_native_login_error_client_secret` is Keycloak's native Quarkus JSON
  log layout (`timestamp`, `level`, `loggerName`) around a quoted event line. Its
  `client_secret` detail is synthetic, not a Keycloak field; it spills as-is.
- `junk.json` is truncated JSON; `text_non_event_line` and `json_log_non_event`
  are Keycloak log lines that are not events (fallback branch, text kept).
- `json_log_unparsable_kv_fallback` (review regression) is a native JSON log
  record whose event line does not parse (a trailing `, `): it takes the
  fallback branch with `message` kept, never a Success with empty fields.
- `json_log_forwarder_type_collision_fallback` (review regression) is a JSON
  log record a forwarder tagged with its own top-level `type`: the event line
  collides with it, so the record falls back instead of being read as a REST
  event with `status_id` Success.
- `json_log_collision_secret` and `json_log_unparsable_secret` carry a
  credential in an event line that cannot be unpacked: the record falls back
  and every field, the line included, is kept as-is.
- `json_admin_create_user_with_password`, `json_admin_create_client_with_secret`
  and `json_admin_unparsable_representation` are admin events whose
  `representation` carries a credential (`credentials[].value`, a client
  `secret`) or is truncated JSON: a parsed representation moves whole to
  `representation_json` and spills field by field; truncated text stays as
  written. Admin REST representation fields per
  https://www.keycloak.org/docs-api/latest/rest-api/index.html#UserRepresentation.

UUIDs are replaced with `00000000-0000-…` values, addresses with documentation
ranges, users with example.com addresses.
- Further review regressions, all mapped faithfully (parsers never mask; every
  value lands in OCSF or `unmapped` as written, `raw_data` is the original):
  CredentialRepresentation `{type, value}` (`json_admin_reset_password_credential`,
  `json_admin_reset_password_untyped_credential`, `json_admin_client_secret_regenerated`),
  private keys (`json_admin_client_certificate_private_key`,
  `json_admin_saml_client_private_key_attribute`, `json_admin_rsa_key_provider_component`),
  array representations (`json_admin_credential_array_representation`,
  `json_admin_string_array_representation`), an unquoted representation
  holding `, ` taken whole (`text_admin_unquoted_representation_dn_split`,
  `json_log_admin_unquoted_representation_spaced`), JSON log messages that are
  not clean event lines (`json_log_leading_space_event_secret`,
  `json_log_prefixed_event_secret`, `json_log_error_text_secret`), TRACE lines
  whose `requestUri`, `cookies=[...]` and `stackTrace` tails are cut off whole
  and kept as-is (`text_trace_*`, `json_log_trace_login_cookies_request_uri`,
  including a prefixed line with a multi-line stackTrace,
  `text_trace_multiline_stack_trace`), a `, requestUri=` inside a representation
  or a quoted value (`*_fake_request_uri`), `;jsessionid=` and `data:` URIs,
  `ndc`, Quarkus exceptions and pre-existing `representation_json` keys. Shapes
  per Keycloak's CredentialRepresentation, CertificateRepresentation and
  JBossLoggingEventListenerProvider.
