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
- `json_log_unparsable_kv_fallback` (review regression) is a native JSON log
  record whose event line does not parse (a trailing `, `): it takes the
  fallback branch with `message` kept, never a Success with empty fields.
- `json_log_forwarder_type_collision_fallback` (review regression) is a JSON
  log record a forwarder tagged with its own top-level `type`: the event line
  collides with it, so the record falls back instead of being read as a REST
  event with `status_id` Success.
- `json_log_collision_secret_withheld` and `json_log_unparsable_secret_withheld`
  (review regressions) carry a credential in an event line that cannot be
  unpacked: the line is withheld (byte length + sha256), and the credential
  appears only in `raw_data` (the checker asserts `nan2421-secret` nowhere else).
- `json_admin_create_user_with_password`, `json_admin_create_client_with_secret`
  and `json_admin_unparsable_representation_withheld` (review regressions) are
  admin events whose `representation` carries a credential (`credentials[].value`,
  a client `secret`) or is truncated JSON: the parsed representation spills with
  the credential redacted, the truncated one is withheld, and `nan2421-secret`
  appears only in `raw_data`. Admin REST representation fields per
  https://www.keycloak.org/docs-api/latest/rest-api/index.html#UserRepresentation.

UUIDs are replaced with `00000000-0000-…` values, addresses with documentation
ranges, users with example.com addresses.
- Round-4 review regressions (each carries `nan2421-secret`, which may appear
  only in `raw_data`): `json_admin_reset_password_credential`,
  `json_admin_reset_password_untyped_credential` and
  `json_admin_client_secret_regenerated` (CredentialRepresentation
  `{type, value}`), `json_admin_client_certificate_private_key`,
  `json_admin_saml_client_private_key_attribute` and
  `json_admin_rsa_key_provider_component` (private keys),
  `json_admin_credential_array_representation` and
  `json_admin_string_array_representation` (array representations, withheld
  whole), `text_admin_unquoted_representation_dn_split` and
  `json_log_admin_unquoted_representation_spaced` (an unquoted representation
  holding `, ` is taken whole, never split), and
  `json_log_leading_space_event_secret_withheld`,
  `json_log_prefixed_event_secret_withheld`, `json_log_error_text_secret_withheld`
  (a JSON log message that is not a clean event line is withheld). Shapes per
  Keycloak's CredentialRepresentation, CertificateRepresentation and
  StripSecretsUtils.
- Round-5 review regressions (each carries `nan2421-secret`, allowed only in
  `raw_data`): TRACE jboss-logging lines (`text_trace_login_cookies_request_uri`,
  `json_log_trace_login_cookies_request_uri`, `text_trace_admin_delete_user_cookies`,
  `text_trace_login_error_stack_trace`, `text_trace_admin_create_user_representation`)
  whose `requestUri`, `cookies=[...]` and `stackTrace` tails are cut off whole and
  withheld (requestUri keeps scheme, host and path); and hostile JSON shapes
  (`json_admin_object_representation_with_representation_json`,
  `json_admin_preexisting_representation_json`, `json_log_object_message_secret`,
  `json_log_quarkus_exception_secret`) withheld by the event-field allowlist. Line
  layout per Keycloak's JBossLoggingEventListenerProvider (setKeycloakContext).
