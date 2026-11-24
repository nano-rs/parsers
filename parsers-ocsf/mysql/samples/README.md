# MySQL / MariaDB samples

Each file is one input event. Slow log entries are multi-line (one per event,
as a multiline-aggregating collector delivers them). Addresses are
documentation values (192.0.2.0/24, 198.51.100.0/24).

| File | Source |
|------|--------|
| `errlog_innodb_note.json`, `errlog_warning_self_signed_ca.json` | Verbatim from the error log format page: https://dev.mysql.com/doc/refman/8.4/en/error-log-format.html |
| `errlog_json_sink.json` | Verbatim `log_sink_json` record from the same page (one line) |
| `errlog_ready_for_connections.json`, `errlog_access_denied.json`, `errlog_error_innodb.json`, `errlog_shutdown_complete.json` | Same format, server messages ER_SERVER_STARTUP_MSG (MY-010931), ER_ACCESS_DENIED_ERROR_WITH_PASSWORD (MY-010926), MY-012592, ER_SERVER_SHUTDOWN_COMPLETE (MY-010910): https://dev.mysql.com/doc/mysql-errors/8.4/en/server-error-reference.html |
| `errlog_mariadb_access_denied.json` | MariaDB error log format: https://mariadb.com/kb/en/error-log/ |
| `genlog_*.json` | General query log (`time thread command argument`): https://dev.mysql.com/doc/refman/8.4/en/query-log.html ; `genlog_init_db.json` is from the percona-toolkit fixture `t/lib/samples/genlogs/genlog001.txt`: https://github.com/percona/percona-toolkit |
| `slowlog_entry.json` | Slow query log entry (header fields per https://dev.mysql.com/doc/refman/8.4/en/slow-query-log.html) |
| `slowlog_percona_multiline.json` | One entry from percona-toolkit `t/lib/samples/slowlogs/slow002.txt` |
| `audit_enterprise_*.json` | MySQL Enterprise Audit JSON connect / query / disconnect records: https://dev.mysql.com/doc/refman/8.4/en/audit-log-file-formats.html (the failed connect is the same shape with `status` 1045) |
| `audit_percona_*.json` | Percona Audit Log plugin JSON (`audit_record`): https://docs.percona.com/percona-server/8.0/audit-log-plugin.html |
| `audit_percona_connect_failed_bracketed.json` | Percona audit failed connect whose `user` is only `[root] @  [ip]` |
| `genlog_connect_proxy_user.json` | General log Connect with the proxy clause (`user@host as proxied on db`): https://dev.mysql.com/doc/refman/8.4/en/proxy-users.html |
| `audit_enterprise_query_data.json` | Enterprise Audit `class: query` record (`query_data`), same format page |
| `genlog_long_query_truncated.json`, `slowlog_long_query_truncated.json` | Synthetic 12 KB bulk INSERT: query_info.query_string holds the whole statement, never truncated |
| `slowlog_admin_command_mariadb.json` | MariaDB slow log entry for `# administrator command: Quit;` with `# Schema:`, `Last_errno`, `Killed`, `Rows_affected`, `Bytes_sent` headers (https://mariadb.com/kb/en/slow-query-log-extended-statistics/): every header kept |
| `empty_message.json` | Empty `message`: raw_data stays the empty string |
| `junk.json` | Malformed input; must fall back without aborting |

## Sending these logs over Splunk HEC

Send each log to nano as an HEC **string** event (`"event": "<the log, as text>"`),
or post it to nano's `/ingest` endpoint. Both work today.

Do not send these logs as HEC **object** events (`"event": { ... }`). For an
object event, nano currently removes some fields (such as `timestamp` and
`host`) before this parser runs, and it may hand the parser only the event's
`message` field. The event can then get the wrong time or lose fields. A fix is
planned in nano (.36).

For MySQL this hits Enterprise Audit JSON records: each has its own `event` and
`timestamp` fields, which nano removes from an object event, so the record is
not parsed. Percona audit records and the error, general and slow logs are not
affected.
