# PostgreSQL samples

Each file is one input event. A multi-line sample (DETAIL / STATEMENT
continuations) is what a multiline-aggregating collector delivers. Addresses
and users are documentation values (192.0.2.0/24, 198.51.100.0/24).

| File | Source |
|------|--------|
| `stderr_*.json` | log_line_prefix forms (`%m [%p] %q%u@%d `) and the csvlog / jsonlog field sets from the logging docs: https://www.postgresql.org/docs/current/runtime-config-logging.html . Message texts are the server's own: connection received / authorized / authenticated and disconnection (`src/backend/utils/init/postinit.c`, `src/backend/tcop/postgres.c`, `src/backend/libpq/auth.c`), auth failures (`src/backend/libpq/auth.c`, `hba.c`), `statement:` / `duration:` (log_statement, log_min_duration_statement), checkpoints (`src/backend/access/transam/xlog.c`), ready to accept / shutdown (`src/backend/postmaster/postmaster.c`) at https://github.com/postgres/postgres |
| `rds_prefix_auth_failed.json` | Amazon RDS default prefix `%t:%r:%u@%d:[%p]:`: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.PostgreSQL.html |
| `syslog_prefix_checkpoint.json` | `log_destination = syslog` with the `[line-seq]` prefix |
| `csvlog_*.json` | csvlog column order from the logging docs (section "Using CSV-Format Log Output") |
| `jsonlog_*.json` | jsonlog keys from the logging docs (Table "Keys and Values of JSON Log Entries"), wrapped in `{"message": ...}` because the record has its own `message` key |
| `stderr_space_remote_prefix_auth_failed.json` | Space-delimited `%r` prefix (`%m [%p] %q%u@%d %r `), logging docs `log_line_prefix` |
| `stderr_role_nologin.json` | `role "%s" is not permitted to log in` (NOLOGIN, SQLSTATE 28000), `src/backend/utils/init/miscinit.c` |
| `stderr_privileged_error.json` | COPY TO/FROM PROGRAM privilege error, `src/backend/commands/copy.c` |
| `stderr_iam_user_statement.json` | IAM / Entra ID style user name containing `@` (`%u@%d` then reads `user@domain@db`) |
| `stderr_est_timezone.json` | `%m` with a named `log_timezone` abbreviation (EST) |
| `stderr_long_statement_truncated.json` | Synthetic 12 KB bulk INSERT: query_info.query_string and message hold the whole statement, never truncated |
| `rds_prefix_ipv6_auth_failed.json` | Amazon RDS default prefix with an IPv6 client (`%t:%r:` reads `UTC:2001:db8::1(port):`) |
| `junk.json` | Malformed input; must fall back without aborting |
