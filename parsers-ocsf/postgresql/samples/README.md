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
| `junk.json` | Malformed input; must fall back without aborting |
