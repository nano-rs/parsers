# Redis samples

Each file is one input event. Addresses are documentation values
(192.0.2.0/24, 198.51.100.0/24).

| File | Source |
|------|--------|
| `server_*.json`, `signal_handler_sigterm.json` | Server log format `pid:role DD Mon YYYY HH:MM:SS.mmm level msg` and the messages themselves (`Redis is starting`, `Ready to accept connections`, `Received SIGTERM scheduling shutdown...`, `is now ready to exit, bye bye...`, `Possible SECURITY ATTACK detected`, `Error accepting a client connection`, `Error loading ACL rule`) from https://github.com/redis/redis/blob/7.2/src/server.c , `networking.c` and `acl.c` |
| `acl_log_auth_failure.json` | The `ACL LOG` example entry from https://redis.io/docs/latest/commands/acl-log/ , as JSON (the field names are the reply's keys) |
| `acl_log_command_denied.json`, `acl_log_key_denied.json` | Same entry shape with `reason` command / key, per the same page |
| `monitor_*.json` | MONITOR output lines from https://redis.io/docs/latest/commands/monitor/ |
| `monitor_ipv6.json`, `monitor_ipv6_loopback.json` | MONITOR with IPv6 clients, which Redis prints bracketed (`[db [ip]:port]`, `anetFormatAddr` in `src/anet.c`) |
| `monitor_config_requirepass.json`, `monitor_acl_setuser.json` | MONITOR lines carrying credentials; the full command, arguments included, is query_info.query_string (parsers never mask) |
| `monitor_long_set.json` | Synthetic 9 KB SET payload: query_info.query_string holds the whole command, never truncated |
| `monitor_config_primaryauth.json` | Valkey `CONFIG SET primaryauth` (replication password, Valkey `src/config.c`); mapped as-is like any command |
| `empty_message.json` | Empty `message`: raw_data stays the empty string |
| `junk.json` | Malformed input; must fall back without aborting |
