# Redis samples

Each file is one input event. Addresses are documentation values
(192.0.2.0/24, 198.51.100.0/24).

| File | Source |
|------|--------|
| `server_*.json`, `signal_handler_sigterm.json` | Server log format `pid:role DD Mon YYYY HH:MM:SS.mmm level msg` and the messages themselves (`Redis is starting`, `Ready to accept connections`, `Received SIGTERM scheduling shutdown...`, `is now ready to exit, bye bye...`, `Possible SECURITY ATTACK detected`, `Error accepting a client connection`, `Error loading ACL rule`) from https://github.com/redis/redis/blob/7.2/src/server.c , `networking.c` and `acl.c` |
| `acl_log_auth_failure.json` | The `ACL LOG` example entry from https://redis.io/docs/latest/commands/acl-log/ , as JSON (the field names are the reply's keys) |
| `acl_log_command_denied.json`, `acl_log_key_denied.json` | Same entry shape with `reason` command / key, per the same page |
| `monitor_*.json` | MONITOR output lines from https://redis.io/docs/latest/commands/monitor/ |
| `junk.json` | Malformed input; must fall back without aborting |
