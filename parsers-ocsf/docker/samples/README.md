# Docker samples

Each file is one input event. Addresses, hostnames and container IDs are
documentation values (192.0.2.0/24, example.com); timestamps were moved to
2026 except where a line is quoted from a source as is.

| File | Source |
|------|--------|
| `jsonfile_stdout.json` | Verbatim from the json-file logging driver docs: https://docs.docker.com/engine/logging/drivers/json-file/ |
| `jsonfile_stderr_json_body.json`, `jsonfile_attrs_tag.json` | json-file driver record shape from the same page (`log`, `stream`, `time`, `attrs` with `--log-opt tag`), with an application body |
| `daemon_desktop_json.json` | Verbatim from the Docker daemon logs page (Docker Desktop `init.log` JSON): https://docs.docker.com/engine/daemon/logs/ |
| `daemon_logrus_*.json`, `daemon_syslog_error.json` | dockerd logrus text format (`time="..." level=... msg="..."`, https://github.com/sirupsen/logrus#formatters) with messages from moby (`Daemon has completed initialization`, `API listen on`, `Processing signal`, handler errors): https://github.com/moby/moby/blob/master/cmd/dockerd/daemon.go, behind the journald / syslog prefix `journalctl -u docker.service` prints |
| `docker_logs_source_envelope.json` | Vector `docker_logs` source event (`message` plus `container_name`, `container_id`, `image`, `stream`): https://vector.dev/docs/reference/configuration/sources/docker_logs/ |
| `docker_logs_json_container_logrus.json` | Vector `docker_logs` event whose container writes logrus-style JSON (`level`, `msg`), with `stream`, `label` and `container_created_at`: a container Base Event, never a daemon event; the envelope is kept in unmapped.envelope |
| `docker_logs_image_equals_name.json` | Container named after its image (`nginx`): the image is device.container.image.name, never dropped as a duplicate |
| `empty_message.json` | Empty `message`: raw_data stays the empty string |
| `junk.json` | Malformed input; must fall back without aborting |
