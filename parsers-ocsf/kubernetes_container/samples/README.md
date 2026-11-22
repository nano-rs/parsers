# Kubernetes container log samples

Each file is one input event. Addresses, node names, pod UIDs and container IDs
are documentation values (192.0.2.0/24, example.com).

| File | Source |
|------|--------|
| `cri_full_line.json`, `cri_partial_line.json` | Verbatim from the kubelet CRI logging proposal: https://github.com/kubernetes/design-proposals-archive/blob/main/node/kubelet-cri-logging.md |
| `jsonfile_docker_driver.json` | Verbatim Docker json-file record quoted in the same proposal |
| `cri_stderr_klog_error.json` | CRI line carrying a klog header (`E1120 ...`): https://github.com/kubernetes/klog |
| `cri_json_body.json` | CRI line carrying a JSON application body |
| `cri_with_pods_path.json`, `cri_with_containers_path.json` | CRI line with the kubelet log file path (`/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log`, `/var/log/containers/<pod>_<ns>_<container>-<id>.log`): https://kubernetes.io/docs/concepts/cluster-administration/logging/ |
| `fluentbit_kubernetes_metadata.json` | Fluent Bit kubernetes filter record (`kubernetes.pod_name`, `namespace_name`, `pod_id`, `host`, `container_name`, `docker_id`, `container_image`): https://docs.fluentbit.io/manual/pipeline/filters/kubernetes |
| `vector_kubernetes_logs.json` | Vector `kubernetes_logs` source event (`kubernetes.pod_namespace`, `pod_name`, `pod_uid`, `pod_node_name`, `container_id`, `container_image_id`, ...): https://vector.dev/docs/reference/configuration/sources/kubernetes_logs/ |
| `vector_kubernetes_logs_container_only.json` | Vector `kubernetes_logs` envelope that names only the container |
| `jsonfile_json_body.json` | json-file record whose `log` is a JSON body: moved, parsed, to log_json |
| `vector_file_source_envelope.json` | Vector `file` source CRI line: `file` (with its restart index `3.log`), `host`, `stream`, `source_type` kept in unmapped.envelope |
| `empty_message.json` | Empty `message`: raw_data stays the empty string |
| `junk.json` | Malformed input; must fall back without aborting |
