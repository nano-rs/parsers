# GCP Audit Log samples

`relay_*.json` (NAN-5898): Cloud Audit Log LogEntry lines exactly as the kestrel
GCP relay (sink -> Pub/Sub pull -> Vector -> `/ingest`) delivers them. GKE
Kubernetes API audit arrives here as Cloud Audit Logs (serviceName `k8s.io`),
not as native `audit.k8s.io` events, so it is this parser's, not
kubernetes_audit's.

| File | Branch |
|------|--------|
| `relay_gke_pods_exec.json` | GKE `pods.exec.create` (k8s_cluster, location -> cloud.region) |
| `relay_iam_create_service_account_key.json` | CreateServiceAccountKey by a caller authenticated with an SA key (actor.user.credential_uid) |
| `relay_iamcredentials_generate_access_token.json` | Data Access GenerateAccessToken (Create), callerIp sentinel `gce-internal-ip` as hostname |
| `relay_secretmanager_access_secret_version.json` | Data Access AccessSecretVersion (Read) |
| `relay_sts_exchange_token_wif.json` | STS ExchangeToken by a Workload Identity Federation principal (principalSubject as actor) |
