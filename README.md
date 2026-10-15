# nano Community Parsers

A collection of VRL parsers for nano log source ingestion. Every parser emits
[OCSF 1.9](https://schema.ocsf.io) records for nano's OCSF lake.

## Branches

| Branch | Content | For |
|--------|---------|-----|
| `main` | OCSF 1.9 parsers (`parsers-ocsf/`) and `enrichments/` | nano (the OCSF lake) |
| `legacy/clickhouse` | Archive: the UDM parsers (`parsers/`) plus the older OCSF parsers | The retired ClickHouse edition |
| `ocsf-1.9` | Frozen copy of the OCSF 1.9 parsers | Installs that still pin it; it receives no new parsers, use `main` |

Legacy ClickHouse-edition users should point their parser repository at
`legacy/clickhouse` or migrate to the OCSF lake. That branch is an archive for
anyone who wants to go back and maintain their own parsers; it is not updated.

## Available Parsers

### Endpoint

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [CrowdStrike Falcon](parsers-ocsf/crowdstrike_falcon) | `crowdstrike_falcon` | CrowdStrike | JSON (FDR + Streaming API) | 25+ event types: ProcessRollup2, NetworkConnect, DnsRequest, FileWrite, UserLogon, DetectionSummary, and more |
| [SentinelOne](parsers-ocsf/sentinelone) | `sentinelone` | SentinelOne | JSON | Threats, activity logs, Deep Visibility (process, network, DNS, file, registry) |
| [VMware Carbon Black](parsers-ocsf/carbon_black) | `carbon_black` | VMware | JSON | CB Analytics alerts, watchlist hits, process events with MITRE TTPs |
| [Microsoft Defender EDR](parsers-ocsf/defender_edr) | `defender_edr` | Microsoft | JSON | Process creation, network connections, file events, logon activities |
| [Microsoft Sysmon](parsers-ocsf/windows_sysmon) | `windows_sysmon` | Microsoft | JSON (Vector/Winlogbeat/NXLog) | Process, network, file, registry, DNS events from Sysmon |
| [Microsoft Sysmon (XML)](parsers-ocsf/sysmon_xml) | `windows_sysmon` | Microsoft | Native XML | All 29 Sysmon event IDs with hash splitting and MITRE extraction |
| [Microsoft Sysmon for Linux (XML)](parsers-ocsf/sysmon_linux_xml) | `linux_sysmon` | Microsoft | Native XML | Sysmon for Linux: process, network, file events with MITRE extraction |
| [Windows Event Log](parsers-ocsf/windows_event) | `windows_event` | Microsoft | Winlogbeat/NXLog JSON | 24+ EventIDs: logon, process, service, Kerberos, account mgmt |
| [Windows Event Log (XML)](parsers-ocsf/windows_event_xml) | `windows_event` | Microsoft | Native XML | 30+ EventIDs parsed from raw Windows Event XML |
| [Windows Event Log (Text)](parsers-ocsf/windows_event_text) | `windows_event` | Microsoft | Rendered text | Splunk UF / wevtutil format with section-aware body parsing |
| [Linux auditd](parsers-ocsf/linux_auditd) | `linux_auditd` | Linux | key=value | SYSCALL, EXECVE, PATH, USER_AUTH, USER_LOGIN, AVC (SELinux), NETFILTER |
| [systemd-journald](parsers-ocsf/linux_journald) | `linux_journald` | systemd | JSON (journalctl -o json) | Priority, facility, unit, originating process, transport; sshd, sudo and netfilter sub-parsing |
| [LimaCharlie EDR](parsers-ocsf/limacharlie) | `limacharlie` | LimaCharlie | JSON | Sensor telemetry: process, network, DNS, file, module, registry, auth, detections |
| [Moat](parsers-ocsf/moat_edr) | `moat_edr` | Omarchy | JSON (NDJSON envelope) | Supply-chain sensor: alerts with correlation chains and AI triage, alert updates, package-install receipts, shipper heartbeat, plus the opt-in process / network / file telemetry classes. OCSF only |

### Network & Firewall

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Palo Alto PAN-OS](parsers-ocsf/palo_alto) | `palo_alto` | Palo Alto Networks | CSV syslog | TRAFFIC, THREAT, SYSTEM, CONFIG, USERID, GlobalProtect, HIP, AUTH |
| [Fortinet FortiGate](parsers-ocsf/fortinet) | `fortinet` | Fortinet | key=value syslog | Traffic, UTM (webfilter, app-ctrl, DNS, IPS, virus), event |
| [Cisco ASA](parsers-ocsf/cisco_asa) | `cisco_asa` | Cisco | Syslog message codes | 30+ message IDs: connections, ACL, NAT, VPN, IPS, auth |
| [Check Point](parsers-ocsf/checkpoint) | `checkpoint` | Check Point | RFC 5424 + LEA | Firewall rules, NAT, VPN, threat prevention, system |
| [Sophos Firewall](parsers-ocsf/sophos) | `sophos` | Sophos | key=value syslog | Firewall, content filtering, AV, ATP, IDP, anti-spam, WAF |
| [Juniper SRX](parsers-ocsf/juniper_srx) | `juniper_srx` | Juniper | RFC 5424 structured data | RT_FLOW sessions, RT_IDP attacks, RT_UTM events |
| [Cisco Meraki](parsers-ocsf/meraki) | `meraki` | Cisco | Syslog | MX firewall flows, IDS alerts, URL filtering, wireless, VPN |
| [MikroTik RouterOS](parsers-ocsf/routeros) | `routeros` | MikroTik | RFC 3164 syslog | DNS queries/answers, user login/logout/failure, firewall flows, DHCP leases |
| [SonicWall](parsers-ocsf/sonicwall) | `sonicwall` | SonicWall | key=value syslog | Connections, IPS detection, content filtering, user auth |
| [Zscaler ZIA](parsers-ocsf/zscaler_zia) | `zscaler_zia` | Zscaler | JSON envelope | Web, firewall, DNS, tunnel, DLP, audit log types |
| [Broadcom ProxySG](parsers-ocsf/broadcom_proxy) | `broadcom_proxy` | Broadcom | ELFF space-delimited | Web proxy access logs with URL reconstruction |
| [Cloudflare](parsers-ocsf/cloudflare) | `cloudflare` | Cloudflare | JSON (Logpush) | HTTP requests, firewall events, DNS logs with WAF/bot scoring |
| [Cisco Umbrella](parsers-ocsf/cisco_umbrella) | `cisco_umbrella` | Cisco | CSV | DNS and proxy logs with domain categorization and identity |
| [Infoblox DHCP](parsers-ocsf/infoblox_dhcp) | `infoblox_dhcp` | Infoblox | Syslog | DISCOVER, OFFER, REQUEST, ACK, RELEASE, NAK, INFORM |
| [Conduit MITM Proxy](parsers-ocsf/conduit_proxy) | `conduit_proxy` | Conduit | JSON | HTTP/HTTPS requests with TLS interception status, threat scoring, DLP |

### Network Security Monitoring

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Zeek](parsers-ocsf/zeek) | `zeek` | Zeek Project | JSON | 24 log types: conn, dns, http, ssl, files, notice, smtp, ssh, rdp, intel, weird, and more |
| [Suricata](parsers-ocsf/suricata) | `suricata` | OISF | EVE JSON | 24 event types: alert, flow, dns, http, tls, fileinfo, smtp, ssh, anomaly, and more |

### Cloud

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [AWS CloudTrail](parsers-ocsf/aws_cloudtrail) | `aws_cloudtrail` | Amazon | JSON | API calls, user identity, resources, error tracking |
| [AWS VPC Flow Logs](parsers-ocsf/aws_vpc_flow) | `aws_vpc_flow` | Amazon | Space-delimited / JSON | VPC network flow logs v2-v5 with protocol mapping |
| [AWS GuardDuty](parsers-ocsf/aws_guardduty) | `aws_guardduty` | Amazon | JSON | Threat findings: network, IAM, S3, malware detections |
| [AWS WAF](parsers-ocsf/aws_waf) | `aws_waf` | Amazon | JSON | WAF v2 access logs: rule matches, rate limiting, bot control |
| [AWS ALB Access Logs](parsers-ocsf/aws_alb) | `aws_alb` | Amazon | Space-delimited | Application Load Balancer request logs with routing details |
| [AWS S3 Access Logs](parsers-ocsf/aws_s3_access) | `aws_s3_access` | Amazon | Space-delimited | S3 server access logs: bucket operations, requester identity |
| [Azure Activity Log](parsers-ocsf/azure_activity) | `azure_activity` | Microsoft | JSON | Operations, status, caller identity, resources |
| [Azure Sign-in Logs](parsers-ocsf/azure_signin) | `azure_signin` | Microsoft | JSON | Entra ID sign-ins: interactive, non-interactive, service principal |
| [Azure Monitor diagnostic export](parsers-ocsf/azure_monitor) | `azure_monitor` | Microsoft | JSON (Diagnostic Settings → Event Hubs / storage) | One lane for a mixed hub, dispatched on `category`: Activity Log (all 8 categories; Defender for Cloud alerts as Detection Finding), Entra ID sign-ins (interactive, non-interactive, service principal, managed identity) and Entra ID audit (user / group / role management). Unknown categories kept whole as Base Event. OCSF only |
| [Azure Firewall](parsers-ocsf/azure_firewall) | `azure_firewall` | Microsoft | JSON | Network rules, application rules, threat intel, DNS proxy |
| [GCP Audit Log](parsers-ocsf/gcp_audit) | `gcp_audit` | Google | JSON | IAM changes, API calls, resource operations, authorization |
| [Kubernetes Audit](parsers-ocsf/kubernetes_audit) | `kubernetes_audit` | CNCF | JSON | API server audit: resource operations, RBAC, user identity |
| [Microsoft 365](parsers-ocsf/microsoft_365) | `microsoft_365` | Microsoft | JSON | Exchange, SharePoint, Azure AD, DLP, Teams audit events |
| [Google Workspace Audit](parsers-ocsf/google_workspace) | `gws_login` | Google | JSON | Admin SDK Reports: login, admin console, OAuth token, Drive activity |

### Security & IAM

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Okta](parsers-ocsf/okta) | `okta` | Okta | JSON | System Log API: auth, MFA, user lifecycle, group, policy events |
| [Duo Security](parsers-ocsf/duo) | `duo` | Cisco | JSON | Authentication, admin actions, MFA with device/geo context |
| [Auth0](parsers-ocsf/auth0) | `auth0` | Okta | JSON | 20+ event types: login, signup, MFA, token exchange, management API |
| [1Password](parsers-ocsf/onepassword) | `onepassword` | 1Password | JSON | Sign-in attempts, item usage, vault access events |
| [CyberArk PAM](parsers-ocsf/cyberark) | `cyberark` | CyberArk | CEF syslog | Vault audit, PSM sessions, privileged access events |
| [Netskope](parsers-ocsf/netskope) | `netskope` | Netskope | JSON | CASB/SSE: app activity, alerts, DLP, network events |
| [F5 BIG-IP ASM](parsers-ocsf/f5_waf) | `f5_waf` | F5 | JSON | Web application firewall: attacks, violations, security events |

### Vulnerability Management

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Qualys](parsers-ocsf/qualys) | `qualys` | Qualys | JSON | Host detections, knowledge base, WAS findings, compliance |
| [Rapid7 InsightVM](parsers-ocsf/rapid7_insightvm) | `rapid7_insightvm` | Rapid7 | JSON | Vulnerability findings, asset data, remediation events |

### Email Security

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Proofpoint](parsers-ocsf/proofpoint) | `proofpoint` | Proofpoint | JSON | Message delivery, TAP threat alerts, spam/phishing verdicts |
| [Mimecast](parsers-ocsf/mimecast) | `mimecast` | Mimecast | JSON | Receipt, URL protection, attachment protection events |

### SaaS Audit

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [GitHub Audit](parsers-ocsf/github_audit) | `github_audit` | GitHub | JSON | Organization and enterprise audit events |
| [Slack Audit](parsers-ocsf/slack_audit) | `slack_audit` | Salesforce | JSON | Enterprise Grid audit: login, file, channel, app events |
| [Slack Access Logs](parsers-ocsf/slack_access) | `slack_access_log` | Salesforce | JSON | Workspace sign-in records from team.accessLogs |

### Application

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Apache HTTP Server](parsers-ocsf/apache) | `apache_access` | Apache | Combined/common log | Client IP, method, status, bytes, user agent, referrer |
| [Nginx](parsers-ocsf/nginx) | `nginx` | Nginx | Combined / JSON / error | Access and error logs with upstream and proxy support |
| [Squid Proxy](parsers-ocsf/squid_proxy) | `squid_proxy` | Squid Project | Access log | Cache hit/miss, URL extraction, HTTP metadata |
| [nano Platform API](parsers-ocsf/nano-platform-api) | `nano-platform-api` | nano | JSON (pino) | nano platform API logs: level mapping, request/response context |
| [nano Operational Logs](parsers-ocsf/nano_operational) | `nano_operational` | nano | JSON (tracing) | nano service operational + tracing logs (api, jobs, search) |

### Generic

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Generic JSON](parsers-ocsf/json_generic) | `json_generic` | — | JSON | Auto-detects common field names for timestamps, IPs, users, actions |
| [Generic Syslog](parsers-ocsf/syslog) | `syslog` | IETF | RFC 3164 / 5424 | Facility/severity decode, app-specific sub-parsing (sshd, sudo, iptables) |

## OCSF parsers

Every directory under [`parsers-ocsf/`](parsers-ocsf) is one parser. The folder
name is load-bearing: nano's repo sync resolves the parser tree as the
hardcoded `parsers-ocsf/` path, so do not rename it or nest a version under it
(`parsers-ocsf-1.9/` or `parsers-ocsf/1.9/` would never be found, or would be
imported several times over).

Each parser records its OCSF version in its own YAML:

```yaml
ocsf_version: "1.9.0"
```

so the version is self-evident in the file and machine-checkable. The validator
asserts `metadata.version` against this key rather than a hardcoded constant.

### Sample corpus

Samples live **beside the parser** — this is the convention for the OCSF tree:

```
parsers-ocsf/<source>/
├── parser.yaml
└── samples/
    ├── 4624_logon_success.json
    ├── 4688_process_creation.json
    └── malformed.json
```

- One file per branch of the parser, named after the branch it exercises
  (each EventID, each CloudTrail shape, each log type) — plus one malformed line,
  because a parser that aborts on garbage drops the whole batch.
- A file is either the raw log line, or a `{"message": "<raw line>"}` wrapper.
  Use the wrapper whenever the raw line is itself JSON containing a `message` key.
- These are the inputs `scripts/validate-ocsf.sh` runs. A parser with no `samples/`
  is reported as UNVALIDATED — it is unproven, not fine.

An inline `samples:` block inside `parser.yaml` (exercised by
`scripts/validate-vrl.sh`) is still honoured, but OCSF parsers use the sidecar
directory because their raw lines — Windows XML, nested
cloud JSON — are far too large to read inline.

### Validating the OCSF tree

```bash
# whole tree
scripts/validate-ocsf.sh

# one parser, or a file listing changed parser paths (same contract as validate-vrl.sh)
scripts/validate-ocsf.sh parsers-ocsf/windows_event_xml/parser.yaml
```

Two gates per sample:

1. **VRL** — `vector vrl` compiles *and runs* the program. `vector vrl` exits 0
   even when a program aborts at runtime, so the signal is whether an object came
   out at all. An abort is a hard failure: that parser drops every event it touches.
2. **OCSF** — the *emitted* event (never a row read back from the lake, which has
   been through column promotion and null-stripping) is checked against nano's OCSF
   contract, plus these tree-wide consistency rules:
   - `metadata.version` equals the parser's own `ocsf_version`
   - `type_uid == class_uid * 100 + activity_id`
   - the parser never writes `.udm.*` or `source_type` (`metadata.log_source`
     carries the source type in OCSF)
   - `class_uid` is a real, **non-deprecated** class — OCSF 1.9 deprecated
     Account Change (3001) and User Access Management (3005) in favour of
     User Management (3007) and Group Management (3006)
   - every path written is a canonical OCSF 1.9 attribute of the event's class,
     or sits under `unmapped.*`. nano's lake stores every canonical path as its own
     column and search serves it (indexed or not); a non-canonical path is refused
     by search ("Unknown canonical OCSF field"), so it is reported

The contract check needs nano's `ocsf_event_validate` binary, which is a nano build
artifact and is not vendored here. Point `OCSF_VALIDATOR` at it, or put it on
`PATH`; without it that half reports SKIPPED and every rule above still runs.

The reference data the script checks against lives next to it:

- `scripts/ocsf-1.9.0-classes.json` — every class uid, caption and `@deprecated` flag,
  regenerated from `https://schema.ocsf.io/api/1.9.0/`
- `scripts/ocsf-1.9.0-contract.json.gz` — nano's embedded OCSF 1.9 contract
  (classes, objects, attribute types), copied verbatim from nanosiem
  `nanosiem-core/src/parsers/ocsf-1.9.0-contract.json.gz`; rule 5 walks it

CI runs both `scripts/validate-vrl.sh` and `scripts/validate-ocsf.sh` over the whole
repository on every PR (`.github/workflows/validate-parsers.yml`).

### Writing an OCSF parser

- Emit the **complete OCSF object on the root** (`. = ocsf`) so it lands in
  the lake and every canonical path is stored as its own queryable column.
- UDM names do not exist in OCSF. `src_ip` is `src_endpoint.ip`, `user` is
  `actor.user.name` (the actor) or `user.name` (the subject, class-dependent),
  `timestamp` is `time`, `id` is `metadata.uid`, `ext.foo` is `unmapped.foo`.
- **Profile-bound attributes require declaring the profile.** `cloud`, `trace`,
  `device` on the IAM classes and `security_control` are not base attributes of
  every class. If the validator says an attribute "is not defined for this OCSF
  class/profile" and the path is right, the missing piece is almost always
  `metadata.profiles`, e.g. `"profiles": ["host"]`.
- When nothing fits, **Base Event (`class_uid` 0) is the right answer.** It is the
  spec's home for an event with no class; forcing an application log line into a
  security class poisons every class-scoped hunt.

## Structure

Each parser lives in its own directory under `parsers-ocsf/` with a `parser.yaml` file containing:

- **name**: Machine-readable identifier (snake_case)
- **display_name**: Human-friendly name
- **version**: Semantic version
- **description**: What this parser does
- **match_values**: The `source_type` that routes to this parser — **one value**

### Naming a source type

One `source_type` per source, and it names *what the log is*, not how it is encoded.
Parsers for different wire formats of the same source therefore share one value:
`windows_sysmon` covers both the JSON and XML Sysmon parsers, and `windows_event`
covers all three Windows Event Log parsers. Pick the parser matching your format and
deploy **exactly one per source type** — deploying two that claim the same value routes
every event down both pipelines and writes it to storage twice.

Genuinely different sources get different values even under one vendor: Sysmon for Linux
is `linux_sysmon`, not `windows_sysmon`.

`match_values` is a list for backward compatibility and because a few collector-backed
parsers still carry per-stream values, but new parsers should declare a single entry.
The value is only a default — it is shown when importing and an operator can change it
to whatever their forwarders already tag with.
- **category**: Log category (endpoint, network, cloud, security, application, generic)
- **vendor**: Vendor/organization name
- **product**: Product name
- **parser_vrl**: The VRL transformation code

## Usage

Import these parsers into nano via **Log Sources > Repositories**. Parsers are imported as draft log sources ready for review and deployment.

## Contributing

1. Create a new directory under `parsers-ocsf/` with your parser name
2. Add a `parser.yaml` following the format above
3. Test your VRL with `vector vrl --program your_parser.vrl --input test.json --print-object`
4. Ensure every field maps to a canonical OCSF 1.9 path or spills to `unmapped.*` (see [Writing an OCSF parser](#writing-an-ocsf-parser))

