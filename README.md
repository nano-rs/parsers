# nano Community Parsers

A collection of VRL parsers for nano log source ingestion.

## Available Parsers

### Endpoint

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [CrowdStrike Falcon](parsers/crowdstrike_falcon) | `crowdstrike_falcon` | CrowdStrike | JSON (FDR + Streaming API) | 25+ event types: ProcessRollup2, NetworkConnect, DnsRequest, FileWrite, UserLogon, DetectionSummary, and more |
| [SentinelOne](parsers/sentinelone) | `sentinelone` | SentinelOne | JSON | Threats, activity logs, Deep Visibility (process, network, DNS, file, registry) |
| [VMware Carbon Black](parsers/carbon_black) | `carbon_black` | VMware | JSON | CB Analytics alerts, watchlist hits, process events with MITRE TTPs |
| [Microsoft Defender EDR](parsers/defender_edr) | `defender_edr` | Microsoft | JSON | Process creation, network connections, file events, logon activities |
| [Microsoft Sysmon](parsers/windows_sysmon) | `windows_sysmon` | Microsoft | JSON (Vector/Winlogbeat/NXLog) | Process, network, file, registry, DNS events from Sysmon |
| [Microsoft Sysmon (XML)](parsers/sysmon_xml) | `windows_sysmon` | Microsoft | Native XML | All 29 Sysmon event IDs with hash splitting and MITRE extraction |
| [Microsoft Sysmon for Linux (XML)](parsers/sysmon_linux_xml) | `linux_sysmon` | Microsoft | Native XML | Sysmon for Linux: process, network, file events with MITRE extraction |
| [Windows Event Log](parsers/windows_event) | `windows_event` | Microsoft | Winlogbeat/NXLog JSON | 24+ EventIDs: logon, process, service, Kerberos, account mgmt |
| [Windows Event Log (XML)](parsers/windows_event_xml) | `windows_event` | Microsoft | Native XML | 30+ EventIDs parsed from raw Windows Event XML |
| [Windows Event Log (Text)](parsers/windows_event_text) | `windows_event` | Microsoft | Rendered text | Splunk UF / wevtutil format with section-aware body parsing |
| [Linux auditd](parsers/linux_auditd) | `linux_auditd` | Linux | key=value | SYSCALL, EXECVE, PATH, USER_AUTH, USER_LOGIN, AVC (SELinux), NETFILTER |
| [systemd-journald](parsers/linux_journald) | `linux_journald` | systemd | JSON (journalctl -o json) | Priority, facility, unit, originating process, transport; sshd, sudo and netfilter sub-parsing |
| [LimaCharlie EDR](parsers/limacharlie) | `limacharlie` | LimaCharlie | JSON | Sensor telemetry: process, network, DNS, file, module, registry, auth, detections |
| [Moat](parsers-ocsf/moat_edr) | `moat_edr` | Omarchy | JSON (NDJSON envelope) | Supply-chain sensor: alerts with correlation chains and AI triage, alert updates, package-install receipts, shipper heartbeat, plus the opt-in process / network / file telemetry classes. OCSF only |

### Network & Firewall

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Palo Alto PAN-OS](parsers/palo_alto) | `palo_alto` | Palo Alto Networks | CSV syslog | TRAFFIC, THREAT, SYSTEM, CONFIG, USERID, GlobalProtect, HIP, AUTH |
| [Fortinet FortiGate](parsers/fortinet) | `fortinet` | Fortinet | key=value syslog | Traffic, UTM (webfilter, app-ctrl, DNS, IPS, virus), event |
| [Cisco ASA](parsers/cisco_asa) | `cisco_asa` | Cisco | Syslog message codes | 30+ message IDs: connections, ACL, NAT, VPN, IPS, auth |
| [Check Point](parsers/checkpoint) | `checkpoint` | Check Point | RFC 5424 + LEA | Firewall rules, NAT, VPN, threat prevention, system |
| [Sophos Firewall](parsers/sophos) | `sophos` | Sophos | key=value syslog | Firewall, content filtering, AV, ATP, IDP, anti-spam, WAF |
| [Juniper SRX](parsers/juniper_srx) | `juniper_srx` | Juniper | RFC 5424 structured data | RT_FLOW sessions, RT_IDP attacks, RT_UTM events |
| [Cisco Meraki](parsers/meraki) | `meraki` | Cisco | Syslog | MX firewall flows, IDS alerts, URL filtering, wireless, VPN |
| [MikroTik RouterOS](parsers/routeros) | `routeros` | MikroTik | RFC 3164 syslog | DNS queries/answers, user login/logout/failure, firewall flows, DHCP leases |
| [SonicWall](parsers/sonicwall) | `sonicwall` | SonicWall | key=value syslog | Connections, IPS detection, content filtering, user auth |
| [Zscaler ZIA](parsers/zscaler_zia) | `zscaler_zia` | Zscaler | JSON envelope | Web, firewall, DNS, tunnel, DLP, audit log types |
| [Broadcom ProxySG](parsers/broadcom_proxy) | `broadcom_proxy` | Broadcom | ELFF space-delimited | Web proxy access logs with URL reconstruction |
| [Cloudflare](parsers/cloudflare) | `cloudflare` | Cloudflare | JSON (Logpush) | HTTP requests, firewall events, DNS logs with WAF/bot scoring |
| [Cisco Umbrella](parsers/cisco_umbrella) | `cisco_umbrella` | Cisco | CSV | DNS and proxy logs with domain categorization and identity |
| [Infoblox DHCP](parsers/infoblox_dhcp) | `infoblox_dhcp` | Infoblox | Syslog | DISCOVER, OFFER, REQUEST, ACK, RELEASE, NAK, INFORM |
| [Conduit MITM Proxy](parsers/conduit_proxy) | `conduit_proxy` | Conduit | JSON | HTTP/HTTPS requests with TLS interception status, threat scoring, DLP |

### Network Security Monitoring

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Zeek](parsers/zeek) | `zeek` | Zeek Project | JSON | 24 log types: conn, dns, http, ssl, files, notice, smtp, ssh, rdp, intel, weird, and more |
| [Suricata](parsers/suricata) | `suricata` | OISF | EVE JSON | 24 event types: alert, flow, dns, http, tls, fileinfo, smtp, ssh, anomaly, and more |

### Cloud

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [AWS CloudTrail](parsers/aws_cloudtrail) | `aws_cloudtrail` | Amazon | JSON | API calls, user identity, resources, error tracking |
| [AWS VPC Flow Logs](parsers/aws_vpc_flow) | `aws_vpc_flow` | Amazon | Space-delimited / JSON | VPC network flow logs v2-v5 with protocol mapping |
| [AWS GuardDuty](parsers/aws_guardduty) | `aws_guardduty` | Amazon | JSON | Threat findings: network, IAM, S3, malware detections |
| [AWS WAF](parsers/aws_waf) | `aws_waf` | Amazon | JSON | WAF v2 access logs: rule matches, rate limiting, bot control |
| [AWS ALB Access Logs](parsers/aws_alb) | `aws_alb` | Amazon | Space-delimited | Application Load Balancer request logs with routing details |
| [AWS S3 Access Logs](parsers/aws_s3_access) | `aws_s3_access` | Amazon | Space-delimited | S3 server access logs: bucket operations, requester identity |
| [Azure Activity Log](parsers/azure_activity) | `azure_activity` | Microsoft | JSON | Operations, status, caller identity, resources |
| [Azure Sign-in Logs](parsers/azure_signin) | `azure_signin` | Microsoft | JSON | Entra ID sign-ins: interactive, non-interactive, service principal |
| [Azure Firewall](parsers/azure_firewall) | `azure_firewall` | Microsoft | JSON | Network rules, application rules, threat intel, DNS proxy |
| [GCP Audit Log](parsers/gcp_audit) | `gcp_audit` | Google | JSON | IAM changes, API calls, resource operations, authorization |
| [Kubernetes Audit](parsers/kubernetes_audit) | `kubernetes_audit` | CNCF | JSON | API server audit: resource operations, RBAC, user identity |
| [Microsoft 365](parsers/microsoft_365) | `microsoft_365` | Microsoft | JSON | Exchange, SharePoint, Azure AD, DLP, Teams audit events |
| [Google Workspace Audit](parsers/google_workspace) | `gws_login` | Google | JSON | Admin SDK Reports: login, admin console, OAuth token, Drive activity |

### Security & IAM

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Okta](parsers/okta) | `okta` | Okta | JSON | System Log API: auth, MFA, user lifecycle, group, policy events |
| [Duo Security](parsers/duo) | `duo` | Cisco | JSON | Authentication, admin actions, MFA with device/geo context |
| [Auth0](parsers/auth0) | `auth0` | Okta | JSON | 20+ event types: login, signup, MFA, token exchange, management API |
| [1Password](parsers/onepassword) | `onepassword` | 1Password | JSON | Sign-in attempts, item usage, vault access events |
| [CyberArk PAM](parsers/cyberark) | `cyberark` | CyberArk | CEF syslog | Vault audit, PSM sessions, privileged access events |
| [Netskope](parsers/netskope) | `netskope` | Netskope | JSON | CASB/SSE: app activity, alerts, DLP, network events |
| [F5 BIG-IP ASM](parsers/f5_waf) | `f5_waf` | F5 | JSON | Web application firewall: attacks, violations, security events |

### Vulnerability Management

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Qualys](parsers/qualys) | `qualys` | Qualys | JSON | Host detections, knowledge base, WAS findings, compliance |
| [Rapid7 InsightVM](parsers/rapid7_insightvm) | `rapid7_insightvm` | Rapid7 | JSON | Vulnerability findings, asset data, remediation events |

### Email Security

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Proofpoint](parsers/proofpoint) | `proofpoint` | Proofpoint | JSON | Message delivery, TAP threat alerts, spam/phishing verdicts |
| [Mimecast](parsers/mimecast) | `mimecast` | Mimecast | JSON | Receipt, URL protection, attachment protection events |

### SaaS Audit

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [GitHub Audit](parsers/github_audit) | `github_audit` | GitHub | JSON | Organization and enterprise audit events |
| [Slack Audit](parsers/slack_audit) | `slack_audit` | Salesforce | JSON | Enterprise Grid audit: login, file, channel, app events |
| [Slack Access Logs](parsers/slack_access) | `slack_access_log` | Salesforce | JSON | Workspace sign-in records from team.accessLogs |

### Application

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Apache HTTP Server](parsers/apache) | `apache_access` | Apache | Combined/common log | Client IP, method, status, bytes, user agent, referrer |
| [Nginx](parsers/nginx) | `nginx` | Nginx | Combined / JSON / error | Access and error logs with upstream and proxy support |
| [Squid Proxy](parsers/squid_proxy) | `squid_proxy` | Squid Project | Access log | Cache hit/miss, URL extraction, HTTP metadata |
| [nano Platform API](parsers/nano-platform-api) | `nano-platform-api` | nano | JSON (pino) | nano platform API logs: level mapping, request/response context |
| [nano Operational Logs](parsers/nano_operational) | `nano_operational` | nano | JSON (tracing) | nano service operational + tracing logs (api, jobs, search) |

### Generic

| Parser | Source type | Vendor | Format | Description |
|--------|-------------|--------|--------|-------------|
| [Generic JSON](parsers/json_generic) | `json_generic` | — | JSON | Auto-detects common field names for timestamps, IPs, users, actions |
| [Generic Syslog](parsers/syslog) | `syslog` | IETF | RFC 3164 / 5424 | Facility/severity decode, app-specific sub-parsing (sshd, sudo, iptables) |

## OCSF parsers

Everything above emits nano's UDM (`.udm.*`). `parsers-ocsf/` holds parsers that
emit [OCSF](https://schema.ocsf.io) records instead, for deployments running
`NANO_SCHEMA_PROFILE=ocsf` — those land in `ocsf_logs` rather than `logs`.

Each is the counterpart of a UDM parser above and **claims the same source type**,
because a source type names the log, not the schema it is mapped into. They are
alternatives: deploy the UDM parser or the OCSF one for a given source, never both.
The tree is the index — every directory under [`parsers-ocsf/`](parsers-ocsf) is
one parser, named after its UDM counterpart in `parsers/`.

### Which OCSF version — the branch decides

**The branch selects the OCSF version.**

| Branch | OCSF version | For |
|--------|--------------|-----|
| `main` | 1.8 | tenants running OCSF on ClickHouse (non-lake) |
| `ocsf-1.9` | 1.9 | tenants on the lake / OCSF 1.9 |

Both the parser and rule repositories have a per-deployment `branch` setting, so a
tenant moves to 1.9 by changing that one field — nothing else about the path or the
import flow changes.

Each parser **also** records the version in its own YAML:

```yaml
ocsf_version: "1.9.0"
```

so the version is self-evident in the file and machine-checkable. The validator
asserts `metadata.version` against this key rather than a hardcoded constant,
which is what lets the same script gate both branches.

**Why the version is not in the folder name.** nano's repo sync resolves the OCSF
tree as the hardcoded `parsers-ocsf/` sibling of the configured parsers path, so a
`parsers-ocsf-1.9/` folder would simply never be found. A nested `parsers-ocsf/1.9/`
does not work either: the tree walk is recursive, so every version directory would
be imported alongside every other one, and an operator would be offered several
copies of the same source. Branch for the version, key for the record.

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

UDM parsers use a different, inline convention (a `samples:` block inside
`parser.yaml`, exercised by `scripts/validate-vrl.sh`). Both are live; OCSF
parsers use the sidecar directory because their raw lines — Windows XML, nested
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
   - every OCSF path written is either promoted (queryable) or under `unmapped.*`;
     anything else is reported as silently unqueryable

The contract check needs nano's `ocsf_event_validate` binary, which is a nano build
artifact and is not vendored here. Point `OCSF_VALIDATOR` at it, or put it on
`PATH`; without it that half reports SKIPPED and every rule above still runs.

The reference data the script checks against lives next to it and is regenerated
from `https://schema.ocsf.io/api/1.9.0/`:

- `scripts/ocsf-1.9.0-classes.json` — every class uid, caption and `@deprecated` flag
- `scripts/ocsf-1.9.0-promoted-fields.txt` — the OCSF field paths nano promotes to
  queryable columns

CI runs both `scripts/validate-vrl.sh` and `scripts/validate-ocsf.sh` over the whole
repository on every PR (`.github/workflows/validate-parsers.yml`).

### Writing an OCSF parser

- Emit the **complete OCSF object on the root** (`. = ocsf`) so it lands in
  `ocsf_logs.event` and the promoted columns materialize.
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

Each parser lives in its own directory under `parsers/` with a `parser.yaml` file containing:

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

1. Create a new directory under `parsers/` with your parser name
2. Add a `parser.yaml` following the format above
3. Test your VRL with `vector vrl --program your_parser.vrl --input test.json --print-object`
4. Ensure all fields map to [UDM](https://docs.nanosiem.com/udm) or overflow to `.ext.*`

