# Azure NSG / VNet flow log samples

Record shapes, tuple field order and values come from the Microsoft Learn
sample records:

- NSG flow logs (version 1 and 2):
  https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview
- Virtual network flow logs (version 4 and 5, encryption states, `networkInterfaceIP`):
  https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview

Subscription ids, GUIDs and non-documentation public IPs were replaced with the
zero UUID and 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.

| File | Exercises |
|------|-----------|
| `nsg_v2_allow_end.json` | NSG v2 record, one tuple, outbound allow, E state with counters |
| `nsg_v2_allow_continuing.json` | NSG v2, C state with counters |
| `nsg_v2_deny_begin.json` | NSG v2, inbound UDP deny (Refuse) |
| `nsg_v2_multi_tuple.json` | NSG v2 doc record with 7 tuples: first mapped, flows kept in `unmapped` |
| `nsg_records_envelope.json` | `{"records": [...]}` storage-blob envelope |
| `nsg_v1_allow_rdp.json` | NSG v1 tuple (no state, no counters) |
| `nsg_no_tuples.json` | record with an empty tuple list (Base Event fallback) |
| `vnet_v4_outbound_end.json` | VNet v4 record, outbound E state |
| `vnet_v4_deny_ssh.json` | VNet v4, D state deny, several groups, `networkInterfaceIP` |
| `vnet_v5_private_link.json` | VNet v5 tuple with Private Link link id and SNAT ip/port |
| `vnet_preflattened_encrypted.json` | pre-flattened record (`flowTuple` + `rule` + `aclID`), X encryption |
| `tuple_nsg_continuing.json` | bare NSG tuple line (doc bandwidth example) |
| `tuple_vnet_ipv6_udp.json` | bare VNet tuple, IPv6, UDP, NX_FALLBACK |
| `junk.json`, `junk_text.json` | non-flow JSON and text (Base Event fallback) |
