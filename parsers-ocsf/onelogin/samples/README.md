# OneLogin event samples

Sources:

- OneLogin Events API, Get Events reference sample response,
  https://developers.onelogin.com/api-docs/1/events/get-events
  (`13_created_user`, `05_user_logged_into_onelogin`: the two records shown,
  addresses and names replaced).
- OneLogin event type list, https://developers.onelogin.com/api-docs/1/events/event-type-lookup/
  (all 597 ids; the parser maps 82 of them). The remaining samples use the
  documented event object fields with ids from that list: 3, 4, 6, 7, 8, 9, 11,
  19, 22, 69, 551, 950, 1001, 1002, and 41 (`AD_CONNECTOR_STARTED`) as an id the parser
  deliberately leaves unmapped (Base Event, id kept).
- `05_user_logged_into_onelogin_invalid_ip.json` carries an `ipaddr` that is
  not an address: no `src_endpoint.ip` (ip_t), the value stays in unmapped.
- `junk.json` is a non-JSON line for the fallback branch.

Identifiers are documentation values: addresses in 192.0.2.0/24,
198.51.100.0/24 and 203.0.113.0/24, account id 123456.
