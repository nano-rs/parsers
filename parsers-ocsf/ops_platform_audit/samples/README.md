# nano platform audit samples

Copied from nano-main `tools/ops-tenant/parsers/ops_platform_audit/samples`
(the lake-era ops parser this one replaces): already-OCSF export lines
(`nano_main_exported_*`, `tenant_mirror_*`), tenant-plane rows with and
without `ocsf_event` (`tenant_plane_*`), raw nano-main `audit_log` rows
(`nano_main_*`, snake_case and camelCase) and a non-JSON line. The lake's
shared-ingest transport fixtures (HEC / HTTP header and decoded-root shapes)
are not ported: kestrel's `/ingest` hands the parser the NDJSON line.
