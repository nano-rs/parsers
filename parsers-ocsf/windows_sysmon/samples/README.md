# Sysmon regression samples

`*_corpus.json` are raw JSON extracted from the `message` field emitted by nano's
`log-blaster-corpus`. All ten routed EIDs are represented. Generator arguments:

```sh
log-blaster-corpus --sysmon 40 --windows-event 0 --proxy 0 --apache 0 \
  --cloudtrail 0 --seed 2361 --output /tmp/sysmon.ndjson
```

The first event of each EID was selected. EID 23 required seed 2367 and EID 22
required seed 2410; the other EIDs use seed 2361. Defaults: 2000 assets,
start time `2026-08-11T00:00:00Z`. The generator's entity data includes random
identifiers, so seeds reproduce the event mix, not necessarily byte-identical logs.

Other fixtures are explicit variants: unsigned modules, inbound connections,
native UTC clocks, invalid/partially mapped values, Windows DNS statuses,
unknown EIDs, scalar/object/array spill values, snake-case key collisions,
empty parent paths, no residual, and malformed input.

Run the provenance check (requires `vector` and `yq` on PATH):

```sh
python3 scripts/sysmon_coverage_check.py parsers-ocsf/windows_sysmon/samples \
  --parser parsers-ocsf/windows_sysmon/parser.yaml --output-dir /tmp/sysmon-output
python3 scripts/sysmon_coverage_check.py \
  parsers-ocsf/windows_sysmon/samples/01_corpus.json /tmp/sysmon-output/01_corpus.json
```

The check requires mapped values at their intended OCSF paths, checks every
remaining EventData value in `unmapped`, and excludes `raw_data` as evidence.
Arrays/objects must round-trip through JSON strings; scalar types must survive.
Unknown EIDs must retain the 1007/99 fallback; empty residual must be absent.
