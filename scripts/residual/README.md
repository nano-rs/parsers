# Residual source preservation

`residual_spill.py` generates the shared spill block in each enabled OCSF parser.
Edit `spill.vrl`, `transforms.vrl`, or the parser's `field-coverage.yaml`, then run:

```sh
python3 scripts/residual_spill.py
python3 scripts/residual_spill.py --check
python3 scripts/field_coverage_check.py parsers-ocsf/defender_edr/parser.yaml
python3 scripts/field_coverage_check.py --all
python3 scripts/test_field_coverage_check.py
```

The parser captures its source into the **local VRL variable** `__source_kv`.
JSON parsers capture the original parsed object; text parsers capture named
fields from their own parse operations. `__raw_body` records the original line
only to exclude it from coverage and spill. Neither variable is emitted.
The checker appends `.__coverage_source = __source_kv` to a temporary copy of
the program and removes that diagnostic attribute before checking the event.
Production parser definitions never emit the diagnostic attribute.

The shared block runs after the mapping branch completes. It restricts exact-value consumption to each parser's explicit
`consumed_candidates`, then records paths whose values actually occur in the
selected output branch, including lossless scalar string/number conversion.
Unknown keys always spill, including values equal to defaults such as 0/false. It excludes `raw_data`, pre-existing `unmapped`, and a `message`
that equals the whole raw body. A human-readable mapped message is evidence.
It does not use substring matching. A field merely read in an unused helper is
not consumed unless its value actually appears in the selected branch.

Every additional normalization has a per-parser `field-coverage.yaml` entry:
source path, transform kind, optional destination path, and a one-line reason.
Rules are conditional: the transformed value must actually match emitted
output. Malformed timestamps, unsupported enums, and unused fallback values
remain residual. These are executable expectations, not unconditional waivers.
No missing source is accepted just because a path is listed.

Residual objects flatten into dotted snake_case paths. Literal dots are escaped
before flattening, then decoded for naming. Collisions receive `_2`, `_3`, etc.
Scalar arrays retain their type/order; arrays containing objects or arrays use
JSON strings. Fully represented scalar arrays are consumed. Partially mapped arrays remain
intact to preserve their order and repeated elements. Secret-bearing keys
(`password`, `secret`, `authorization`, `token`, case-insensitive) are redacted
recursively before encoding; a sensitive object key redacts its whole value.
Name/value and Key/Value header or parameter objects redact the payload when
the name identifies a sensitive field.
This is spill redaction; the existing untouched `raw_data` retention is unchanged.
An empty residual is omitted. Existing derived scalar evidence is retained when
it is not a duplicate of source or mapped values; source aliases are replaced
by canonical source paths.

The checker runs inline and sidecar samples, and adds JSON probes for unknown
keys, nested objects, scalar/object arrays, secret redaction, and collisions.
`--output-dir` optionally retains emitted production events for review.
`--all` fails for any parser lacking source capture or a coverage manifest;
it never silently treats unsupported text input as covered.

## Per-event cost (NAN-5351)

The block runs on every event, so it is written for VRL's cost model: every
read of a variable copies it. An array or object used as a lookup set would
be copied on each lookup, which made the original block quadratic in event
size. The generated block therefore:

- holds value sets in strings (`"," + encode_json(member)` per member) and
  tests membership with `contains`; a string read shares its buffer;
- turns `consumed_candidates` into a regex literal, compiled once;
- groups the `transforms` rules that render to the same body (templates in
  `transforms.vrl`) and runs them in ONE loop over the flattened source, each
  group a whole-key regex literal around its body, instead of parsing a rule
  table and copying the source for every rule;
- decides each source key with one `filter` and builds the residual with one
  rename, falling back to the original in-order loop only when two keys decode
  or snake-case to the same name;
- skips work its input makes unnecessary (no secret word: no redaction walk;
  no dotted key: no escaping; no array or brace-led string: scalar members only).

Compile cost matters as much as per-event cost: Vector compiles every remap
program in the tree on every reload, and nano rolls back a deploy whose reload
is not acknowledged in time (NAN-5298). Unrolling one `if` block per rule was
as fast per event but doubled compile time for the parsers with the most
rules (crowdstrike_falcon 10 s -> 21 s in `vector validate`), because Vector's
type checker clones and merges the program's whole type state at each branch.
Keep the statement count independent of the rule count.

Each shortcut must leave output byte-identical. Compare the emitted events of
every sample before and after any change to the template.

The original `sysmon_coverage_check.py` remains an additional, stricter check of
Sysmon-specific mappings. The generic check is intended to complement those
branch-specific assertions, not weaken them.

Some existing derived evidence has meaning beyond source-value equality.
`preserve_unmapped` explicitly documents these exceptions (currently Moat DNS
context). Those objects retain their existing shape and are recursively redacted.
The flat dotted-key requirement applies to the new source residuals.

Configured text probes inject unseen fields and password values through KV,
CEF, XML, rendered Windows text, and multi-element syslog structured data. They
assert both successful capture and redacted preservation. Probes are temporary
in-memory inputs; supplied samples remain unchanged.

When adding a mapped field, update its consumed candidate and any transformation
rule. A candidate alone never waives coverage: its actual value must appear in
the selected branch. Do not add wildcard candidates for entire source objects.
