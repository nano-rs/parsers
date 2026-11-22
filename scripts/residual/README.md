# Residual source preservation

`residual_spill.py` also opens every parser with the shared source-timezone
prelude (`source_tz.vrl`): it reads and removes `.nano.source_timezone` (the
log source's timezone setting, an IANA name or a fixed offset) and sets
`__src_tz` (an IANA name; UTC if absent or invalid) and `__src_shift_ms` (any
fixed `+HH:MM` offset, applied by arithmetic) for clocks without an offset. When a
parser read such a clock (`__time_assumed`), the spill records the zone in
`unmapped.nano_time_assumed_tz`. `.nano` is nano's input, never a source field:
`scripts/test_source_timezone.py` checks the shift and that `.nano` never
leaks.

**Parsers never mask, redact or withhold anything.** A parser converts raw to
real: every source field is mapped faithfully into OCSF or spilled into
`unmapped` exactly as parsed, `raw_data` is the untouched original, and
fallback text is kept as-is. Masking is an opt-in Nano Pipe step, a pipeline
concern, never a parser concern. Do not add redaction to this template, to a
parser, or to the checker.

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

The shared block runs after the mapping branch completes. **A source field is
consumed only by an explicit mapping**: a `mappings` entry in
`field-coverage.yaml` (`source key: [target path, ...]`) or a `transforms`
rule with its `target`, whose value (lossless scalar string/number conversion
allowed) is found AT THAT TARGET PATH of the selected branch. A value that
merely appears somewhere else in the event never consumes a field: no
coincidental consumption (a `TokenType` of `1` is not `activity_id: 1`).
Everything else spills, including values equal to defaults such as 0/false.
Target paths drop array indices (`resources.uid` covers every resource), and
`raw_data`, `unmapped` and a `message` equal to the whole raw body are never
targets. A human-readable mapped message is a target like any other.

`field_coverage_check.py` verifies every declaration by provenance: in at
least one sample, replacing that source value with a sentinel of the same type and
shape must move the value at the declared target from the old value to
exactly the sentinel, converted by the rule if there is one. Sentinels are
deterministic but unguessable: each draw is seeded with SHA-256 of (base seed,
parser, sample, field, draw), so every run gives the same verdict (no flaky
check), and a parser cannot depend on the values. A clock moves by whole
seconds, a `scale` source by a whole number of result units, and a small code
is drawn from outside the values the field takes in any sample (a short
lookup table cannot echo it). A plain mapping needs two distinct sentinels
to arrive (a lookup that happens to output one is not a copy); a boolean or
an enum rule needs one.
Lists are compared element by element as multisets, so a static list never
passes. Only that source field may change (a longer text containing it, such
as a raw message, may change with it). A declaration that only matches by
coincidence, or that no sample exercises, fails the parser.
`scripts/infer_mappings.py <parser>` writes the declarations the same way
(review its output); `--all-keys` considers every captured key for a new
parser. `PROVENANCE_SEED` overrides the base seed (`random` draws a fresh
one, for fuzzing); a failure prints the seed it used.

Source keys are flattened with escaped segments: a nested path is `a.b`, a
literal dotted key is `a~1b` (and a literal `~` is `~0`), so the two are
different fields, mapped and spilled independently. Declare a literal dotted
key in its escaped form.

Every additional normalization has a per-parser `field-coverage.yaml` entry:
source path, transform kind, destination path, and a one-line reason.
Rules are conditional: the transformed value must be at the destination.
Malformed timestamps, unsupported enums, and unused fallback values
remain residual. These are executable expectations, not unconditional waivers.
No missing source is accepted just because a path is listed.

Existing derived evidence (what the parser wrote to `unmapped` itself) is kept
unless it is null, empty, a container text, or a copy of a source value (that
value is mapped or spilled under its source path); equality with an unrelated
mapped attribute is no reason to drop it.

Residual objects flatten into dotted snake_case paths. Literal dots are escaped
before flattening, then decoded for naming. Collisions receive `_2`, `_3`, etc.
Scalar arrays retain their type/order; arrays containing objects or arrays use
JSON strings. A scalar array is consumed only when every element is at one of
its declared targets. Partially mapped arrays remain
intact to preserve their order and repeated elements. Every value spills
as-is, whatever its key is called (a `password` or `token` key is no
different from any other). An empty residual is omitted. Existing derived scalar evidence is retained when
it is not a duplicate of source or mapped values; source aliases are replaced
by canonical source paths.

The checker runs inline and sidecar samples, and adds JSON probes for unknown
keys, nested objects, scalar/object arrays, credential-named keys (which must
spill unaltered like any other), and collisions.
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
- holds the declared mappings in one string literal (`__decl`) looked up with
  `find`, and the mapped leaves as path-qualified members (`__repr`);
- groups the `transforms` rules that render to the same body (templates in
  `transforms.vrl`) and runs them in ONE loop over the flattened source, each
  group a whole-key regex literal around its body, instead of parsing a rule
  table and copying the source for every rule;
- decides each source key with one `filter` and builds the residual with one
  rename, falling back to the original in-order loop only when two keys decode
  or snake-case to the same name;
- skips work its input makes unnecessary (no dotted key: no escaping; no
  array or brace-led string: scalar members only).

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
context). Those objects retain their existing shape and values.
The flat dotted-key requirement applies to the new source residuals.

Configured text probes inject unseen fields and password values through KV,
CEF, XML, rendered Windows text, and multi-element syslog structured data. They
assert successful capture and unaltered preservation: the probe's password
value must reach the parsed source exactly, and check() then requires it
mapped or spilled with that value. For every sample, an emitted `raw_data`
must equal the original input byte for byte. Probes are temporary
in-memory inputs; supplied samples remain unchanged.

When adding a mapped field, declare its mapping (or transformation rule) with
the exact target path. A declaration never waives coverage: the value must be
at that path in the selected branch, and provenance must show it comes from
that source field. Do not declare a target the field only sometimes equals.
