#!/usr/bin/env python3
# The classifier below is a PORT of nano's (nanosiem-core
# src/parsers/vector_config/hec_payload.rs, `input_contract`). When nano's own
# classifier binary is available (NANO_INPUT_CONTRACT, or the build pinned in
# scripts/input-contract.lock), this test runs every parser through it too and
# fails on any difference, so the port cannot drift from nano.
"""A parser's input contract survives the generated blocks; HEC / OTel delivery works.

A parser declares what it reads with comment lines in its VRL (nanosiem
NAN-5883). This content channel serves EVERY install, so declarations come in
a backward-compatible pair:
- `# nano:input=json|text` (v1): every nano version reads it, exactly as today;
- `# nano:input-v2=json|text|json_or_text` (v2): read from nano v2.0.36, where
  it wins over v1; older versions ignore it.
A v2 line always comes with a v1 line, and a bare v1 `json_or_text` is refused
(older nano reads it as undeclared and may infer JSON). Undeclared, nano infers
the contract from the first structural decoder; from v2.0.36 it skips the
generated blocks (prelude, local clock, residual spill, mixed input), older
versions count them.

What each contract receives over HEC (nanosiem NAN-5891, v2.0.36+):
- string events and `/services/collector/raw`: the text, as before;
- object events: `json` / `json_or_text` get the sender's whole record; `text`
  gets the record's line (its string `message`, else, with no `message` at all,
  its string `line`), or the whole record when it has none, and the record's
  other keys are filed under `unmapped`.

The generated blocks (the source-timezone prelude at the top of every parser,
the local-clock blocks, the residual spill) must never change the answer older
nano versions give either: the prelude once called parse_regex, which made
`regex` the first decoder of every parser, and every HEC / OTLP event of every
JSON-input parser got unmapped.parse_error. This test keeps:

1. the classification of every parser equal with and without the prelude and
   local-clock blocks under the pre-v2.0.36 rule;
2. the generated templates free of any structural decoder ahead of the parser
   (prelude, local clock) and of any LINE decoder anywhere (spill, transforms);
   every parser's pre-v2.0.36 contract equal to scripts/json-input-parsers.txt,
   and every v2 declaration paired with a v1 line;
3. the port equal to nano's classifier binary, when it is available;
4. Generic JSON declaring its contract (nano v2.0.36+ gives an undeclared
   parser the v2.0.35 HEC delivery, NAN-5902), and, fed exactly what nano
   delivers for a Splunk HEC object event (the record view: envelope keys and
   record keys on the root, the record text in `.message`), an OTel-style event,
   a string event and an /ingest body, parsing without a parse_error, keeping
   every record value, and taking time and host from the record, not the
   envelope;
5. every JSON-input parser declaring its contract (NAN-5902), and every
   declared JSON parser, run through nano's own HEC delivery VRL
   (scripts/nano-hec) with and without its declaration, giving the same output
   on every lane but HEC object events (HEC string JSON / text, /raw, /ingest
   JSON / text, OTLP), and reading an HEC object event as it reads the same
   record posted to /ingest. `--report=<file>` writes the HEC object
   before / after difference per parser.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_source_timezone import ROOT, run  # noqa: E402
from provenance import VECTOR_ENV  # noqa: E402

# Kept equal to FIRST_DECODER / LINE_DECODER in nanosiem-core hec_payload.rs.
FIRST_DECODER = re.compile(r'\bparse_(json|syslog|regex_all|regex|groks|grok|cef|key_value|csv|xml|common_log|apache_log|nginx_log|klog|glog|logfmt|linux_authorization|aws_[a-z_]+|tokens|ruby_hash|cbor|influxdb)\b')
LINE_DECODER = re.compile(r'\bparse_(syslog|groks|grok|cef|key_value|csv|xml|common_log|apache_log|nginx_log|klog|glog|logfmt|linux_authorization|aws_alb_log|aws_vpc_flow_log|aws_cloudwatch_log_subscription_message)\b')

# The blocks generated AHEAD of or inside the parser's own code. (The residual
# spill closes the program; its parse_json has always been there, so a parser
# with no decoder of its own, such as opentelemetry_logs, reads as JSON-input
# with or without these blocks.)
GENERATED = [('# NAN source timezone.', '# END NAN source timezone'),
             ('# NAN local clock:', '# END NAN local clock')]


def legacy_reads_json_object(vrl):
    """nano before v2.0.36 (`vrl_reads_json_object`): comments skipped, generated code counted."""
    code = []
    for line in vrl.splitlines():
        trimmed = line.strip()
        if trimmed.startswith('#'):
            comment = trimmed[1:].strip().lower()
            if comment == 'nano:input=json':
                return True
            if comment == 'nano:input=text':
                return False
            continue
        code.append(line)
    code = '\n'.join(code)
    first = FIRST_DECODER.search(code)
    return bool(first and first.group(1) == 'json' and not LINE_DECODER.search(code))


def _comment(line):
    t = line.strip()
    return t[1:].strip() if t.startswith('#') else None


def _is_block_start(comment, end):
    return comment.startswith(end) and (len(comment) == len(end) or comment[len(end)] in '.: ')


def own_code(vrl):
    """Port of nano `own_code`: comments and generated `# NAN x` ... `# END NAN x` blocks removed."""
    lines = vrl.splitlines()
    code, i = [], 0
    while i < len(lines):
        c = _comment(lines[i])
        if c is None:
            code.append(lines[i])
            i += 1
            continue
        if c.startswith('NAN'):
            best = None
            for j in range(i + 1, len(lines)):
                cj = _comment(lines[j])
                if cj and cj.startswith('END '):
                    end = cj[4:].strip()
                    if _is_block_start(c, end) and (best is None or len(end) > best[1]):
                        best = (j, len(end))
            if best:
                i = best[0] + 1
                continue
        i += 1
    return '\n'.join(code)


CONTRACTS = ('json', 'text', 'json_or_text')
V1, V2 = 'nano:input=', 'nano:input-v2='


def declarations(vrl):
    """(v1, v2, bad): the first `# nano:input=` and `# nano:input-v2=` values,
    and every problem nano's classifier warns about (an unknown value, a
    second declaration with a different value, a v1 `json_or_text` anywhere)."""
    v1 = v2 = None
    bad = []
    for line in vrl.splitlines():
        c = _comment(line)
        if c is None:
            continue
        c = c.lower()
        for key in (V2, V1):
            if c.startswith(key):
                value = c[len(key):].strip()
                if value not in CONTRACTS:
                    bad.append(f'unknown input contract `# {key}{value}`')
                    break
                if key == V1 and value == 'json_or_text':
                    bad.append('`# nano:input=json_or_text` is undeclared on nano before v2.0.36; keep `# nano:input=json|text` and add `# nano:input-v2=json_or_text`')
                first = v2 if key == V2 else v1
                if first is None:
                    if key == V2:
                        v2 = value
                    else:
                        v1 = value
                elif first != value:
                    bad.append(f'two `# {key}` declarations (`{first}` and `{value}`); the first one applies')
                break
    return v1, v2, bad


def input_contract(vrl):
    """Port of nano (v2.0.36+) `input_contract`: (contract, declared, inferred).
    `# nano:input-v2=` wins over `# nano:input=`; else inference."""
    v1, v2, _ = declarations(vrl)
    declared = v2 or v1
    code = own_code(vrl)
    first = FIRST_DECODER.search(code)
    inferred = 'json' if first and first.group(1) == 'json' and not LINE_DECODER.search(code) else 'text'
    return (declared or inferred, declared is not None, inferred)


def reads_json_first(vrl):
    """Port of nano `reads_json_first`: a `text` parser whose first decoder is
    parse_json (it should declare json_or_text)."""
    first = FIRST_DECODER.search(own_code(vrl))
    return input_contract(vrl)[0] == 'text' and bool(first and first.group(1) == 'json')


def reads_json_object(vrl):
    """Whether nano (v2.0.36+) hands the parser the whole HEC object record."""
    return input_contract(vrl)[0] in ('json', 'json_or_text')


def pairing_problems(vrl):
    """The content channel serves every install: a v2 contract never changes
    what older nano does. It needs a v1 line, and a bare v1 json_or_text
    (which older nano reads as undeclared, and may infer as JSON) is refused."""
    v1, v2, bad = declarations(vrl)
    problems = list(bad)
    if v2 and not v1:
        problems.append(f'`# nano:input-v2={v2}` without a `# nano:input=json|text` line: older nano would infer its contract')
    return problems


def nano_classifier():
    """nano's own classifier binary (`parser_input_contract`), or None."""
    path = os.environ.get('NANO_INPUT_CONTRACT', '')
    return path if path and os.access(path, os.X_OK) else None


def nano_verdicts(binary, programs):
    lines = ''.join(json.dumps({'name': n, 'parser_vrl': v}) + '\n' for n, v in programs)
    out = subprocess.run([binary], input=lines, capture_output=True, text=True, check=True).stdout
    return {r['name']: r for r in map(json.loads, out.splitlines())}


def without_generated(vrl):
    out, skip = [], None
    for line in vrl.splitlines():
        s = line.strip()
        if skip is None:
            for start, end in GENERATED:
                if s.startswith(start):
                    skip = end
                    break
            if skip is None:
                out.append(line)
        elif s.startswith(skip):
            skip = None
    return '\n'.join(out)


def hec_delivery(vrl, event):
    """The `.message` nano (v2.0.36+) hands a DECLARED parser for an HEC object
    event (hec_normalize and the `<parser>_hec_payload` step). An undeclared
    parser gets the v2.0.35 delivery instead (NAN-5902), which this does not
    model: None."""
    if not input_contract(vrl)[1]:
        return None
    if reads_json_object(vrl):
        return json.dumps(event, separators=(',', ':'))
    if isinstance(event.get('message'), str):
        return event['message']
    if 'message' not in event and isinstance(event.get('line'), str):
        return event['line']
    return json.dumps(event)


# Kept equal to `nano_hecv_reserved` in nanosiem-core vector_config/mod.rs
# (`hec_record_view_vrl!`): record keys never copied onto the root.
HEC_VIEW_RESERVED = {'source_type', 'namespace', 'auth_status', 'timestamp', 'metadata', 'ingest_time',
                     '_inserted_at', 'id', 'ext', 'message', 'sourcetype', 'splunk_sourcetype',
                     'splunk_source', 'splunk_index', 'splunk_channel', 'content_format',
                     'routing_timestamp', 'claimed_source_type'}
# The HEC envelope beside the record: its own time and host, never the record's.
HEC_ENVELOPE = {'time': '2026-11-25T20:00:00Z', 'host': 'hec-envelope-host', 'sourcetype': '_json', 'index': 'main'}


def hec_record_view(vrl, event):
    """The root a declared parser runs on for an HEC object event (nano
    v2.0.36+, `hec_record_view_vrl!` then `<parser>_hec_payload`): the
    envelope and routing keys, a copy of each record key the root lacks, and
    `.message` = what hec_delivery says."""
    root = {'source_type': 'json_generic', 'auth_status': 'authenticated', 'splunk_channel': 'c-1',
            'content_format': 'splunk_hec', 'timestamp': HEC_ENVELOPE['time'], 'host': HEC_ENVELOPE['host'],
            'splunk_sourcetype': HEC_ENVELOPE['sourcetype'], 'splunk_index': HEC_ENVELOPE['index'],
            'metadata': {'forwarded_via': 'splunk_hec'}}
    for k, v in event.items():
        if v is not None and k not in HEC_VIEW_RESERVED and k not in root:
            root[k] = v
    root['message'] = hec_delivery(vrl, event)
    return root


def leaves(value):
    """Every scalar leaf of a JSON value."""
    if isinstance(value, dict):
        for v in value.values():
            yield from leaves(v)
    elif isinstance(value, list):
        for v in value:
            yield from leaves(v)
    elif value is not None:
        yield value


# ---------------------------------------------------------------------------
# Every declared JSON parser, before and after its declaration, through nano's
# own HEC delivery VRL (scripts/nano-hec, copied from nanosiem by
# scripts/nano_hec_sync.py).
#
# "Before" is the parser with its `# nano:input=` lines removed, fed what nano
# v2.0.36+ gives an undeclared JSON-input parser (hec_normalize, then
# HEC_LEGACY_JSON_PAYLOAD_VRL: the v2.0.35 delivery). "After" is the parser as
# shipped, fed what a declared one gets (hec_normalize, then
# HEC_JSON_PAYLOAD_VRL: the lossless record view). Lanes:
#
#   hec_object       an HEC object event (`"event": {...}`), each JSON sample
#                    as the record, sent beside an envelope with its own host
#                    and time: the ONLY lane the declaration may change;
#   hec_string_json  an HEC string event carrying the JSON text;
#   hec_string_text  an HEC string event carrying a plain text line;
#   hec_raw          `/services/collector/raw` (event kind `raw`);
#   hec_unmarked     an object event from a Vector that marks no event kind
#                    (before nano-rs/vector 0.62.0-nano.2);
#   ingest_json / ingest_text   HTTP /ingest bodies, on the root
#                    `parse_content` builds;
#   otlp             an OTLP log (body, `resources`, `attributes`), on the
#                    root `otlp_logs_prep` builds.
#
# Every lane runs the parser's `<parser>_hec_payload` step, as nano renders
# it in front of the parser for every lane (on /ingest and OTLP it must be a
# no-op). Any output difference outside hec_object FAILS. On hec_object the
# declared parser must get the record text, keep it as raw_data, never see
# the envelope host, and parse it exactly as it parses the same record posted
# to /ingest.
# ---------------------------------------------------------------------------
NANO_HEC = Path(__file__).resolve().parent / 'nano-hec'
DECLARATION_LINE = re.compile(r'^\s*#\s*nano:input(-v2)?=.*$', re.M | re.I)
# The splunk_hec source (bytes codec) writes the envelope BESIDE `.message`.
HEC_SOURCE_ENVELOPE = {'timestamp': HEC_ENVELOPE['time'], 'host': HEC_ENVELOPE['host'],
                       'splunk_source': 'hec-envelope-source', 'splunk_index': HEC_ENVELOPE['index'],
                       'splunk_channel': 'c-1'}
PIPELINE_TIME = '2026-11-25T20:00:01Z'
# Keys `_ocsf_prepare` never files from the HEC stash (HEC_SIBLING_SKIP_KEYS_OCSF).
SIBLING_SKIP = {'message', 'parse_error', 'parse_fallback', 'parse_failure', 'claimed_source_type'}
TEXT_LINE = 'plain text line nan5902 user=alice src=10.0.0.9 action=allow'


def nano_hec_program(payload, hec=True, extra=''):
    """hec_normalize (HEC lanes only), then the parser's `<parser>_hec_payload`
    step, as ONE program. nano renders that step in front of the parser for
    EVERY lane routed to it (/ingest and OTLP too, where it must be a no-op),
    so the non-HEC lanes run it as well. In nano these are separate remaps, so
    the event metadata the step reads is laundered to an unknown type first
    (otherwise VRL proves `object(%nano_hec)` cannot fail and refuses the
    program). The stash `_ocsf_prepare` files under `unmapped` is copied to
    `.__stash`."""
    launder = ''.join(f'%{k} = if .__never == true {{ "x" }} else {{ %{k} }}\n'
                      for k in ('nano_hec', 'nano_hec_record', 'nano_hec_event'))
    head = ('%splunk_hec.event_kind = .__kind\n%nano_credential_id = .__cred\n%nano_credential_name = .__route\n'
            'del(.__kind)\ndel(.__cred)\ndel(.__route)\n'
            + (NANO_HEC / 'hec_normalize.vrl').read_text() + '\n'
            + f'.routing_timestamp = "{PIPELINE_TIME}"\n') if hec else ''
    return head + launder + extra + '\n' + (NANO_HEC / payload).read_text() + '\n.__stash = %nano_hec_event\n'


def vector_objects(program, events):
    with tempfile.TemporaryDirectory(prefix='input-contract-') as tmp:
        tmp = Path(tmp)
        (tmp / 'p.vrl').write_text(program)
        (tmp / 'in.json').write_text(''.join(json.dumps(e) + '\n' for e in events))
        out = subprocess.run(['vector', 'vrl', '--program', str(tmp / 'p.vrl'), '--input', str(tmp / 'in.json'),
                              '--print-object'], text=True, capture_output=True, timeout=900, env=VECTOR_ENV)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[-2000:])
    got = [json.loads(l, strict=False) for l in out.stdout.splitlines() if l.startswith('{')]
    if len(got) != len(events):
        raise RuntimeError(f'{len(events)} events in, {len(got)} out (an event aborted?)\n{out.stderr[-2000:]}')
    return got


def samples_of(parser_dir):
    """Each raw log line a parser ships as a sample (inline `samples:` and the
    sidecar `samples/` files, which validate-ocsf.sh unwraps the same way)."""
    doc = yaml.safe_load((parser_dir / 'parser.yaml').read_text())
    raws = []
    for s in doc.get('samples') or []:
        if isinstance(s, dict) and s.get('envelope'):
            continue  # an `envelope: true` sample is an event, not a log line
        raw = s.get('raw') if isinstance(s, dict) else s
        if raw is not None:
            raws.append(raw if isinstance(raw, str) else json.dumps(raw))
    for f in sorted((parser_dir / 'samples').glob('*')) if (parser_dir / 'samples').is_dir() else []:
        text = f.read_text().strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict) and 'message' in parsed:
            if isinstance(parsed['message'], str):
                raws.append(parsed['message'])
        else:
            raws.append(text)
    return raws


def json_record(raw):
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def lane_inputs(name, raws):
    """(lane, sample index, delivered via HEC?, event) for one parser."""
    hec = lambda kind, message: {**HEC_SOURCE_ENVELOPE, 'splunk_sourcetype': name, '__kind': kind,
                                 '__cred': 'cred-nan5902', '__route': name, 'message': message}
    # The roots nano's other lanes build (nanosiem config/vector): /ingest
    # (`parse_content`, 00-base.toml: a JSON body's keys but `message` merged
    # onto the root, `.message` = the body) and OTLP (`otlp_logs_prep`,
    # 03-otlp-source.toml: `.message` = the body, `resources` / `attributes`
    # beside it and copied to `ext`).
    def ingest(raw, record):
        root = {'source_type': name, 'content_format': 'json' if record is not None else 'raw',
                'metadata': {'forwarded_via': 'http'}}
        for k, v in (record or {}).items():
            if k != 'message' and v is not None:
                root[k] = v
        root['message'] = raw
        return root
    otlp_ctx = {'resources': {'service.name': 'nan5902', 'host.name': 'otlp-host-5902'},
                'attributes': {'log.file.name': 'nan5902.log'}}
    otlp = lambda raw: {'source_type': 'otlp_log', 'content_format': 'otlp', 'message': raw, 'severity': 'INFO',
                        'severity_number': 9, **otlp_ctx, 'ext': {**otlp_ctx['resources'], **otlp_ctx['attributes']},
                        'trace_id': '', 'span_id': '', 'metadata': {'forwarded_via': 'otlp'}}
    out = []
    for i, raw in enumerate(raws):
        record = json_record(raw)
        if record is not None:
            # The sender's record text: a sample is one line; a pretty-printed
            # one is sent compact, as a forwarder serializes it.
            text = raw.strip() if '\n' not in raw.strip() else json.dumps(record, separators=(',', ':'))
            out.append(('hec_object', i, True, hec('object', text)))
            out.append(('hec_string_json', i, True, hec('string', raw)))
            out.append(('hec_raw', i, True, hec('raw', raw)))
            # A Vector that marks no event kind (before nano-rs/vector
            # 0.62.0-nano.2): compact JSON text is taken as an object event.
            out.append(('hec_unmarked', i, True, hec(None, text)))
            out.append(('ingest_json', i, False, ingest(raw, record)))
            out.append(('otlp', i, False, otlp(raw)))
        else:
            out.append(('hec_string_text', i, True, hec('string', raw)))
            out.append(('hec_raw', i, True, hec('raw', raw)))
            out.append(('ingest_text', i, False, ingest(raw, None)))
            out.append(('otlp', i, False, otlp(raw)))
    out.append(('hec_string_text', -1, True, hec('string', TEXT_LINE)))
    out.append(('ingest_text', -1, False, ingest(TEXT_LINE, None)))
    out.append(('otlp', -1, False, otlp(TEXT_LINE)))
    return out


def file_stash(event, stash):
    """`_ocsf_prepare`'s HEC sibling merge: stash keys under `unmapped`, never
    over a key the parser set."""
    if isinstance(stash, dict) and (isinstance(event.get('unmapped'), dict) or event.get('unmapped') is None):
        unmapped = dict(event.get('unmapped') or {})
        for k, v in stash.items():
            if k not in SIBLING_SKIP and unmapped.get(k) is None:
                unmapped[k] = v
        if unmapped:
            event['unmapped'] = unmapped
    return event


def flat(value, prefix=''):
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out.update(flat(v, f'{prefix}{k}.'))
        return out if out or not prefix else {prefix[:-1]: {}}
    return {prefix[:-1]: value}


UUID4 = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
VRL_POSITION = re.compile(r' at \(\d+:\d+\)')


def normalize_clock(value, lo, hi):
    """Values that differ from run to run compare equal: the wall clock (a
    parser's `now()` fallback), a random uuid_v4() id, and the program offset
    VRL writes into an error message (the declaration lines shift it)."""
    if isinstance(value, dict):
        return {k: normalize_clock(v, lo, hi) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize_clock(v, lo, hi) for v in value]
    if isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi:
        return '<now>'
    if isinstance(value, str):
        if UUID4.match(value):
            return '<uuid4>'
        return VRL_POSITION.sub(' at (<pos>)', value)
    return value


def delivered(variant_payload, inputs, extra=''):
    """What nano hands the parser for every lane: (root, stash). HEC lanes run
    hec_normalize then the payload step; /ingest and OTLP the payload step."""
    out = [None] * len(inputs)
    for via_hec in (True, False):
        picked = [k for k, (_, _, h, _) in enumerate(inputs) if h == via_hec]
        if not picked:
            continue
        roots = vector_objects(nano_hec_program(variant_payload, hec=via_hec, extra=extra), [inputs[k][3] for k in picked])
        for k, root in zip(picked, roots):
            stash = root.pop('__stash', None)
            root.pop('__never', None)
            out[k] = (root, stash)
    return out


def before_after(name, vrl, mutation=''):
    """Run one parser over every lane, undeclared (before, twice: what differs
    between the two runs is the parser's own clock or randomness) and declared
    (after)."""
    raws = samples_of(ROOT / 'parsers-ocsf' / name)
    if not any(json_record(r) is not None for r in raws):
        # No JSON sample (opentelemetry_logs ships its log bodies): send the
        # first line as an HEC object record, as a forwarder wraps it.
        raws.append(json.dumps({'message': raws[0] if raws else TEXT_LINE, 'timestamp': '2026-11-24T01:02:03Z',
                                'host': 'Rec-Host-5902', 'service': 'nan5902'}, separators=(',', ':')))
    inputs = lane_inputs(name, raws)
    undeclared = DECLARATION_LINE.sub('', vrl)
    sides = {}
    for side, payload, program, extra in (('before', 'hec_legacy_json_payload.vrl', undeclared, ''),
                                          ('again', 'hec_legacy_json_payload.vrl', undeclared, ''),
                                          ('after', 'hec_json_payload.vrl', vrl, mutation)):
        roots = delivered(payload, inputs, extra)
        parser_in = [d[0] for d in roots]
        stashes = [d[1] for d in roots]
        lo = int(time.time() * 1000) - 1000
        outs = vector_objects(program, parser_in)
        hi = int(time.time() * 1000) + 1000
        sides[side] = [normalize_clock(file_stash(o, st), lo, hi) for o, st in zip(outs, stashes)]
        sides[side + '_in'] = parser_in
    return raws, inputs, sides


def differing(a, b, skip=()):
    fa, fb = flat(a), flat(b)
    return sorted(k for k in set(fa) | set(fb) if fa.get(k) != fb.get(k) and k not in skip)


# JSON-input parsers kept undeclared on purpose (name: why). Each still gets
# the v2.0.35 HEC delivery on nano v2.0.36+.
UNDECLARED_ON_PURPOSE = {}

# Declared parsers whose own code reads more of the event than `.message`, so
# an HEC event (envelope keys on the root) need not parse as an /ingest body.
ROOT_READERS = {
    # An OTLP log parser: it reads the OTLP root (timestamp, attributes,
    # resource, trace ids). Over HEC the root `timestamp` is the envelope's.
    'opentelemetry_logs',
}


def check_as_ingest(failures, where, hec, ingest, skip, compacted):
    """A declared parser reads an HEC object record as it reads the same
    record posted to /ingest."""
    if compacted:
        skip = skip | {'raw_data', 'metadata.uid'}  # a pretty-printed sample is sent compact
    diff = differing(hec, ingest, skip)
    if diff:
        failures.append(f'{where}: declared, the HEC object event does not parse as its /ingest body does: {diff[:8]}')


def compare_parser(name, vrl, mutation=''):
    """(failures, report row) for one declared parser.

    - Every lane but hec_object: the output equals the undeclared parser's.
    - hec_object: the declared parser gets the record text and its output
      equals its /ingest output for the same sample (what the declaration
      promises: an HEC object event is read as /ingest reads it), raw_data is
      the record as sent, and the envelope host never reaches the event.
      The before / after difference is reported, not judged."""
    failures = []
    raws, inputs, sides = before_after(name, vrl, mutation)
    unstable = [set(differing(b, g)) for b, g in zip(sides['before'], sides['again'])]
    ingest = {i: k for k, (lane, i, _, _) in enumerate(inputs) if lane == 'ingest_json'}
    row = {'parser': name, 'samples': len(raws), 'hec_object': 0, 'changed': 0, 'fields': {}, 'classes': [], 'lanes': {}}
    for k, (lane, i, _, event) in enumerate(inputs):
        before, after, after_in = sides['before'][k], sides['after'][k], sides['after_in'][k]
        row['lanes'][lane] = row['lanes'].get(lane, 0) + 1
        where = f'{name} {lane} sample {i}'
        if lane != 'hec_object':
            diff = differing(before, after, unstable[k])
            if diff:
                failures.append(f'{where}: the declaration changed the output outside the HEC object lane: {diff[:8]}')
            continue
        row['hec_object'] += 1
        record_text = event['message']
        record = json_record(record_text) or {}
        if len(record) == 1 and isinstance(record.get('message'), dict):
            # `{"message": {...}}` alone is a wrapper: nano unwraps it for
            # every parser (hec_normalize), so the declaration changes nothing.
            row['wrappers'] = row.get('wrappers', 0) + 1
            diff = differing(before, after, unstable[k])
            if diff:
                failures.append(f'{where}: a wrapper record parses differently once declared: {diff[:8]}')
            continue
        if after_in.get('message') != record_text:
            failures.append(f'{where}: nano did not hand the declared parser the record text')
        if 'raw_data' in after and after['raw_data'] != record_text:
            failures.append(f'{where}: raw_data is not the record as sent: {str(after["raw_data"])[:80]!r}')
        if HEC_ENVELOPE['host'] in json.dumps(after):
            failures.append(f'{where}: the HEC envelope host reached the declared event')
        if name not in ROOT_READERS:  # a root reader's HEC root is not an /ingest root
            check_as_ingest(failures, where, after, sides['after'][ingest[i]], unstable[k] | unstable[ingest[i]],
                            record_text != raws[i])
        changed = differing(before, after, unstable[k])
        if changed:
            row['changed'] += 1
        if before.get('class_uid') != after.get('class_uid'):
            row['classes'].append(f'{before.get("class_uid")}->{after.get("class_uid")}')
        for key in changed:
            key = 'unmapped.*' if key.startswith('unmapped.') else key
            row['fields'][key] = row['fields'].get(key, 0) + 1
    return failures, row


# The test must catch a declared delivery that breaks a lane it never should
# touch. Each mutation runs in front of the declared parser's payload step
# (where an HEC object event still carries `%nano_hec_record`) and must fail
# exactly its lanes.
MUTATIONS = (
    # hec_object fails too: it is checked against the /ingest output.
    ('/ingest and OTLP',
     'if includes(["json", "raw", "otlp"], .content_format) { .message = "{\\"mutated\\":1}" }',
     {'ingest_json', 'ingest_text', 'otlp', 'hec_object'}),
    ('HEC string, /raw and unmarked',
     'if .content_format == "splunk_hec" && !is_object(%nano_hec_record) { .message = "mutated line" }',
     {'hec_string_json', 'hec_string_text', 'hec_raw', 'hec_unmarked'}),
    ('the HEC object record',
     'if is_object(%nano_hec_record) { %nano_hec_record = {"text": "{\\"mutated\\":1}", "unfiled": {}} }',
     {'hec_object'}),
)


def mutation_checks(failures):
    """Prove the lane comparisons are live: break the declared delivery on one
    group of lanes at a time (json_generic) and require exactly that group to
    fail."""
    vrl = yaml.safe_load((ROOT / 'parsers-ocsf/json_generic/parser.yaml').read_text())['parser_vrl']
    for label, mutation, lanes in MUTATIONS:
        fails, _ = compare_parser('json_generic', vrl, mutation)
        hit = {f.split(' ')[1] for f in fails}
        if not lanes <= hit:
            failures.append(f'mutation check ({label}): a broken declared delivery went unnoticed on {sorted(lanes - hit)}')
        if hit - lanes:
            failures.append(f'mutation check ({label}): it also failed {sorted(hit - lanes)} (mutation not lane-specific)')
    return len(MUTATIONS)


def declared_delivery_checks(failures, report_path=None):
    """Every parser that declares a JSON contract, before vs after, on every lane."""
    from concurrent.futures import ThreadPoolExecutor
    programs = []
    for path in sorted((ROOT / 'parsers-ocsf').glob('*/parser.yaml')):
        vrl = yaml.safe_load(path.read_text())['parser_vrl']
        contract, declared, _ = input_contract(vrl)
        if declared and contract in ('json', 'json_or_text'):
            programs.append((path.parent.name, vrl))
    workers = max(1, min(int(os.environ.get('INPUT_CONTRACT_JOBS', '6')), len(programs)))
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for name, (fails, row) in zip([n for n, _ in programs], pool.map(lambda p: compare_parser(*p), programs)):
            failures.extend(fails)
            rows.append(row)
    if report_path:
        Path(report_path).write_text(json.dumps(rows, indent=1, sort_keys=True))
    lanes = sum(sum(r['lanes'].values()) for r in rows)
    return f'; {len(programs)} declared JSON parsers identical before / after on every non-HEC-object lane ({lanes} runs each side)'


def main():
    failures = []
    parsers = sorted((ROOT / 'parsers-ocsf').glob('*/parser.yaml'))
    for path in parsers:
        vrl = yaml.safe_load(path.read_text())['parser_vrl']
        own, full = legacy_reads_json_object(without_generated(vrl)), legacy_reads_json_object(vrl)
        if own != full:
            failures.append(f'{path.parent.name}: the generated blocks turn a {"JSON" if own else "text"}-input parser into a {"JSON" if full else "text"}-input one on nano before v2.0.36 (it hands it the wrong HEC / OTLP payload)')

    templates = ROOT / 'scripts' / 'residual'
    code_of = lambda name: '\n'.join(l for l in (templates / name).read_text().splitlines() if not l.strip().startswith('#'))
    for name in ('source_tz.vrl', 'local_clock.vrl'):
        hit = FIRST_DECODER.search(code_of(name))
        if hit:
            failures.append(f'scripts/residual/{name}: {hit.group(0)} ahead of the parser decides its input contract; use match / slice')
    for name in ('spill.vrl', 'transforms.vrl'):
        hit = LINE_DECODER.search(code_of(name))
        if hit:
            failures.append(f'scripts/residual/{name}: {hit.group(0)} anywhere in a program makes nano treat the parser as text; it would flip every JSON-input parser')

    # The pairing rules themselves.
    for vrl, want in (('# nano:input=text\n# nano:input-v2=json_or_text\n. = .', 0),
                      ('# nano:input-v2=json_or_text\n. = .', 1),
                      ('# nano:input=json_or_text\n. = .', 1),
                      ('# nano:input-v2=jsonish\n# nano:input=text\n. = .', 1),
                      # Conflicting duplicates, as nano's classifier warns.
                      ('# nano:input=text\n# nano:input=json\n. = .', 1),
                      ('# nano:input=text\n# nano:input=json_or_text\n. = .', 2),
                      ('# nano:input=text\n# nano:input-v2=json\n# nano:input-v2=text\n. = .', 1),
                      ('# nano:input=text\n# nano:input=text\n. = .', 0)):
        if len(pairing_problems(vrl)) != want:
            failures.append(f'pairing check: {vrl!r} gave {pairing_problems(vrl)}')
    if input_contract('# nano:input=text\n# nano:input-v2=json_or_text\n. = .')[0] != 'json_or_text' or \
            legacy_reads_json_object('# nano:input=text\n# nano:input-v2=json_or_text\np = parse_json!(.message)'):
        failures.append('v2 must win on v2.0.36+ and be invisible to the pre-v2.0.36 rule')

    pinned = {l.strip() for l in (ROOT / 'scripts' / 'json-input-parsers.txt').read_text().splitlines() if l.strip() and not l.startswith('#')}
    for path in parsers:
        name = path.parent.name
        vrl = yaml.safe_load(path.read_text())['parser_vrl']
        is_json = legacy_reads_json_object(vrl)
        if is_json != (name in pinned):
            failures.append(f'{name}: nano before v2.0.36 reads it as a {"JSON" if is_json else "text"}-input parser, scripts/json-input-parsers.txt says {"JSON" if name in pinned else "text"}')
        failures.extend(f'{name}: {p}' for p in pairing_problems(vrl))
    for name in sorted(pinned - {p.parent.name for p in parsers}):
        failures.append(f'scripts/json-input-parsers.txt: {name} is not a parser')

    # Advisory: a `text` parser that tries parse_json first reads JSON records
    # too; on nano v2.0.36+ it gets an HEC object record's `message` line, not
    # the record, until it declares json_or_text.
    for path in parsers:
        if reads_json_first(yaml.safe_load(path.read_text())['parser_vrl']):
            print(f'NOTE {path.parent.name}: input contract `text` but parse_json first; on nano v2.0.36+ add `# nano:input-v2=json_or_text` once it tells a forwarder wrapper from its records')

    binary = nano_classifier()
    programs = [(p.parent.name, yaml.safe_load(p.read_text())['parser_vrl']) for p in parsers]
    if binary:
        nano = nano_verdicts(binary, programs)
        for name, vrl in programs:
            port = input_contract(vrl)
            got = nano.get(name) or {}
            v1, v2, _ = declarations(vrl)
            legacy = 'json' if legacy_reads_json_object(vrl) else 'text'
            if (got.get('contract'), got.get('declared'), got.get('inferred')) != port or \
                    (got.get('declared_v1'), got.get('declared_v2'), got.get('legacy')) != (v1, v2, legacy) or \
                    bool(got.get('reads_json_first')) != reads_json_first(vrl):
                failures.append(f'{name}: nano classifies it {got}, the Python port {port}')
            for w in got.get('warnings') or []:
                failures.append(f'{name}: nano warns about its input contract: {w}')
        checked = f'; nano\'s classifier ({binary}) agrees on all {len(programs)}'
    else:
        checked = ('; nano\'s classifier binary not available (set NANO_INPUT_CONTRACT, see '
                   'scripts/input-contract.lock): checked with the Python port only')

    vrl = yaml.safe_load((ROOT / 'parsers-ocsf/json_generic/parser.yaml').read_text())['parser_vrl']
    if not reads_json_object(vrl):
        failures.append('json_generic: not classified as a JSON-input parser')
    # NAN-5902: from nano v2.0.36 an UNDECLARED parser gets the v2.0.35 HEC
    # delivery: an object event's own host / timestamp replaced by the
    # envelope's, and an object `message` alone in raw_data. The default
    # parser must declare its contract to receive the whole record.
    if input_contract(vrl)[:2] != ('json', True) or declarations(vrl)[0] != 'json':
        failures.append('json_generic: must declare `# nano:input=json` (undeclared, nano v2.0.36+ gives it the '
                        'v2.0.35 HEC delivery and an HEC object event loses its own host / timestamp)')
    shapes = {
        # Splunk HEC: {"event": {"message": "...", "k": 1}, "sourcetype": "_json"}
        'hec_object': {'message': 'hec1 contract obj', 'k': 1, 'user': 'alice'},
        # An OTel-style forwarder: the log body as message, attributes and resource beside it.
        'otel': {'message': 'otel contract line', 'severity_text': 'WARN',
                 'attributes': {'http.method': 'GET', 'k': 2}, 'resource': {'service.name': 'checkout'}},
    }
    for name, event in shapes.items():
        message = hec_delivery(vrl, event)
        if message is None:
            failures.append(f'json_generic {name}: undeclared, it gets the v2.0.35 HEC delivery')
            continue
        (out, _), = run('json_generic', [hec_record_view(vrl, event)])
        unmapped = out.get('unmapped') or {}
        if 'parse_error' in unmapped or (out.get('metadata') or {}).get('log_level') == 'error':
            failures.append(f'json_generic {name}: parse_error {unmapped.get("parse_error")!r} (delivered {message[:60]!r})')
        if out.get('raw_data') != message:
            failures.append(f'json_generic {name}: raw_data {out.get("raw_data")!r} is not the delivered payload')
        siblings = [k for k in event if k != 'message']
        kept = set(unmapped) | set(out)
        lost = [k for k in siblings if not any(x == k or x.startswith(k + '.') for x in kept)]
        if lost:
            failures.append(f'json_generic {name}: sibling field(s) {lost} not kept outside raw_data')

    # NAN-5902 (the v2.0.36 RC2 fresh-install finding): an HEC object event
    # with its OWN host and timestamp and an object `message`. Through the
    # record view the parser must take time and host from the record (never
    # the envelope's), keep the record byte for byte in raw_data, and keep
    # every value searchable outside raw_data.
    record = {'marker': 'hec-obj-5902', 'timestamp': '2026-11-24T01:02:03Z', 'host': 'Rec-Host-5902',
              'n': 42, 'f': 1.5, 'b': True, 'arr': [1, 'two', {'three': 3}],
              'deep': {'l1': {'l2': {'l3': 'deep-5902'}}}, 'a.b': 'flat-5902', 'a': {'b': 'nested-5902'},
              'nul': None, 'message': {'inner': 'msg-obj-5902'}}
    lossless = 0
    if hec_delivery(vrl, record) is not None:
        root = hec_record_view(vrl, record)
        (out, _), = run('json_generic', [root])
        unmapped = out.get('unmapped') or {}
        if 'parse_error' in unmapped:
            failures.append(f'json_generic hec record: parse_error {unmapped["parse_error"]!r}')
        if out.get('raw_data') != root['message']:
            failures.append(f'json_generic hec record: raw_data {out.get("raw_data")!r} is not the record text')
        if out.get('time') != 1795482123000:
            failures.append(f'json_generic hec record: time {out.get("time")!r} is not the record timestamp (2026-11-24T01:02:03Z)')
        if (out.get('device') or {}).get('hostname') != 'rec-host-5902':
            failures.append(f'json_generic hec record: device.hostname {(out.get("device") or {}).get("hostname")!r} is not the record host')
        if HEC_ENVELOPE['host'] in json.dumps(out):
            failures.append('json_generic hec record: the HEC envelope host reached the event')
        mapped = json.dumps(unmapped)
        for leaf in leaves(record):
            if leaf == record['timestamp']:
                continue  # consumed into `time`, asserted above
            text = json.dumps(leaf) if not isinstance(leaf, str) else leaf
            if text not in mapped:
                failures.append(f'json_generic hec record: value {leaf!r} not kept in unmapped (only in raw_data)')
        lossless = 1

    # Text and JSON over the other lanes, unchanged by the declaration: an HEC
    # string event or /raw body and an /ingest body arrive as `.message` = the
    # text. JSON text parses; a plain line keeps raw_data and reports the error.
    for name, text, is_json in (('hec string json', '{"marker":"str-json-5902","x":{"y":"z"}}', True),
                                ('ingest json', '{"marker":"ingest-5902","user":"alice","n":7}', True),
                                ('hec string text', 'plain text str-5902 k=v user=alice', False),
                                ('ingest text', 'raw line ingest-5902 src=10.0.0.9 action=allow', False)):
        (out, _), = run('json_generic', [{'message': text, 'source_type': 'json_generic'}])
        unmapped = out.get('unmapped') or {}
        if out.get('raw_data') != text:
            failures.append(f'json_generic {name}: raw_data {out.get("raw_data")!r} is not the delivered text')
        if is_json and ('parse_error' in unmapped or unmapped.get('marker') != json.loads(text)['marker']):
            failures.append(f'json_generic {name}: JSON text not parsed: {unmapped}')
        if not is_json and 'parse_error' not in unmapped:
            failures.append(f'json_generic {name}: a non-JSON line must report unmapped.parse_error')

    # NAN-5902: every JSON-input parser states its contract, so nano v2.0.36+
    # hands it an HEC object event's whole record (undeclared, it gets the
    # v2.0.35 delivery: the record's own host / timestamp replaced by the
    # envelope's). A parser kept undeclared on purpose is listed, with why.
    for name in sorted(pinned):
        path = ROOT / 'parsers-ocsf' / name / 'parser.yaml'
        if not path.exists() or name in UNDECLARED_ON_PURPOSE:
            continue
        if not input_contract(yaml.safe_load(path.read_text())['parser_vrl'])[1]:
            failures.append(f'{name}: a JSON-input parser must declare `# nano:input=json` (undeclared, nano v2.0.36+ '
                            'gives it the v2.0.35 HEC delivery and an HEC object event loses its own host / timestamp)')

    # The nano HEC VRL copy, against a nanosiem checkout when one is named.
    nanosiem = os.environ.get('NANOSIEM_GIT', '')
    if nanosiem:
        sync = subprocess.run([sys.executable, str(Path(__file__).resolve().parent / 'nano_hec_sync.py'), '--check',
                               nanosiem, os.environ.get('NANOSIEM_REF', 'origin/main')], capture_output=True, text=True)
        if sync.returncode != 0:
            failures.append((sync.stderr or sync.stdout).strip())

    report = next((a.split('=', 1)[1] for a in sys.argv[1:] if a.startswith('--report=')), None)
    lanes = declared_delivery_checks(failures, report)
    lanes += f'; {mutation_checks(failures)} delivery mutations each caught on exactly their lanes'

    for f in failures:
        print('FAIL', f)
    if failures:
        sys.exit(1)
    print(f'PASS input contract: {len(parsers)} parsers keep their HEC / OTLP input contract with the generated blocks '
          f'({len(pinned)} JSON-input, as pinned); '
          f'json_generic declares json and parses {len(shapes) + lossless} HEC object shapes losslessly plus 4 text / JSON lanes{lanes}{checked}')


if __name__ == '__main__':
    main()
