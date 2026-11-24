#!/usr/bin/env python3
# The classifier below is a PORT of nano's (nanosiem-core
# src/parsers/vector_config/hec_payload.rs, `input_contract`). When nano's own
# classifier binary is available (NANO_INPUT_CONTRACT, or the build pinned in
# scripts/input-contract.lock), this test runs every parser through it too and
# fails on any difference, so the port cannot drift from nano.
"""A parser's input contract survives the generated blocks; HEC / OTel delivery works.

A parser declares what it reads with one comment line in its VRL (nanosiem
NAN-5883, v2.0.36+): `# nano:input=json`, `# nano:input=text` or
`# nano:input=json_or_text`. Undeclared, nano infers it: when the FIRST
structural decoder of the parser's own code is `parse_json` and no line decoder
appears, it is `json`; otherwise `text`. From v2.0.36 nano skips comments and the
generated blocks (prelude, local clock, residual spill, mixed input) when it
infers; older nano versions skip only comments, and know only `json` / `text`
declarations (`json_or_text` reads as undeclared there).

What each contract receives over HEC (nanosiem NAN-5891, v2.0.36+):
- `json` / `json_or_text`: the sender's whole record, unmodified (an object
  event's JSON; a string event's text), as HTTP /ingest does;
- `text`: the record's line (its string `message`, else, with no `message` at
  all, its string `line`), or the whole record when it has none; the record's
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
   every parser's contract (record-reading: json or json_or_text) equal to
   scripts/json-input-parsers.txt;
3. the port equal to nano's classifier binary, when it is available;
4. Generic JSON, fed exactly what nano delivers for a Splunk HEC object event
   and an OTel-style event (message plus attributes / resource), parsing
   without a parse_error and keeping the sibling fields.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_source_timezone import ROOT, run  # noqa: E402

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


def input_contract(vrl):
    """Port of nano `input_contract`: (contract, declared, inferred)."""
    declared = None
    for line in vrl.splitlines():
        c = _comment(line)
        if c is None:
            continue
        c = c.lower()
        if c.startswith('nano:input='):
            value = c[len('nano:input='):].strip()
            if value in CONTRACTS and declared is None:
                declared = value
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
    """Whether nano (v2.0.36+) hands the parser the whole HEC record."""
    return input_contract(vrl)[0] in ('json', 'json_or_text')


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
    """The `.message` nano (v2.0.36+) hands the parser for an HEC object event
    (the `bytes`-decoded record, hec_normalize, the `<parser>_hec_payload` step)."""
    if reads_json_object(vrl):
        return json.dumps(event)
    if isinstance(event.get('message'), str):
        return event['message']
    if 'message' not in event and isinstance(event.get('line'), str):
        return event['line']
    return json.dumps(event)


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

    pinned = {l.strip() for l in (ROOT / 'scripts' / 'json-input-parsers.txt').read_text().splitlines() if l.strip() and not l.startswith('#')}
    for path in parsers:
        name = path.parent.name
        is_json = reads_json_object(yaml.safe_load(path.read_text())['parser_vrl'])
        if is_json != (name in pinned):
            failures.append(f'{name}: nano reads it as a {"JSON" if is_json else "text"}-input parser, scripts/json-input-parsers.txt says {"JSON" if name in pinned else "text"}')
    for name in sorted(pinned - {p.parent.name for p in parsers}):
        failures.append(f'scripts/json-input-parsers.txt: {name} is not a parser')

    # Advisory: a `text` parser that tries parse_json first reads JSON records
    # too; on nano v2.0.36+ it gets an HEC object record's `message` line, not
    # the record, until it declares json_or_text.
    for path in parsers:
        if reads_json_first(yaml.safe_load(path.read_text())['parser_vrl']):
            print(f'NOTE {path.parent.name}: input contract `text` but parse_json first; declare `# nano:input=json_or_text`')

    binary = nano_classifier()
    programs = [(p.parent.name, yaml.safe_load(p.read_text())['parser_vrl']) for p in parsers]
    if binary:
        nano = nano_verdicts(binary, programs)
        for name, vrl in programs:
            port = input_contract(vrl)
            got = nano.get(name) or {}
            if (got.get('contract'), got.get('declared'), got.get('inferred')) != port or \
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
    shapes = {
        # Splunk HEC: {"event": {"message": "...", "k": 1}, "sourcetype": "_json"}
        'hec_object': {'message': 'hec1 contract obj', 'k': 1, 'user': 'alice'},
        # An OTel-style forwarder: the log body as message, attributes and resource beside it.
        'otel': {'message': 'otel contract line', 'severity_text': 'WARN',
                 'attributes': {'http.method': 'GET', 'k': 2}, 'resource': {'service.name': 'checkout'}},
    }
    for name, event in shapes.items():
        message = hec_delivery(vrl, event)
        (out, _), = run('json_generic', [{'message': message}])
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

    for f in failures:
        print('FAIL', f)
    if failures:
        sys.exit(1)
    print(f'PASS input contract: {len(parsers)} parsers keep their HEC / OTLP input contract with the generated blocks '
          f'({len(pinned)} JSON-input, as pinned); '
          f'json_generic parses {len(shapes)} delivered envelope shapes{checked}')


if __name__ == '__main__':
    main()
