#!/usr/bin/env python3
# The classifier below is a PORT of nano's: nanosiem-core
# src/parsers/vector_config/hec_payload.rs (`vrl_reads_json_object`,
# FIRST_DECODER / LINE_DECODER, HEC_JSON_PAYLOAD_VRL). Keep it equal to that file
# until nanosiem NAN-5883 (an explicit input contract, checked by nano itself)
# replaces this copy.
"""A parser's input contract survives the generated blocks; HEC / OTel delivery works.

nano decides what a parser receives for an HEC (or OTel-style) object event from
the parser's program (nanosiem-core `parsers/vector_config/hec_payload.rs`,
`vrl_reads_json_object`): comment lines are skipped (`# nano:input=json|text`
declares it), and when the FIRST structural decoder is `parse_json` and no line
decoder appears, the parser is JSON-input and gets the whole event object as
its `.message`. Otherwise it is a text parser and gets the event's `message`
text alone.

The generated blocks (the source-timezone prelude at the top of every parser,
the local-clock blocks, the residual spill) must never change that answer. The
prelude once called parse_regex, which made `regex` the first decoder of every
parser: Generic JSON (and every JSON-input parser) became a text parser, and
every HEC / OTLP event got unmapped.parse_error. This test keeps:

1. the classification of every parser equal with and without the prelude and
   local-clock blocks;
2. the generated templates free of any structural decoder ahead of the parser
   (prelude, local clock) and of any LINE decoder anywhere (spill, transforms:
   one there flips every JSON-input parser to text);
   every parser's contract equal to scripts/json-input-parsers.txt;
3. Generic JSON, fed exactly what nano delivers for a Splunk HEC object event
   and an OTel-style event (message plus attributes / resource), parsing
   without a parse_error and keeping the sibling fields.
"""
import json
import re
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


def reads_json_object(vrl):
    """Port of nanosiem `vrl_reads_json_object`."""
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
    """The `.message` nano hands the parser for an HEC object event that has a
    `message` (hec_normalize + the `<parser>_hec_payload` step)."""
    if reads_json_object(vrl):
        record = None
        try:
            record = json.loads(event['message'])
        except (TypeError, ValueError):
            pass
        return event['message'] if isinstance(record, dict) else json.dumps(event, sort_keys=True)
    return event['message']


def main():
    failures = []
    parsers = sorted((ROOT / 'parsers-ocsf').glob('*/parser.yaml'))
    for path in parsers:
        vrl = yaml.safe_load(path.read_text())['parser_vrl']
        own, full = reads_json_object(without_generated(vrl)), reads_json_object(vrl)
        if own != full:
            failures.append(f'{path.parent.name}: the generated blocks turn a {"JSON" if own else "text"}-input parser into a {"JSON" if full else "text"}-input one (nano hands it the wrong HEC / OTLP payload)')

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
          f'json_generic parses {len(shapes)} delivered envelope shapes')


if __name__ == '__main__':
    main()
