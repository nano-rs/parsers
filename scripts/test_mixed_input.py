#!/usr/bin/env python3
"""The generated mixed-input block (scripts/residual/mixed_input.vrl).

Runs the block in a small program for every delivery shape a mixed source can
reach its parser in, and checks the template stays free of line decoders (one
anywhere in a program makes nano read the parser as text) and that every parser
using the block states its input contract.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from residual_spill import MX_START, mixed_input  # noqa: E402
from test_source_timezone import ROOT, VECTOR_ENV  # noqa: E402

# Kept equal to LINE_DECODER in nanosiem-core hec_payload.rs (and test_input_contract.py).
LINE_DECODER = re.compile(r'\bparse_(syslog|groks|grok|cef|key_value|csv|xml|common_log|apache_log|nginx_log|klog|glog|logfmt|linux_authorization|aws_alb_log|aws_vpc_flow_log|aws_cloudwatch_log_subscription_message)\b')

PROGRAM = '''__mx_body = to_string(.message) ?? encode_json(.)
__mx_line = r'^LINE '
__mx_keys = ["rk", "rk2"]
{block}
. = {{"raw": __mx_raw, "record": __mx_record, "text": __mx_text, "wrapper": __mx_wrapper, "stash_left": %nano_hec_event != null}}
'''

# (name, .message, %nano_hec_event or None, expected outputs)
CASES = [
    ('a text line', 'LINE one', None,
     {'raw': 'LINE one', 'record': {}, 'text': 'LINE one', 'wrapper': {}, 'stash_left': False}),
    ('a JSON record', '{"rk":1,"message":"prose"}', None,
     {'raw': '{"rk":1,"message":"prose"}', 'record': {'rk': 1, 'message': 'prose'}, 'text': '', 'wrapper': {}}),
    ('a wrapper around a text line', '{"message":"LINE two","pod":"p1"}', None,
     {'text': 'LINE two', 'wrapper': {'pod': 'p1'}, 'record': {}}),
    ('a JSON record whose message only looks like prose', '{"message":"not a line","rk2":"x"}', None,
     {'record': {'message': 'not a line', 'rk2': 'x'}, 'text': ''}),
    ('over HEC: an object message alone, the event in the stash', '{"content":"c","format":"simple"}',
     {'rk': 'r1', 'message': {'content': 'c', 'format': 'simple'}},
     {'record': {'rk': 'r1', 'message': {'content': 'c', 'format': 'simple'}}, 'text': '', 'stash_left': False}),
    ('over HEC: a forwarder text beside the record, the record in the stash', 'forwarder note',
     {'rk': 'r1', 'message': 'forwarder note'},
     {'record': {'rk': 'r1', 'message': 'forwarder note'}, 'text': '', 'stash_left': False}),
    ('over HEC to a text parser: a line with siblings stays a line (nano files the siblings)', 'LINE three',
     {'message': 'LINE three', 'pod': 'p1'},
     {'text': 'LINE three', 'record': {}, 'stash_left': True}),
    ('a stash that is no record of this source is left alone', 'some text', {'message': 'some text', 'other': 1},
     {'text': 'some text', 'record': {}, 'stash_left': True}),
    ('an object root without message (a decoded record)', None, None,
     {'record': {'rk': 5}, 'text': ''}),
]


def run(message, stash):
    block = mixed_input()
    prefix = f'%nano_hec_event = parse_json!({json.dumps(json.dumps(stash))})\n' if stash is not None else ''
    with tempfile.TemporaryDirectory(prefix='mixed-input-') as tmp:
        tmp = Path(tmp)
        (tmp / 'p.vrl').write_text(prefix + PROGRAM.format(block=block))
        event = {'message': message} if message is not None else {'rk': 5}
        (tmp / 'in.json').write_text(json.dumps(event) + '\n')
        out = subprocess.run(['vector', 'vrl', '--program', str(tmp / 'p.vrl'), '--input', str(tmp / 'in.json'), '--print-object'],
                             text=True, capture_output=True, timeout=120, env=VECTOR_ENV)
    assert out.returncode == 0, out.stderr
    return next(json.loads(l, strict=False) for l in out.stdout.splitlines() if l.startswith('{'))


def main():
    failures = []
    for name, message, stash, want in CASES:
        got = run(message, stash)
        for key, value in want.items():
            if got.get(key) != value:
                failures.append(f'{name}: {key} = {got.get(key)!r}, want {value!r}')
    code = '\n'.join(l for l in (ROOT / 'scripts/residual/mixed_input.vrl').read_text().splitlines() if not l.strip().startswith('#'))
    hit = LINE_DECODER.search(code)
    if hit:
        failures.append(f'scripts/residual/mixed_input.vrl: {hit.group(0)} would make every parser using it a text-input one')
    users = 0
    for path in sorted((ROOT / 'parsers-ocsf').glob('*/parser.yaml')):
        text = path.read_text()
        if MX_START in text:
            users += 1
            if not re.search(r'^[ \t]*# nano:input=(?:json|text)[ \t]*$', text, re.M):
                failures.append(f'{path.parent.name}: uses the mixed-input block without stating its input contract')
    for f in failures:
        print('FAIL', f)
    if failures:
        sys.exit(1)
    print(f'PASS mixed input: {len(CASES)} delivery shapes; {users} parser(s) use the block, each with a stated contract')


if __name__ == '__main__':
    main()
