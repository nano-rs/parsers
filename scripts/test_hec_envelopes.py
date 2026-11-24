#!/usr/bin/env python3
"""Parsers parse what an HEC / OTel object event delivers.

Cases live beside each parser in parsers-ocsf/<parser>/hec-envelopes.yaml:

    cases:
    - name: <what it covers>
      event: {<the HEC `event` object, as the sender posts it>}
      expect: {<dotted path>: <value>, ...}     # "<missing>" for absent
      keep: [<a sender key>, ...]                # a wrapper's keys the parser keeps

The delivery follows nano (nanosiem config/vector/02-hec-source.toml
hec_normalize, and nanosiem-core src/parsers/vector_config/hec_payload.rs
HEC_JSON_PAYLOAD_VRL for a JSON-input parser; the classifier is the port in
test_input_contract.py). Vector's splunk_hec source spreads an object event over
the event root, so the sender's other keys sit beside `.message` when the parser
runs (this test puts them there too). An object event with a `message` and
sibling keys is also kept whole in event metadata (%nano_hec_event), which this
test sets the same way:

- no `message`: `.message` is the event's JSON, no stash;
- a `message` and no siblings: `.message` is it (an object JSON-encoded);
- a `message` and siblings: the stash holds the event; `.message` is the
  message (an object JSON-encoded). For a JSON-input parser whose message is
  not itself a JSON object, `.message` becomes the whole event's JSON and the
  stash is removed.

Every case fails on unmapped.parse_fallback / parse_error. A `keep` key (a
wrapper's sender key: the record's own fields are field coverage's to check)
must appear, by value, outside raw_data, unless the parser left the stash: then
nano's prepare step files it under unmapped after the parser.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_input_contract import reads_json_object  # noqa: E402
from test_source_timezone import ROOT, VECTOR_ENV  # noqa: E402


def delivered(vrl, event):
    """(.message, %nano_hec_event or None) as nano hands them to the parser."""
    if 'message' not in event:
        return json.dumps(event, sort_keys=True), None
    message = event['message'] if isinstance(event['message'], str) else json.dumps(event['message'], sort_keys=True)
    if len(event) == 1:
        return message, None
    if reads_json_object(vrl):
        try:
            record = json.loads(message)
        except ValueError:
            record = None
        if not isinstance(record, dict):
            return json.dumps(event, sort_keys=True), None
    return message, event


def vrl_string(text):
    return json.dumps(text, ensure_ascii=False)


def run_case(vrl, message, stash, root):
    prefix = f'%nano_hec_event = parse_json!({vrl_string(json.dumps(stash, ensure_ascii=False))})\n' if stash is not None else ''
    program = prefix + vrl + '\n.__stash_left = %nano_hec_event != null\n'
    with tempfile.TemporaryDirectory(prefix='hec-envelope-') as tmp:
        tmp = Path(tmp)
        (tmp / 'p.vrl').write_text(program)
        (tmp / 'in.json').write_text(json.dumps({**root, 'message': message}) + '\n')
        out = subprocess.run(['vector', 'vrl', '--program', str(tmp / 'p.vrl'), '--input', str(tmp / 'in.json'), '--print-object'],
                             text=True, capture_output=True, timeout=300, env=VECTOR_ENV)
    assert out.returncode == 0, out.stderr
    event = next(json.loads(l, strict=False) for l in out.stdout.splitlines() if l.startswith('{'))
    return event, event.pop('__stash_left', False)


def at(obj, path):
    """A dotted path; a key may itself hold dots (unmapped keys are flattened)."""
    parts = path.split('.')
    if not parts or parts == ['']:
        return obj
    if not isinstance(obj, dict):
        return '<missing>'
    for k in range(len(parts), 0, -1):
        key = '.'.join(parts[:k])
        if key in obj:
            found = at(obj[key], '.'.join(parts[k:])) if k < len(parts) else obj[key]
            if found != '<missing>':
                return found
    return '<missing>'


def main():
    failures, count, parsers = [], 0, set()
    for fixture in sorted((ROOT / 'parsers-ocsf').glob('*/hec-envelopes.yaml')):
        parser = fixture.parent.name
        vrl = yaml.safe_load((fixture.parent / 'parser.yaml').read_text())['parser_vrl']
        for case in yaml.safe_load(fixture.read_text())['cases']:
            count += 1
            parsers.add(parser)
            name, event = f'{parser}: {case["name"]}', case['event']
            message, stash = delivered(vrl, event)
            root = {k: v for k, v in event.items() if k != 'message'}
            out, stash_left = run_case(vrl, message, stash, root)
            unmapped = out.get('unmapped') or {}
            for bad in ('parse_fallback', 'parse_error'):
                if bad in unmapped:
                    failures.append(f'{name}: unmapped.{bad} = {unmapped[bad]!r}')
            for path, want in (case.get('expect') or {}).items():
                got = at(out, path)
                if got != want and str(got) != str(want):
                    failures.append(f'{name}: {path} = {got!r}, want {want!r}')
            if not (stash is not None and stash_left):
                text = json.dumps({k: v for k, v in out.items() if k != 'raw_data'}, ensure_ascii=False)
                for key in case.get('keep') or []:
                    value = event[key]
                    if json.dumps(value, ensure_ascii=False) not in text and str(value) not in text:
                        failures.append(f'{name}: sender key {key}={value!r} lost (only in raw_data)')
    for f in failures:
        print('FAIL', f)
    if failures:
        sys.exit(1)
    print(f'PASS HEC envelopes: {count} delivered shapes parse ({", ".join(sorted(parsers))})')


if __name__ == '__main__':
    main()
