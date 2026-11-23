#!/usr/bin/env python3
"""The hashicorp_vault parser maps faithfully and never masks.

A parser converts raw to real: masking is an opt-in pipeline step, never a
parser concern. This runs every hashicorp_vault sample (sidecar and inline)
plus entries an audit device writes with log_raw=true, hmac_accessor=false or
audit_non_hmac_*_keys through `vector vrl` and asserts, for each one:

- raw_data is the original line, byte for byte;
- no value is replaced: "<redacted>" appears nowhere, and every marker value
  planted in the input (tokens, passwords, payloads, headers, URLs with
  userinfo or a query, error text, warnings, syslog structured data) appears
  unchanged somewhere in the emitted event outside raw_data;
- the captured source equals the parsed JSON entry (syslog header aside), and
  the shared no-loss check() accepts the event;
- a line that is not a Vault audit entry falls back to Base Event with its
  text kept in message and raw_data.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import field_coverage_check as fcc  # noqa: E402  (shared no-loss check)
import residual_spill  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
PARSER = ROOT / 'parsers-ocsf/hashicorp_vault/parser.yaml'
VAULT_JSON = re.compile(r'\{\s*"(?:time|type|auth|request|response|error|forwarded_from)"\s*:')
H = 'hmac-sha256:' + 'ab' * 32
TOKEN = 'hvs.CAESIKEEPfakeTOKEN9999documentationONLYccccccccGh4KHGh2cy5LRUVQ'
SYSLOG = '<110>1 2025-06-04T20:30:00Z vault-0 vault - - [meta@32473 token="KEEP-sd1"] '


def entry(**kw):
    base = {'time': '2025-06-04T20:40:00Z', 'type': 'response',
            'auth': {'client_token': H, 'accessor': H, 'display_name': 'userpass-alice', 'policies': ['default']},
            'request': {'id': 'fid-' + kw.pop('rid'), 'operation': 'update', 'mount_type': 'kv',
                        'path': 'secret/data/app', 'remote_address': '192.0.2.70'}}
    for key, value in kw.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key].update(value)
        else:
            base[key] = value
    return json.dumps(base)


# Every value carrying KEEP- (or TOKEN) must survive outside raw_data.
EXTRA = [
    SYSLOG + json.dumps({
        'time': '2025-06-04T20:30:00Z', 'type': 'request',
        'auth': {'client_token': TOKEN, 'accessor': 'KEEP-accessor-clear', 'display_name': 'token'},
        'request': {'id': 'fid-syslog', 'operation': 'update', 'path': 'secret/data/app',
                    'headers': {'X-Vault-Token': [TOKEN], 'Cookie': ['KEEP-cookie']},
                    'data': {'data': {'db_password': 'KEEP-kv-secret'}},
                    'remote_address': '192.0.2.9'}}),
    entry(rid='kv2', request={'data': {'data': {'password': 'KEEP-a1', 'env': [{'name': 'DB_PASSWORD', 'value': 'KEEP-a2'}]}}},
          response={'mount_type': 'kv', 'data': {'data': {'apiKey': 'KEEP-a3', 'nested': {'deep': ['KEEP-a4']}}}}),
    entry(rid='init', request={'path': 'sys/init', 'mount_type': 'system'},
          response={'data': {'keys': ['KEEP-c1', 'KEEP-c2'], 'root_token': 'KEEP-c3'},
                    'warnings': ['KEEP-warning text'],
                    'wrap_info': {'token': 'KEEP-wrap', 'ttl': 60}}),
    entry(rid='err', error='KEEP-error: backend said ' + TOKEN,
          request={'request_uri': 'https://KEEP-user:KEEP-pass@vault.example.com/v1/secret?KEEP-q=1#KEEP-frag'},
          response={'redirect': '/ui/?KEEP-redirect=1'}),
    json.dumps({'time': '2025-06-04T20:41:02Z', 'type': 'request', 'future_top': 'KEEP-top',
                'request': {'id': 'fid-up', 'operation': 'update', 'mount_type': 'userpass',
                            'path': 'auth/userpass/login/eve', 'data': {'password': 'KEEP-d7'},
                            'remote_address': '192.0.2.73'}}),
    'vault: request failed token=' + TOKEN,
    '{"time":"2025-06-04T20:42:00Z","type":"response","request":{"id":"fid-trunc","path":"KEEP-trunc',
]
MARKER = re.compile(r'KEEP-[A-Za-z0-9_-]+|' + re.escape(TOKEN))


def events():
    doc = yaml.safe_load(PARSER.read_text())
    lines = [s['raw'] if isinstance(s['raw'], str) else json.dumps(s['raw']) for s in doc.get('samples', [])]
    for sample in sorted(PARSER.parent.glob('samples/*.json')):
        lines.append(fcc.envelope(sample.read_text().strip())['message'])
    return doc['parser_vrl'], lines + EXTRA


def source_json(message):
    """The JSON entry in a line, its syslog header removed, or None."""
    body = message.strip()
    if not body.startswith('{'):
        found = VAULT_JSON.search(body)
        if not found:
            return None
        body = body[found.start():]
    try:
        obj = json.loads(body)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def main():
    program, lines = events()
    with tempfile.TemporaryDirectory(prefix='vault-fidelity-') as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / 'p.vrl').write_text(program + '\n.__coverage_source = __source_kv\n')
        (tmp / 'in.json').write_text(''.join(json.dumps({'message': line}) + '\n' for line in lines))
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp / 'p.vrl'), '--input', str(tmp / 'in.json'),
                              '--print-object'], text=True, capture_output=True, timeout=180)
    assert run.returncode == 0, run.stderr
    outputs = [json.loads(l, strict=False) for l in run.stdout.splitlines() if l.startswith('{')]
    assert len(outputs) == len(lines), f'{len(outputs)} events for {len(lines)} lines'
    failures = []
    for index, (line, out) in enumerate(zip(lines, outputs)):
        try:
            source = out.pop('__coverage_source')
            assert out.get('raw_data') == line, 'raw_data is not the original line'
            rest = {k: v for k, v in out.items() if k != 'raw_data'}
            text = json.dumps(rest, ensure_ascii=False)
            assert '<redacted>' not in text and 'withheld' not in text, 'a value was masked'
            for marker in MARKER.findall(line):
                assert marker in text, f'{marker!r} missing outside raw_data'
            entry_obj = source_json(line)
            if out['class_uid'] == 0 and entry_obj is None:
                assert out.get('message') == line, 'fallback message is not the original text'
            if entry_obj is not None:
                header = source.pop('syslog_header', None)
                assert source == entry_obj, 'captured source differs from the parsed entry'
                if header is not None:
                    assert line.strip().startswith(header), 'syslog header altered'
                    source['syslog_header'] = header
                cfg = yaml.safe_load((PARSER.parent / 'field-coverage.yaml').read_text())
                rules = cfg.get('transforms', [])
                fcc.check(source, out, line, rules, mappings=residual_spill.mappings_of(cfg))
        except AssertionError as error:
            failures.append(f'line {index}: {error}')
    if failures:
        print('\n'.join('FAIL ' + f for f in failures))
        raise SystemExit(1)
    print(f'PASS hashicorp_vault fidelity: {len(lines)} lines, raw_data original, nothing masked, no lost field')


if __name__ == '__main__':
    main()
