#!/usr/bin/env python3
"""No live Vault credential may survive the hashicorp_vault parser.

With log_raw=true (or audit_non_hmac_request_keys) a Vault audit device writes
live tokens, JWTs, passwords and secret payloads in clear. Whatever the
parser stores (raw_data, mapped columns, unmapped spill) is persisted and
text-indexed, so this test runs every hashicorp_vault sample, its inline
samples and a few hostile variants through `vector vrl` and asserts that no
token-shaped value, JWT or known plaintext secret appears anywhere in any
emitted event.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
PARSER = ROOT / 'parsers-ocsf/hashicorp_vault/parser.yaml'
TOKEN = re.compile(r'(?<![A-Za-z0-9])(?:hv[sbr]|[sbr])\.[A-Za-z0-9_-]{20,}')
JWT = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}')
# Plaintext secrets the raw-mode samples carry in non-token-shaped fields.
PLAINTEXT = ['Sup3rS3cretDocPassw0rd', 'plaintext-response-value-doc', 'FAKEaccessorDOC',
             'hostile-plaintext-password', 'hostile-kv-secret-value']

HOSTILE_TOKEN = 'hvs.CAESIHOSTILEfakeTOKEN9999documentationONLYccccccccGh4KHGh2cy5IT1NUSUxF'
HOSTILE = [
    # syslog audit device: header before the JSON, token in a header value
    '<110>1 2025-06-04T20:30:00Z vault-0 vault - - - ' + json.dumps({
        'time': '2025-06-04T20:30:00Z', 'type': 'request',
        'auth': {'client_token': HOSTILE_TOKEN, 'display_name': 'token'},
        'request': {'id': 'h-1', 'operation': 'update', 'path': 'secret/data/app',
                    'headers': {'X-Vault-Token': [HOSTILE_TOKEN]},
                    'data': {'data': {'db_password': 'hostile-kv-secret-value'}},
                    'remote_address': '192.0.2.9'}}),
    # raw mode detected only from the response token; plaintext login password
    json.dumps({'time': '2025-06-04T20:31:00Z', 'type': 'response',
                'request': {'id': 'h-2', 'operation': 'update', 'path': 'auth/ldap/login/eve',
                            'data': {'password': 'hostile-plaintext-password'},
                            'remote_address': '192.0.2.10'},
                'response': {'auth': {'client_token': HOSTILE_TOKEN, 'display_name': 'ldap-eve'}}}),
    # a token in an arbitrary field and in the error text
    json.dumps({'time': '2025-06-04T20:32:00Z', 'type': 'response', 'error': 'bad token ' + HOSTILE_TOKEN,
                'request': {'id': 'h-3', 'operation': 'read', 'path': 'auth/token/lookup',
                            'data': {'token': HOSTILE_TOKEN}, 'remote_address': '192.0.2.11'},
                'response': {'data': {'id': HOSTILE_TOKEN}}}),
    # not JSON at all: the fallback branch keeps raw_data, which must be scrubbed too
    'vault: request failed token=' + HOSTILE_TOKEN,
]


def events():
    doc = yaml.safe_load(PARSER.read_text())
    lines = []
    for sample in sorted((PARSER.parent / 'samples').glob('*.json')):
        text = sample.read_text().strip()
        try:
            obj = json.loads(text, strict=False)
        except json.JSONDecodeError:
            obj = None
        lines.append(obj if isinstance(obj, dict) and set(obj) == {'message'} else {'message': text})
    for sample in doc.get('samples', []):
        lines.append({'message': sample['raw']})
    lines += [{'message': raw} for raw in HOSTILE]
    return doc['parser_vrl'], lines


def main():
    program, inputs = events()
    with tempfile.TemporaryDirectory(prefix='vault-redaction-') as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / 'p.vrl').write_text(program)
        (tmp / 'in.json').write_text(''.join(json.dumps(i) + '\n' for i in inputs))
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp / 'p.vrl'), '--input', str(tmp / 'in.json'),
                              '--print-object'], capture_output=True, text=True, timeout=180)
    assert run.returncode == 0, run.stderr
    outputs = [line for line in run.stdout.splitlines() if line.startswith('{')]
    assert len(outputs) == len(inputs), f'{len(outputs)} events for {len(inputs)} inputs'
    failures = []
    for raw, out in zip(inputs, outputs):
        leaks = TOKEN.findall(out) + JWT.findall(out) + [p for p in PLAINTEXT if p in out]
        if leaks:
            failures.append(f'{raw["message"][:80]}...: leaked {sorted(set(leaks))}')
        if '"raw_data"' not in out:
            failures.append(f'{raw["message"][:80]}...: raw_data missing')
    # The source fixtures really do carry the secrets, so a pass is meaningful.
    corpus = ''.join(i['message'] for i in inputs)
    assert TOKEN.search(corpus) and JWT.search(corpus) and all(p in corpus for p in PLAINTEXT[:2])
    if failures:
        print('\n'.join(failures))
        sys.exit(1)
    print(f'OK: {len(inputs)} Vault events, no token, JWT or plaintext secret in any output')


if __name__ == '__main__':
    main()
