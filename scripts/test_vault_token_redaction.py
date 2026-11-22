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
# Modern hv[sbr]. tokens are base64url; legacy s. / r. service tokens are
# base62 (no '-'), so a hyphenated path segment such as s.payments-prod is not
# one; legacy b. batch tokens are long.
TOKEN = re.compile(r'(?<![A-Za-z0-9])(?:hv[sbr]\.[A-Za-z0-9_-]{8,}|[sr]\.[A-Za-z0-9]{20,}(?![A-Za-z0-9_-])|b\.[A-Za-z0-9_-]{60,})')
JWT = re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}')
# Plaintext secrets the raw-mode samples carry in non-token-shaped fields.
PLAINTEXT = ['Sup3rS3cretDocPassw0rd', 'plaintext-response-value-doc', 'FAKEaccessorDOC',
             'hostile-plaintext-password', 'hostile-kv-secret-value']

HOSTILE_TOKEN = 'hvs.CAESIHOSTILEfakeTOKEN9999documentationONLYccccccccGh4KHGh2cy5IT1NUSUxF'
# Every secret below carries the marker LEAK; no emitted event may contain it.
# The fixtures deliberately use HMAC'd client tokens (so nothing token-shaped
# tells the parser the device is in raw mode), compound or unexpected key
# names, nested and array payloads, unusual headers and broken lines: the scrub
# must fail closed on each of them.
H = 'hmac-sha256:' + 'ab' * 32
SYSLOG = '<110>1 2025-06-04T20:30:00Z vault-0 vault - - - '


def entry(**kw):
    base = {'time': '2025-06-04T20:40:00Z', 'type': 'response',
            'auth': {'client_token': H, 'accessor': H, 'display_name': 'userpass-alice', 'policies': ['default']},
            'request': {'id': 'adv-' + kw.pop('rid'), 'operation': 'update', 'mount_type': 'kv',
                        'path': 'secret/data/app', 'remote_address': '192.0.2.70'}}
    for key, value in kw.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key].update(value)
        else:
            base[key] = value
    return json.dumps(base)


HOSTILE = [
    # syslog audit device: header before the JSON, token in a header value
    SYSLOG + json.dumps({
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
    # --- neon round 2: HMAC'd client token (no raw-mode signal) ---
    # audit_non_hmac_request_keys: KV v2 nested secrets and name/value arrays
    entry(rid='kv2', request={'data': {'data': {'password': 'LEAK-a1', 'db_password': 'LEAK-a2', 'api_key': 'LEAK-a3',
                                                 'env': [{'name': 'DB_PASSWORD', 'value': 'LEAK-a4'}]},
                                        'options': {'cas': 1}}},
          response={'mount_type': 'kv', 'data': {'data': {'apiKey': 'LEAK-a5', 'nested': {'deep': ['LEAK-a6']}}}}),
    # compound / unexpected credential key names
    entry(rid='names', request={'data': {'oidc_client_secret': 'LEAK-b1', 'root_token': 'LEAK-b2',
                                         'access_token': 'LEAK-b3', 'userPassword': 'LEAK-b4',
                                         'private_key_pem': 'LEAK-b5', 'apiKey': 'LEAK-b6', 'conn_url': 'LEAK-b7'}}),
    # sys/init response: unseal keys and the root token
    entry(rid='init', request={'path': 'sys/init', 'mount_type': 'system'},
          response={'data': {'keys': ['LEAK-c1', 'LEAK-c2'], 'keys_base64': ['LEAK-c3'], 'root_token': 'LEAK-c4'}}),
    # unauthenticated log_raw logins: aws iam headers, oidc callback code, userpass password
    json.dumps({'time': '2025-06-04T20:41:00Z', 'type': 'request', 'auth': {'token_type': 'default'},
                'request': {'id': 'adv-aws', 'operation': 'update', 'mount_type': 'aws', 'path': 'auth/aws/login',
                            'data': {'iam_request_headers': 'LEAK-d1', 'iam_request_body': 'LEAK-d2',
                                     'iam_http_request_method': 'POST', 'role': 'LEAK-d3'},
                            'remote_address': '192.0.2.71'}}),
    json.dumps({'time': '2025-06-04T20:41:01Z', 'type': 'request', 'auth': {'token_type': 'default'},
                'request': {'id': 'adv-oidc', 'operation': 'read', 'mount_type': 'oidc',
                            'path': 'auth/oidc/oidc/callback',
                            'data': {'code': 'LEAK-d4', 'state': 'LEAK-d5', 'nonce': 'LEAK-d6'},
                            'remote_address': '192.0.2.72'}}),
    json.dumps({'time': '2025-06-04T20:41:02Z', 'type': 'request',
                'request': {'id': 'adv-up', 'operation': 'update', 'mount_type': 'userpass',
                            'path': 'auth/userpass/login/eve', 'data': {'password': 'LEAK-d7'},
                            'remote_address': '192.0.2.73'}}),
    # a non-prefixed (legacy UUID / dev) token in clear headers; raw accessors; token lookup body
    entry(rid='uuid', auth={'client_token': 'LEAK-e1-uuid-token', 'accessor': 'LEAK-e2-accessor'},
          request={'path': 'auth/token/lookup-self', 'mount_type': 'token', 'client_token_accessor': 'LEAK-e3',
                   'headers': {'X-Vault-Token': ['LEAK-e4'], 'Proxy-Authorization': ['LEAK-e5'],
                               'X-Vault-MFA': ['LEAK-e6'], 'X-Vault-Wrap-Token': ['LEAK-e7'],
                               'Cookie': ['LEAK-e8'], 'X-Custom-Auth': ['LEAK-e9'],
                               'user-agent': ['vault/1.19.1']}},
          response={'data': {'id': 'LEAK-e10', 'accessor': 'LEAK-e11', 'data': {'db_pass': 'LEAK-e12'}},
                    'headers': {'Set-Cookie': ['LEAK-e13']},
                    'wrap_info': {'token': 'LEAK-e14', 'accessor': 'LEAK-e15', 'wrapped_accessor': 'LEAK-e16',
                                  'ttl': 60, 'creation_path': 'sys/wrapping/wrap'},
                    'secret': {'lease_id': 'database/creds/ro/abc', 'secret_key': 'LEAK-e17'},
                    'auth': {'client_token': 'LEAK-e18', 'accessor': 'LEAK-e19', 'display_name': 'token',
                             'metadata': {'username': 'alice', 'api_secret': 'LEAK-e20', 'otp_code': 'LEAK-e21'}}}),
    # credential-named auth metadata; an unknown auth / request / response key
    entry(rid='meta', auth={'metadata': {'role': 'ci', 'password_hint': 'LEAK-f1', 'k8s_jwt': 'LEAK-f2'},
                            'future_field': 'LEAK-f3'},
          request={'future_payload': {'blob': 'LEAK-f4'}}, response={'future_payload': 'LEAK-f5'}),
    # syslog-prefixed line ending in a newline (TCP syslog / journald / file tailers)
    SYSLOG + entry(rid='nl', auth={'accessor': 'LEAK-g1'},
                   request={'path': 'auth/userpass/login/bob', 'mount_type': 'userpass',
                            'data': {'password': 'LEAK-g2'},
                            'headers': {'authorization': ['Basic TEVBSy1nMy1iYXNpYw==']}}) + '\n',
    # RFC 5424 structured data holding a brace before the JSON
    '<110>1 2025-06-04T20:30:00Z vault-0 vault - - [meta@1234 tag="{prod}"] '
    + entry(rid='sd', request={'data': {'password': 'LEAK-h1'}}),
    # truncated (UDP syslog / rsyslog line limit) entries: not parseable JSON
    entry(rid='trunc1', auth={'accessor': 'LEAK-i1'},
          request={'headers': {'authorization': ['Bearer LEAKi2bearertoken'], 'x-vault-token': ['LEAK-i3']},
                   'data': {'password': 'LEAK-i4', 'secret_id': 'LEAK-i5', 'api_key': 'LEAK-i6',
                            'private_key': 'LEAK-i7', 'blob': 'LEAK-i8-truncated-here-and-more'}})[:-40],
    SYSLOG + entry(rid='trunc2', request={'data': {'conn': 'LEAK-i9-cut-in-the-middle-of-value'}})[:-15],
    # unparsable text with key=value credentials
    'vault: login failed user=eve password=LEAK-j1 api_key: LEAK-j2 x-vault-token=LEAK-j3 Authorization: Basic TEVBSy1qNA==',
    # padded JWT, a 5-part JWE, an _-prefixed modern token and a short one, in a kept field (error)
    entry(rid='jwt', error='denied jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJMRUFLLWsxIn0=.c2lnLUxFQUs= jwe '
                           'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..LEAKiv12.LEAKk2ciphertext.LEAKtag3 '
                           'tok_hvs.LEAKk4underscoreprefixed short hvs.LEAKk5shrt1',
          request={'data': {'jwt': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJMRUFLLWs2In0=.c2lnLUxFQUs='}}),
    # PEM private key in an unknown top-level field (kept envelope; line-level scrub)
    entry(rid='pem', extra='-----BEGIN RSA PRIVATE KEY-----\nLEAKm1\n-----END RSA PRIVATE KEY-----'),
]

# Clean, HMAC'd entries must come through byte-for-byte: a path segment that
# merely starts with "s." is not a token.
CLEAN = [
    json.dumps({'time': '2025-06-04T20:50:00Z', 'type': 'response',
                'auth': {'client_token': H, 'accessor': H, 'display_name': 'userpass-alice', 'policies': ['default'],
                         'metadata': {'username': 'alice'}},
                'request': {'id': 'clean-1', 'operation': 'read', 'mount_type': 'kv',
                            'path': 'secret/data/s.payments-prod-us-east-1', 'remote_address': '192.0.2.80',
                            'headers': {'user-agent': ['vault/1.19.1']}},
                'response': {'mount_type': 'kv', 'data': {'data': {'k': H},
                                                          'metadata': {'created_time': H, 'version': 3}}}}),
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
    lines += [{'message': raw} for raw in CLEAN]
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
        leaks += re.findall(r'LEAK[A-Za-z0-9-]*', out) + re.findall(r'TEVBSy[A-Za-z0-9+/=]*', out)
        if leaks:
            failures.append(f'{raw["message"][:80]}...: leaked {sorted(set(leaks))}')
        if '"raw_data"' not in out:
            failures.append(f'{raw["message"][:80]}...: raw_data missing')
        event = json.loads(out, strict=False)
        for path in (('session', 'uid'), ('actor', 'session', 'uid')):
            node = event
            for part in path:
                node = node.get(part) if isinstance(node, dict) else None
            if node is not None and not str(node).startswith('hmac-'):
                failures.append(f'{raw["message"][:80]}...: {".".join(path)} is {node!r}, not an HMAC accessor')
        if raw['message'] in CLEAN:
            if event.get('raw_data') != raw['message']:
                failures.append(f'{raw["message"][:80]}...: clean entry was rewritten')
            if (event.get('resources') or [{}])[0].get('uid') != 'secret/data/s.payments-prod-us-east-1':
                failures.append(f'{raw["message"][:80]}...: clean path corrupted')
        elif raw['message'] in HOSTILE and event.get('class_uid') == 0 and 'LEAK' in raw['message'] and raw['message'].lstrip().startswith(('{', '<')) and 'trunc' not in raw['message']:
            failures.append(f'{raw["message"][:80]}...: parseable hostile entry fell back to Base Event')
    # The source fixtures really do carry the secrets, so a pass is meaningful.
    corpus = ''.join(i['message'] for i in inputs)
    assert TOKEN.search(corpus) and JWT.search(corpus) and all(p in corpus for p in PLAINTEXT[:2])
    assert corpus.count('LEAK') >= 60, corpus.count('LEAK')
    if failures:
        print('\n'.join(failures))
        sys.exit(1)
    print(f'OK: {len(inputs)} Vault events, no token, JWT or plaintext secret in any output')


if __name__ == '__main__':
    main()
