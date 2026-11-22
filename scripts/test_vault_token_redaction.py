#!/usr/bin/env python3
"""No live Vault credential may survive the hashicorp_vault parser.

With log_raw=true (or audit_non_hmac_request_keys) a Vault audit device writes
live tokens, JWTs, passwords and secret payloads in clear. Whatever the
parser stores (raw_data, mapped columns, unmapped spill) is persisted and
text-indexed, so this test runs every hashicorp_vault sample, its inline
samples and a few hostile variants through `vector vrl` and asserts that no
token-shaped value, JWT or known plaintext secret appears anywhere in any
emitted event.

It also holds the strict source check field_coverage_check.py cannot run on
this parser (field-coverage.yaml declares it a text source because the
scrubbed source can never equal the input): for every entry the captured
source must equal the input JSON (syslog header removed) except at
"<redacted>" leaves, with exactly the same keys, and the shared no-loss
check() and residual probe object run on the result. A clean, HMAC'd sample
must come through with no redaction at all (source and raw_data unchanged).

A line that is not a complete Vault audit entry must keep none of its text:
raw_data is a fixed marker with the original's byte length and SHA-256, and no
word of the original may appear anywhere in the event.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import field_coverage_check as fcc  # noqa: E402  (shared no-loss check, unmodified)

ROOT = pathlib.Path(__file__).resolve().parents[1]
PARSER = ROOT / 'parsers-ocsf/hashicorp_vault/parser.yaml'
# Modern hv[sbr]. tokens are base64url; legacy s. / r. service tokens are
# base62 (no '-'), so a hyphenated path segment such as s.payments-prod is not
# one; legacy b. batch tokens are long.
TOKEN = re.compile(r'(?<![A-Za-z0-9])(?:hv[sbr]\.[A-Za-z0-9_-]{8,}|[sr]\.[A-Za-z0-9]{20,}(?![A-Za-z0-9_-])|b\.[A-Za-z0-9_-]{60,})')
# A JWT (padding allowed) or a 5-part JWE, whose second segment is not eyJ.
JWT = re.compile(r'ey[A-Za-z0-9_=-]{6,}\.(?:ey[A-Za-z0-9_=-]{6,}|[A-Za-z0-9_=-]*\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.)')
HMAC = re.compile(r'^hmac-sha256:[0-9a-f]{64}$')
VAULT_JSON = re.compile(r'\{\s*"(?:time|type|auth|request|response|error|forwarded_from)"\s*:')
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
    # --- neon round 3 ---
    # unknown top-level keys on a parseable entry
    entry(rid='top', extra={'password': 'LEAK-o1', 'api_key': 'LEAK-o2', 'secret_val': 'LEAK-o3'},
          custom_blob='LEAK-o4', listed=['LEAK-o5', {'x': 'LEAK-o6'}]),
    # the request URI query string (OIDC callback code, ?token=)
    entry(rid='uri', request={'path': 'auth/oidc/oidc/callback', 'mount_type': 'oidc',
                              'request_uri': '/v1/auth/oidc/oidc/callback?state=st1&code=LEAK-p1&token=LEAK-p2'}),
    # truncated token lookup / KV v2 bodies whose secrets sit under id / name / username / path
    entry(rid='trunc3', request={'path': 'auth/token/lookup-self', 'mount_type': 'token'},
          response={'data': {'id': 'LEAK-q1-uuid-token', 'name': 'LEAK-q2', 'policies': ['default'],
                             'blob': 'x' * 40}})[:-30],
    entry(rid='trunc4', request={'data': {'data': {'id': 'LEAK-q3', 'name': 'LEAK-q4', 'username': 'LEAK-q5',
                                                    'path': 'LEAK-q6', 'email': 'LEAK-q7', 'role': 'LEAK-q8',
                                                    'error': 'LEAK-q9', 'blob': 'x' * 40}}})[:-30],
    # a continuation fragment with no opening brace
    '"password":"LEAK-r1","api_key":"LEAK-r2","token":"LEAK-r3","conn":"LEAK-r4"}',
    # quoted values with spaces and non-Bearer Authorization schemes in free text
    'vault: login failed password="LEAK-s1 LEAK-s2" Authorization: Token LEAK-s3 '
    'authorization=Digest LEAK-s4 Proxy-Authorization: AWS4-HMAC-SHA256 LEAK-s5 secret=\'LEAK-s6 LEAK-s7\'',
    # values that merely start with "hmac-" are not Vault HMACs
    entry(rid='fakehmac', auth={'client_token': 'hmac-LEAK-t1', 'accessor': 'hmac-LEAK-t2'},
          request={'data': {'signing_key': 'hmac-LEAK-t3', 'k2': 'hmac-sha256:LEAK-t4'}}),
    # credentials in RFC 5424 structured data of a parseable syslog line
    '<110>1 2025-06-04T20:30:00Z vault-0 vault - - [meta@1234 token="LEAK-u1" password=LEAK-u2] '
    + entry(rid='sdtok'),
    # nested auth.metadata, and a PGP private key block in a kept field
    entry(rid='meta2', auth={'metadata': {'role': 'ci', 'custom': {'password': 'LEAK-v1', 'api_key': 'LEAK-v2'},
                                          'list': ['LEAK-v3']}},
          error='-----BEGIN PGP PRIVATE KEY BLOCK-----\nLEAK-w1\n-----END PGP PRIVATE KEY BLOCK-----'),
]

# Round 4: entries that parse, with credentials in the remaining edge cases.
HOSTILE += [
    entry(rid='acctok', auth={'accessor_token': 'LEAK-x1'}),
    entry(rid='urinl', request={'request_uri': '/v1/auth/oidc/oidc/callback\n?code=LEAK-x2&state=LEAK-x3'},
          response={'redirect': 'https://idp.example.com/cb?code=LEAK-x4&token=LEAK-x5'}),
    entry(rid='nonobj', request={'headers': 'X-Vault-Token: LEAK-x6'},
          response={'headers': ['LEAK-x7'], 'wrap_info': 'LEAK-x8', 'secret': ['LEAK-x9']}),
    entry(rid='leaseobj', response={'secret': {'lease_id': {'raw': 'LEAK-x10'}}}),
    '<110>1 2025-06-04T20:30:00Z vault-0 vault - - [meta@1234 x-vault-mfa="LEAK-x11"] ' + entry(rid='sdmfa'),
    'garbage before json X-Vault-MFA: LEAK-x12 ' + entry(rid='junkhdr'),
    entry(rid='eyi', error='bad jwt eyJhbGciOiJIUzI1NiJ9.eyIxIjoiTEVBSy14MTMifQ.c2ln'),
]

# #82 review 1: URLs, JSON escapes, odd token shapes, un-HMAC'd error and
# warnings, duplicate keys, and kept envelope fields of the wrong type.
def escaped(text, plain, esc):
    assert plain in text, plain
    return text.replace(plain, esc)


HOSTILE += [
    entry(rid='frag', response={'redirect': 'https://app.example.com/callback#access_token=LEAK-z1&id_token=LEAK-z2'}),
    entry(rid='fragq', response={'redirect': 'https://app.example.com/cb#access_token=LEAK-z3?x=1'}),
    entry(rid='userinfo', request={'request_uri': 'https://user:LEAK-z5@vault.internal/v1/secret/data/app'},
          response={'redirect': 'https://admin:LEAK-z4@idp.example.com/login'}),
    entry(rid='relfrag', request={'request_uri': '/v1/auth/oidc/callback#code=LEAK-z6'}),
    # JSON escapes: the secret is only visible after decoding
    escaped(entry(rid='esc1', request={'path': 'auth/token/lookup/hvs.LEAKz7escapedtoken'}), 'hvs.LEAK', '\\u0068vs.LEAK'),
    escaped(entry(rid='esc2', request={'headers': {'user-agent': ['x eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJMRUFLIn0.LEAKz8sig']}}),
            'eyJhbGci', '\\u0065yJhbGci'),
    escaped(entry(rid='esc3', auth={'display_name': '-----BEGIN RSA PRIVATE KEY-----\nLEAK-z9\n-----END RSA PRIVATE KEY-----'}),
            '-----BEGIN', '\\u002d----BEGIN'),
    entry(rid='esc4', error='Authorization: Bearer\tLEAKz10tabbearer', response={'warnings': ['Basic\nLEAKz11nl']}),
    # adjacent legacy tokens, Bearer values with ':' / '%', lowercase PEM, in kept strings
    entry(rid='adj', request={'path': 'secret/data/s.LEAKone1234567890123456 s.LEAKtwo1234567890123456'},
          auth={'display_name': 'r.LEAKthr1234567890123456,r.LEAKfou1234567890123456'}),
    entry(rid='bearer', request={'headers': {'user-agent': ['Authorization: Bearer pk:LEAK-z12 Bearer abcdef12%2FLEAK-z13']}}),
    entry(rid='pemlow', auth={'display_name': '-----begin rsa private key-----\nLEAK-z14\n-----end rsa private key-----'}),
    # un-HMAC'd error / warnings with DSN passwords and URL query secrets
    entry(rid='dsn', error='failed to connect to postgres://admin:LEAK-z15@db.internal:5432/prod'),
    entry(rid='urlerr', error='Get "https://idp.example.com/token?client_secret=LEAK-z16&code=LEAK-z17": 401',
          response={'warnings': ['retry with password=LEAK-z18', 'see https://x.example.com/?token=LEAK-z19']}),
    # duplicate keys: the earlier, shadowed value must not survive in raw_data
    '{"time":"2025-06-04T20:40:00Z","type":"response","auth":{"client_token":"LEAK-z20","client_token":"' + H + '"},'
    '"request":{"id":"dup1","operation":"read","path":"secret/data/app"}}',
    '{"time":"2025-06-04T20:40:00Z","type":"response","request":{"id":"dup2","operation":"update","path":"secret/data/app",'
    '"data":{"password":"LEAK-z21"},"data":{}}}',
    '{"extra":"LEAK-z22","extra":"","time":"2025-06-04T20:40:00Z","type":"response",'
    '"request":{"id":"dup3","operation":"read","path":"secret/data/app"}}',
    # mfa_requirement is not a kept field; kept fields with the wrong type or shape
    entry(rid='mfa', auth={'mfa_requirement': {'mfa_request_id': 'LEAK-z23', 'mfa_constraints': {}}}),
    entry(rid='shape', time={'t': 'LEAK-z24'}, forwarded_from={'f': 'LEAK-z25'},
          auth={'display_name': {'x': 'LEAK-z26'}, 'policies': ['default', {'x': 'LEAK-z27'}],
                'policy_results': {'allowed': True, 'extra': 'LEAK-z28'}, 'token_ttl': 'LEAK-z29',
                'metadata': {'role': 'ci', 'n': {'deep': 'LEAK-z30'}}},
          request={'namespace': {'id': 'root', 'secret': 'LEAK-z31'},
                   'headers': {'user-agent': 'LEAK-z32', 'x-request-id': ['ok', {'a': 'LEAK-z33'}]}},
          response={'wrap_info': {'creation_path': {'p': 'LEAK-z34'}, 'format': ['LEAK-z35']},
                    'warnings': [{'w': 'LEAK-z36'}]}),
]

# Lines that are not a complete Vault audit entry: their text must not be kept.
UNPARSABLE = [
    'vault: login failed for "alice": password=LEAK-y1 api_key=LEAK-y2 Authorization: Token LEAK-y3',
    '<110>1 2025-06-04T20:30:00Z vault-0 vault - - [meta@1234 msg="ctx":] password=LEAK-y4',
    entry(rid='trunc5', request={'data': {'k': 'v'}}, extra={'user-agent': 'LEAK-y5', 'blob': 'x' * 40})[:-20],
    'Digest authorization: Digest username="eve", realm="v", response="LEAK-y6"',
]

# Valid JSON the parser does not recognize: Base Event, nothing spilled.
FALLBACK = [
    json.dumps({'time': '2025-06-04T20:40:00Z', 'type': 'audit_custom', 'api_key': 'LEAK-n1', 'db_pass': 'LEAK-n2',
                'secret_payload': 'LEAK-n3', 'conn': 'LEAK-n4'}),
    json.dumps({'time': '2025-06-04T20:40:00Z', 'type': 'response', 'extra_secret': 'LEAK-n5', 'api_key': 'LEAK-n6',
                'response': {'data': {'k': 'LEAK-n7'}}}),
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
# Samples that carry clear credentials (or a syslog header with structured
# data) and are therefore rewritten; every other sample must come through
# with zero redaction.
SCRUBBED_SAMPLES = re.compile(r'^(?:vault_lograw_.*|vault_syslog_.*|vault_response_kv_update_error_all_fields|junk)$')
MARKER = '<unparsable Vault audit record withheld>'
CLEAN_SAMPLES = []


def events():
    doc = yaml.safe_load(PARSER.read_text())
    lines = []
    for sample in sorted((PARSER.parent / 'samples').glob('*.json')):
        text = sample.read_text().strip()
        try:
            obj = json.loads(text, strict=False)
        except json.JSONDecodeError:
            obj = None
        line = obj if isinstance(obj, dict) and set(obj) == {'message'} else {'message': text}
        if not SCRUBBED_SAMPLES.match(sample.stem):
            CLEAN_SAMPLES.append(line['message'])
        lines.append(line)
    for sample in doc.get('samples', []):
        lines.append({'message': sample['raw']})
        if 'FAKE' not in sample['raw'] and source_json(sample['raw']) is not None:
            CLEAN_SAMPLES.append(sample['raw'])
    lines += [{'message': raw} for raw in HOSTILE]
    lines += [{'message': raw} for raw in UNPARSABLE]
    lines += [{'message': raw} for raw in CLEAN]
    lines += [{'message': raw} for raw in FALLBACK]
    lines.append({'message': residual_probe()})
    return doc['parser_vrl'] + '\n.__coverage_source = __source_kv\n', lines


def residual_probe():
    """The shared field_coverage_check residual probe object on a clean entry."""
    obj = json.loads((PARSER.parent / 'samples/vault_response_userpass_login_success.json').read_text())
    obj['ResidualProbe'] = {'UnknownLeaf': 'nan2421-unknown-5d38', 'Scalars': ['nan2421-a', 987654321, False], 'Objects': [{'Field': 'nan2421-b', 'apiToken': 'nan2421-secret'}, {'name': 'Authorization', 'value': 'nan2421-secret'}], 'Password': 'nan2421-secret', 'Deep': {'clientSecret': 'nan2421-secret'}}
    obj['Dotted.Probe'] = 'nan2421-dotted'
    obj['Dotted'] = {'Probe': 'nan2421-nested'}
    obj['UnknownZero'] = 0
    obj['UnknownFalse'] = False
    obj['CollisionProbe'] = 'nan2421-first'
    obj['collision_probe'] = 'nan2421-second'
    return json.dumps(obj)


def redaction_diff(src, orig, path=''):
    """Differences between the captured source and the input other than redaction."""
    if src == '<redacted>':
        return []  # a whole value replaced (wrong type, or a wiped string)
    if isinstance(orig, dict):
        if not isinstance(src, dict) or set(src) != set(orig):
            return [f'{path}: keys {sorted(src) if isinstance(src, dict) else src!r} != {sorted(orig)}']
        return [d for k in orig for d in redaction_diff(src[k], orig[k], f'{path}.{k}' if path else k)]
    if isinstance(orig, list):
        if not isinstance(src, list) or len(src) != len(orig):
            return [f'{path}: list changed']
        return [d for i, (a, b) in enumerate(zip(src, orig)) for d in redaction_diff(a, b, f'{path}[{i}]')]
    if src == orig and type(src) is type(orig):
        return []
    if isinstance(orig, str) and isinstance(src, str) and '<redacted>' in src:
        return []
    return [f'{path}: {orig!r} became {src!r}']


def kept_json(raw_data):
    """The JSON object raw_data carries after its (sanitized) syslog header."""
    raw_data = raw_data or ''
    for start in [i for i, c in enumerate(raw_data) if c == '{']:
        try:
            obj = json.loads(raw_data[start:], strict=False)
        except json.JSONDecodeError:
            continue
        return obj if isinstance(obj, dict) else None
    return None


def source_json(message):
    """The input entry as JSON, syslog header removed; None when it is not JSON.

    Mirrors the parser: a line that starts with a brace is the entry itself;
    otherwise the entry starts at the first brace that opens a Vault key."""
    text = message.strip()
    if text.startswith('{'):
        start = 0
    else:
        match = VAULT_JSON.search(message)
        if not match:
            return None
        text, start = message[match.start():].strip(), 0
    try:
        obj = json.loads(text[start:], strict=False)
    except json.JSONDecodeError:
        return None
    return obj if isinstance(obj, dict) else None


def main():
    program, inputs = events()
    global FIXED_WORDS
    # Words every fallback event carries whatever the input (class names, the
    # marker, product names); anything else from the input must not appear.
    FIXED_WORDS = {'Base', 'Event', 'Uncategorized', 'Other', 'Informational', 'Unknown', 'Unrecognized', 'Vault',
                   'audit', 'record', 'unparsable', 'withheld', 'input', 'error', 'HashiCorp', 'SHA-256', '1.9.0',
                   'version', 'product', 'name', 'vendor_name', 'raw_data', 'message', 'unmapped', 'time', 'type'}
    with tempfile.TemporaryDirectory(prefix='vault-redaction-') as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / 'p.vrl').write_text(program)
        (tmp / 'in.json').write_text(''.join(json.dumps(i) + '\n' for i in inputs))
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp / 'p.vrl'), '--input', str(tmp / 'in.json'),
                              '--print-object'], capture_output=True, text=True, timeout=180)
    assert run.returncode == 0, run.stderr
    outputs = [line for line in run.stdout.splitlines() if line.startswith('{')]
    assert len(outputs) == len(inputs), f'{len(outputs)} events for {len(inputs)} inputs'
    config = yaml.safe_load((PARSER.parent / 'field-coverage.yaml').read_text())
    rules, candidates = config.get('transforms', []), config['consumed_candidates']
    failures = []
    checked = 0
    for raw, out in zip(inputs, outputs):
        event = json.loads(out, strict=False)
        source = event.pop('__coverage_source')
        original = source_json(raw['message'])
        if event.get('class_uid') == 0:
            if source != {}:
                failures.append(f'{raw["message"][:80]}...: fallback still captures a source to spill')
            if event.get('unmapped') != {'parse_fallback': 'unparsable input'}:
                failures.append(f'{raw["message"][:80]}...: fallback unmapped is {event.get("unmapped")!r}')
            body = raw['message'].encode()
            if (event.get('raw_data') != MARKER or event.get('raw_data_size') != len(body)
                    or (event.get('raw_data_hash') or {}).get('value') != hashlib.sha256(body).hexdigest()):
                failures.append(f'{raw["message"][:80]}...: fallback raw_data is not the marker + size + sha256')
            words = lambda text: set(re.findall(r'[A-Za-z0-9_.@/-]{4,}', text))
            kept = (words(raw['message']) & words(out)) - FIXED_WORDS
            if kept:
                failures.append(f'{raw["message"][:80]}...: unparsable text kept: {sorted(kept)[:8]}')
        elif original is None:
            failures.append(f'{raw["message"][:80]}...: mapped, but the input is not JSON')
        else:
            failures += [f'{raw["message"][:60]}...: {d}' for d in redaction_diff(source, original)]
            body = raw['message'].encode()
            if (event.get('raw_data_size') != len(body)
                    or (event.get('raw_data_hash') or {}).get('value') != hashlib.sha256(body).hexdigest()):
                failures.append(f'{raw["message"][:60]}...: raw_data_size / raw_data_hash do not identify the original')
            if kept_json(event.get('raw_data')) != source:
                failures.append(f'{raw["message"][:60]}...: raw_data is not the re-encoded redacted record')
            try:
                fcc.check(source, event, raw['message'], rules, [], candidates)
                checked += 1
            except AssertionError as error:
                failures.append(f'{raw["message"][:60]}...: no-loss check: {error}')
        leaks = TOKEN.findall(out) + JWT.findall(out) + [p for p in PLAINTEXT if p in out]
        leaks += re.findall(r'LEAK[A-Za-z0-9-]*', out) + re.findall(r'TEVBSy[A-Za-z0-9+/=]*', out)
        leaks += re.findall(r'nan2421-[a-z0-9-]+', out)
        if leaks:
            failures.append(f'{raw["message"][:80]}...: leaked {sorted(set(leaks))}')
        if '"raw_data"' not in out:
            failures.append(f'{raw["message"][:80]}...: raw_data missing')
        for path in (('session', 'uid'), ('actor', 'session', 'uid'),
                     ('session', 'credential_uid'), ('actor', 'session', 'credential_uid')):
            node = event
            for part in path:
                node = node.get(part) if isinstance(node, dict) else None
            if node is not None and not HMAC.match(str(node)):
                failures.append(f'{raw["message"][:80]}...: {".".join(path)} is {node!r}, not an HMAC accessor')
        if raw['message'] in CLEAN_SAMPLES and (source != original or kept_json(event.get('raw_data')) != original):
            failures.append(f'{raw["message"][:80]}...: clean sample was redacted or rewritten')
        if raw['message'] in CLEAN:
            if kept_json(event.get('raw_data')) != original:
                failures.append(f'{raw["message"][:80]}...: clean entry was rewritten')
            if (event.get('resources') or [{}])[0].get('uid') != 'secret/data/s.payments-prod-us-east-1':
                failures.append(f'{raw["message"][:80]}...: clean path corrupted')
        elif raw['message'] in HOSTILE and event.get('class_uid') == 0 and source_json(raw['message']) is not None:
            failures.append(f'{raw["message"][:80]}...: parseable hostile entry fell back to Base Event')
    # The source fixtures really do carry the secrets, so a pass is meaningful.
    corpus = ''.join(i['message'] for i in inputs)
    assert TOKEN.search(corpus) and JWT.search(corpus) and all(p in corpus for p in PLAINTEXT[:2])
    assert corpus.count('LEAK') >= 100, corpus.count('LEAK')
    assert checked >= 30, f'only {checked} mapped entries reached the strict source check'
    assert len(CLEAN_SAMPLES) >= 12, f'only {len(CLEAN_SAMPLES)} clean samples checked for zero redaction'
    if failures:
        print('\n'.join(failures))
        sys.exit(1)
    print(f'OK: {len(inputs)} Vault events, no token, JWT or plaintext secret in any output; '
          f'{checked} mapped entries pass the strict redaction-only source check')


if __name__ == '__main__':
    main()
