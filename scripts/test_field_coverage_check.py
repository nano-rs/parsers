#!/usr/bin/env python3
"""Focused regression checks for residual preservation and checker rejection."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import field_coverage_check as fcc
from field_coverage_check import check, inject_probe, normalize_probes, normalized_source, validate_config
import residual_spill
from residual_spill import generated


class ResidualTests(unittest.TestCase):
    def test_spill_and_checker(self):
        cases = [
            ({'UnknownZero': 0, 'UnknownFalse': False}, {'time': 0, 'is_remote': False}, {'unknown_zero': 0, 'unknown_false': False}),
            ({'Unknown': 'unique-unknown'}, {}, {'unknown': 'unique-unknown'}),
            ({'Known': 'mapped'}, {'message': 'mapped'}, {}),
            ({'FooBar': 'first', 'foo_bar': 'second'}, {}, {'foo_bar': 'first', 'foo_bar_2': 'second'}),
            ({'x.y': 'literal', 'x': {'y': 'nested'}}, {}, {'x.y': 'nested', 'x.y_2': 'literal'}),
            ({'List': [1, 'two', False]}, {}, {'list': [1, 'two', False]}),
            ({'List': [{'Name': 'thing', 'ApiToken': 'private'}]}, {}, {'list': '[{"ApiToken":"private","Name":"thing"}]'}),
            # A parser never masks: credential-named keys spill as-is.
            ({'Password': 'private', 'Nested': {'clientSecret': 'private'}}, {}, {'password': 'private', 'nested.client_secret': 'private'}),
            ({'Name': 'UPPER'}, {'user': {'name': 'upper'}}, {}),
            ({'Name': 'UPPER'}, {}, {'name': 'UPPER'}),
            # No coincidental consumption: a value equal to an attribute that is
            # not the key's declared target (or the rule's target) still spills.
            ({'Known': 'mapped'}, {'other': 'mapped'}, {'known': 'mapped'}),
            ({'Known': 1}, {'activity_id': 1, 'message': 2}, {'known': 1}),
            ({'Name': 'UPPER'}, {'actor': {'user': {'name': 'upper'}}}, {'name': 'UPPER'}),
            ({'Known': '42'}, {'message': 42}, {}),
            ({'KnownList': ['one', 2]}, {'a': ['one', 2]}, {}),
            ({'KnownList': ['one', 2]}, {'a': 'one', 'b': 2}, {'known_list': ['one', 2]}),
            ({'KnownList': ['one', 'unseen']}, {'a': ['one']}, {'known_list': ['one', 'unseen']}),
            # A target inside an array of objects (indices dropped).
            ({'Res': 'r1'}, {'resources': [{'uid': 'x'}, {'uid': 'r1'}]}, {}),
            ({'Res': 'r1'}, {'resources': [{'name': 'r1'}]}, {'res': 'r1'}),
            ({'cs(Host)': 'h'}, {'http_request': {'url': {'hostname': 'h'}}}, {}),
            # A literal dotted key is not the nested path it spells: mapping the
            # nested x.y never consumes the literal "x.y" (and vice versa).
            ({'x.y': 'literal', 'x': {'y': 'nested'}}, {'nested_target': 'nested'}, {'x.y': 'literal'}),
            ({'x.y': 'literal', 'x': {'y': 'nested'}}, {'literal_target': 'literal'}, {'x.y': 'nested'}),
            ({'DéjàVu': 'unicode', 'HTTPStatus200': 'code'}, {}, {'déjà_vu': 'unicode', 'http_status_200': 'code'}),
            ({}, {'unmapped': {'empty': ''}}, {}),
            ({'Headers': [{'Name': 'Authorization', 'Value': 'private'}]}, {}, {'headers': '[{"Name":"Authorization","Value":"private"}]'}),
            ({'Details': {'Password': 'private'}}, {'unmapped': {'details_json': '{"Password":"private"}'}}, {'details.password': 'private'}),
            # Existing derived evidence under a credential-named key is kept too.
            ({'Other': 'x'}, {'unmapped': {'session_token': 'derived-value'}}, {'other': 'x', 'session_token': 'derived-value'}),
            # NAN-3604: dotted keys inside objects inside arrays keep their dots.
            ({'Records': [{'http://a.example/claims/upn': 'u@example.com', 'x.y': {'p.q~r': 1}}]}, {}, {'records': '[{"http://a.example/claims/upn":"u@example.com","x.y":{"p.q~r":1}}]'}),
        ]
        rules = [{'source': 'Name', 'kind': 'lowercase', 'target': 'user.name', 'reason': 'Test normalization must exist in emitted branch.'}]
        mappings = {'Known': ['message'], 'KnownList': ['a'], 'Res': ['resources.uid'], 'cs(Host)': ['http_request.url.hostname'],
                    'x.y': ['nested_target'], 'x~1y': ['literal_target']}
        program = residual_spill.prelude() + '\n__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'transforms': rules, 'mappings': mappings})
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp/'p.vrl').write_text(program)
            (tmp/'events.json').write_text(''.join(json.dumps({'source': s, 'output': o})+'\n' for s,o,_ in cases))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'events.json')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            outputs = [json.loads(l) for l in run.stdout.splitlines() if l.startswith('{')]
            self.assertEqual(len(outputs), len(cases), run.stdout + run.stderr)
            for (source, mapped, expected), output in zip(cases, outputs):
                with self.subTest(source=source):
                    self.assertEqual(output.get('unmapped', {}), expected)
                    check(source, output, 'raw input', rules, mappings=mappings)
                    if expected:
                        broken = copy.deepcopy(output)
                        del broken['unmapped'][next(iter(expected))]
                        with self.assertRaises(AssertionError):
                            check(source, broken, 'raw input', rules, mappings=mappings)


class TargetEvidenceTests(unittest.TestCase):
    """A targeted rule is satisfied only by the mapped event (spill.vrl __mapped)."""

    def test_checker_ignores_unmapped_raw_data_and_raw_message(self):
        for target, output in (('raw_data', {'raw_data': 'raw input'}), ('message', {'message': 'raw input', 'raw_data': 'raw input'})):
            lower = [{'source': 'Name', 'kind': 'lowercase', 'target': target, 'reason': 'r'}]
            with self.subTest(target=target), self.assertRaises(AssertionError):
                check({'Name': 'RAW INPUT'}, output, 'raw input', lower)
        # A message that is not the raw body is evidence.
        lower = [{'source': 'Name', 'kind': 'lowercase', 'target': 'message', 'reason': 'r'}]
        check({'Name': 'HELLO'}, {'message': 'hello', 'raw_data': 'raw input'}, 'raw input', lower)

    def test_vrl_matches_against_mapped(self):
        rules = [{'source': 'Name', 'kind': 'lowercase', 'target': 'message', 'reason': 'r'}]
        cases = [({'Name': 'RAW INPUT'}, {'message': 'raw input'}, {'name': 'RAW INPUT'}),
                 ({'Name': 'HELLO'}, {'message': 'hello'}, {})]
        program = residual_spill.prelude() + '\n__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'transforms': rules})
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp/'p.vrl').write_text(program)
            (tmp/'events.json').write_text(''.join(json.dumps({'source': s, 'output': o})+'\n' for s, o, _ in cases))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'events.json')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            outputs = [json.loads(l) for l in run.stdout.splitlines() if l.startswith('{')]
        self.assertEqual([o.get('unmapped', {}) for o in outputs], [c[2] for c in cases])


class ConfigTests(unittest.TestCase):
    """validate_config: the two opt-in lists, each entry justified and well formed."""

    def test_valid(self):
        validate_config({'source_normalize': [
            {'kind': 'unwrap_single', 'path': 'logEvents', 'reason': 'r'},
            {'kind': 'base64_json_merge', 'path': 'message.data', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': ['message'], 'target': 'message_json', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'message', 'match': '^type=', 'key_value_delimiter': '=', 'field_delimiter': ', ', 'reason': 'r'},
        ]})

    def test_masking_kinds_rejected(self):
        # Parsers never mask: no step or rule may withhold, allowlist, keep a
        # subset, or truncate a value.
        for step in ({'kind': 'withhold', 'paths': ['message'], 'match': '.', 'reason': 'r'},
                     {'kind': 'allowlist', 'keep': ['a'], 'reason': 'r'},
                     {'kind': 'parse_json_object', 'paths': ['m'], 'target': 't', 'keep': ['id'], 'reason': 'r'}):
            with self.subTest(step=step), self.assertRaises(AssertionError):
                validate_config({'source_normalize': [step]})
        with self.assertRaises(AssertionError):
            validate_config({'transforms': [{'source': 'Q', 'kind': 'truncate', 'target': 'q', 'length': 4096, 'reason': 'r'}]})

    def test_step_guardrails(self):
        bad = [
            {'kind': 'unwrap_single', 'path': 'logEvents'},
            {'kind': 'unwrap_single', 'path': '', 'reason': 'r'},
            {'kind': 'nope', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': [], 'target': 't', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': ['m'], 'target': 'a.b', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': ['m'], 'target': 'm', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'a.b', 'match': '^', 'key_value_delimiter': '=', 'field_delimiter': ' ', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'message', 'key_value_delimiter': '=', 'field_delimiter': ' ', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'm', 'match': '(', 'key_value_delimiter': '=', 'field_delimiter': ' ', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'm', 'match': '^', 'key_value_delimiter': '=', 'field_delimiter': ' ', 'tail_keys': ['a b'], 'reason': 'r'},
            {'kind': 'unwrap_single', 'path': 'x', 'reason': 'r', 'extra': 1},
        ]
        for step in bad:
            with self.subTest(step=step), self.assertRaises(AssertionError):
                validate_config({'source_normalize': [step]})

    def test_target_guardrails(self):
        # A target is mapped-event evidence: never unmapped, raw_data or empty.
        for target in ('unmapped.sql_short', 'unmapped', 'raw_data', 'raw_data.x', '', 'a..b', 7):
            rule = {'source': 'Sql', 'kind': 'lowercase', 'target': target, 'reason': 'r'}
            with self.subTest(target=target):
                with self.assertRaises(AssertionError):
                    validate_config({'transforms': [rule]})
                with self.assertRaises(AssertionError):
                    generated({'transforms': [rule]})

    def test_transform_parameters(self):
        base = {'source': 'S', 'target': 't', 'reason': 'r'}
        for rule in ({'kind': 'scale', 'factor': 0}, {'kind': 'scale'}, {'kind': 'scale', 'factor': float('inf')},
                     {'kind': 'scale', 'factor': '2'}, {'kind': 'enum', 'values': {}}, {'kind': 'enum'},
                     {'kind': 'epoch_ms', 'format': ''}, {'kind': 'epoch_ms', 'format': 5}):
            with self.subTest(rule=rule), self.assertRaises(AssertionError):
                validate_config({'transforms': [{**base, **rule}]})
        validate_config({'transforms': [{**base, 'kind': 'scale', 'factor': 0.001}, {**base, 'kind': 'enum', 'values': {'a': 1}}, {**base, 'kind': 'epoch_ms'}]})

    def test_explicit_targets_required(self):
        # No coincidental consumption: a rule without a target, or the old
        # value-anywhere candidate list, is rejected.
        with self.assertRaises(AssertionError):
            validate_config({'transforms': [{'source': 'S', 'kind': 'lowercase', 'reason': 'r'}]})
        with self.assertRaises(AssertionError):
            generated({'consumed_candidates': ['a']})
        for bad in ({'a': []}, {'a': 'unmapped.a'}, {'a': ['raw_data']}, {'a': ''}, {'': 'x'}, ['a']):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                generated({'mappings': bad})
        self.assertIn('resources.uid', generated({'mappings': {'a': 'resources.0.uid'}}))

    def test_parse_timestamp_needs_timezone(self):
        # Without timezone: VRL reads an offset-less clock in the HOST timezone.
        naive = fcc.naive_timestamps
        self.assertEqual(len(naive('t, e = parse_timestamp(s, "%Y-%m-%d %H:%M:%S")')), 1)
        self.assertEqual(len(naive('t = parse_timestamp!(replace(s, r\' Z$\', ""), "%Y (x)")')), 1)
        self.assertEqual(naive('t, e = parse_timestamp(s, "%+", timezone: "UTC")'), [])
        self.assertEqual(naive('t = parse_timestamp!(replace(s, r\')\', ""), "%Y", timezone: "UTC")'), [])
        # Comments never count, either way; a timezone variable is fine; a
        # word "timezone" elsewhere in the call is not the argument.
        self.assertEqual(naive('# t = parse_timestamp(s, "%Y")\nx = 1'), [])
        self.assertEqual(naive('t = parse_timestamp(s, "%Y", timezone: tz) # local'), [])
        self.assertEqual(naive('t = parse_timestamp(p.timezone, "%+")'), [])
        self.assertEqual(naive('t = parse_timestamp(s, "%d/%b/%Y:%H:%M:%S %z")'), [])
        self.assertEqual(len(naive('t = parse_timestamp(timezone, fmt)')), 1)
        self.assertEqual(len(naive('t = parse_timestamp(s, "%Y") # timezone: "UTC"')), 1)

    def test_json_envelope_retired(self):
        with self.assertRaises(AssertionError):
            validate_config({'json_envelope': 'message'})


def fake_kv(text, step):
    """A stand-in for VRL parse_key_value on simple `k="v", k2="v2"` text."""
    pairs = {}
    for field in text.split(step['field_delimiter']):
        key, sep, value = field.partition(step['key_value_delimiter'])
        if not sep or not key:
            return None
        pairs[key] = value.strip('"')
    return pairs


KV = {'kind': 'parse_kv_merge', 'path': 'message', 'match': '^(type|operationType)=', 'key_value_delimiter': '=', 'field_delimiter': ', ', 'reason': 'r'}


class SourceNormalizeTests(unittest.TestCase):
    """field-coverage.yaml `source_normalize`: lossless envelope steps, nothing more."""

    def test_no_rules_is_identity(self):
        original = {'a': [1], 'b': {'c': 'd'}}
        self.assertEqual(normalized_source(original, None), original)

    def test_unwrap_single(self):
        rules = [{'kind': 'unwrap_single', 'path': 'logEvents'}]
        one = {'logGroup': 'g', 'logEvents': [{'id': '1', 'message': 'm'}]}
        self.assertEqual(normalized_source(one, rules), {'logGroup': 'g', 'logEvents': {'id': '1', 'message': 'm'}})
        many = {'logEvents': [{'id': '1'}, {'id': '2'}]}
        self.assertEqual(normalized_source(many, rules), many)
        scalar = {'logEvents': ['x']}
        self.assertEqual(normalized_source(scalar, rules), scalar)
        self.assertEqual(one['logEvents'], [{'id': '1', 'message': 'm'}], 'input must not be mutated')

    def test_base64_json_merge(self):
        rules = [{'kind': 'base64_json_merge', 'path': 'message.data'}]
        entry = {'insertId': 'x', 'textPayload': 't'}
        data = base64.b64encode(json.dumps(entry).encode()).decode()
        wrapper = {'message': {'data': data, 'messageId': '7'}, 'subscription': 's'}
        self.assertEqual(normalized_source(wrapper, rules), {'insertId': 'x', 'textPayload': 't', 'message': {'messageId': '7'}, 'subscription': 's'})
        for bad in ('!!!', base64.b64encode(b'[1]').decode(), ''):
            raw = {'message': {'data': bad}}
            self.assertEqual(normalized_source(raw, rules), raw)

    def test_base64_json_merge_collision_is_skipped(self):
        # A decoded key that already exists in the wrapper must not overwrite
        # (or be overwritten): the step is skipped and nothing is lost.
        rules = [{'kind': 'base64_json_merge', 'path': 'message.data'}]
        for entry in ({'insertId': 'x', 'subscription': 'INNER'}, {'insertId': 'x', 'message': 'INNER'}):
            data = base64.b64encode(json.dumps(entry).encode()).decode()
            wrapper = {'message': {'data': data}, 'subscription': 's'}
            with self.subTest(entry=entry):
                self.assertEqual(normalized_source(wrapper, rules), wrapper)

    def test_parse_json_object(self):
        rules = [{'kind': 'unwrap_single', 'path': 'logEvents'},
                 {'kind': 'parse_json_object', 'paths': ['logEvents.message', 'message'], 'target': 'message_json'}]
        inner = {'level': 'ERROR', 'tags': ['a'], 'status': 0, 'password': 'kept-as-is'}
        env = {'logEvents': [{'message': json.dumps(inner)}]}
        self.assertEqual(normalized_source(env, rules)['message_json'], inner)
        flat = {'message': json.dumps(inner), 'logGroup': 'g'}
        # Moved, not copied: the JSON text becomes its parsed fields, all of them.
        self.assertEqual(normalized_source(flat, rules), {'message_json': inner, 'logGroup': 'g'})
        self.assertEqual(normalized_source(env, rules), {'logEvents': {}, 'message_json': inner})
        text = {'message': 'START RequestId: x'}
        self.assertEqual(normalized_source(text, rules), text)
        listed = {'message': '[1, 2]'}
        self.assertEqual(normalized_source(listed, rules), listed)

    def test_parse_json_object_arrays(self):
        rules = [{'kind': 'parse_json_object', 'paths': ['representation'], 'target': 'representation_json', 'arrays': True}]
        listed = {'representation': '[{"name": "realm-admin"}]'}
        self.assertEqual(normalized_source(listed, rules), {'representation_json': [{'name': 'realm-admin'}]})
        self.assertEqual(normalized_source(listed, [dict(rules[0], arrays=False)]), listed)
        with self.assertRaises(AssertionError):
            validate_config({'source_normalize': [dict(rules[0], arrays='yes', reason='r')]})

    def test_parse_json_object_never_overwrites_target(self):
        rules = [{'kind': 'parse_json_object', 'paths': ['message'], 'target': 'message_json'}]
        original = {'message': '{"a": 1}', 'message_json': 'PRE_EXISTING_VALUE'}
        self.assertEqual(normalized_source(original, rules), original)

    def test_parse_kv_merge_tail_key(self):
        step = dict(KV, tail_keys=['representation'])
        line = 'operationType=CREATE, realmId=r1, representation={"attributes":{"dn":"cn=a, dc=corp"},"credentials":[{"value":"x"}]}'
        out = normalized_source({'message': line}, [step])
        self.assertEqual(out, {'operationType': 'CREATE', 'realmId': 'r1', 'representation': '{"attributes":{"dn":"cn=a, dc=corp"},"credentials":[{"value":"x"}]}'})
        quoted = 'operationType="CREATE", representation="{\\"a\\":\\"b, c\\"}"'
        self.assertEqual(normalized_source({'message': quoted}, [step])['representation'], '{"a":"b, c"}')
        self.assertEqual(normalized_source({'message': 'type=LOGIN, realmId=r1'}, [step]), {'type': 'LOGIN', 'realmId': 'r1'})

    def test_parse_kv_merge_tail_keys_keycloak_trace(self):
        # Keycloak TRACE lines end with representation, requestUri, cookies=[...],
        # stackTrace; each is cut off whole, never split on ", ".
        step = dict(KV, tail_keys=['representation', 'requestUri', 'cookies', 'stackTrace'])
        line = ('type=LOGIN, realmId=r1, requestUri=https://sso.example.com/auth?code=abc, '
                'cookies=[KEYCLOAK_IDENTITY=xyz, AUTH_SESSION_ID=x.node1], stackTrace=a, b')
        out = normalized_source({'message': line}, [step])
        self.assertEqual(out, {'type': 'LOGIN', 'realmId': 'r1', 'requestUri': 'https://sso.example.com/auth?code=abc',
                               'cookies': '[KEYCLOAK_IDENTITY=xyz, AUTH_SESSION_ID=x.node1]', 'stackTrace': 'a, b'})
        admin = 'operationType=CREATE, realmId=r1, representation={"username":"a, b"}, requestUri=https://h/x, cookies=[K=v]'
        out = normalized_source({'message': admin}, [step])
        self.assertEqual(out['representation'], '{"username":"a, b"}')
        self.assertEqual(out['cookies'], '[K=v]')

    def test_parse_kv_merge(self):
        original = {'@timestamp': 't', 'message': 'type="LOGIN", username="a"'}
        self.assertEqual(normalized_source(original, [KV], fake_kv), {'@timestamp': 't', 'type': 'LOGIN', 'username': 'a'})
        for wrong in ({'@timestamp': 't', 'type': 'LOGIN'}, {'@timestamp': 't'}, {},
                      {'type': 'LOGIN', 'username': 'a'},
                      {'@timestamp': 't', 'message': original['message'], 'type': 'LOGIN', 'username': 'a'}):
            with self.subTest(wrong=wrong):
                self.assertNotEqual(normalized_source(original, [KV], fake_kv), wrong)

    def test_parse_kv_merge_skips(self):
        cases = [
            {'message': 'not an event'},              # guard does not match
            {'message': 'type=", oops'},               # parse error
            {'message': 7},                            # not a string
            {'type': 'X', 'message': 'type="LOGIN"'},  # collides with an outer key
        ]
        for original in cases:
            with self.subTest(original=original):
                self.assertEqual(normalized_source(original, [KV], fake_kv), original)
        self.assertEqual(normalized_source({'message': 'type=A'}, [KV], lambda text, step: {}), {'message': 'type=A'})

    def test_parse_kv_merge_uses_vrl(self):
        # The default parser is VRL's own parse_key_value, quirks included.
        self.assertEqual(normalized_source({'message': 'type="A", x="has, comma"'}, [KV]), {'type': 'A', 'x': 'has, comma'})
        trailing = {'message': 'type="LOGIN_ERROR", realmId="r1", '}
        self.assertEqual(normalized_source(trailing, [KV]), trailing)

    def test_unknown_kind_fails(self):
        with self.assertRaises(AssertionError):
            normalized_source({}, [{'kind': 'nope'}])


class NormalizeProbeTests(unittest.TestCase):
    """Every declared step is probed inside the payload it unwraps."""

    def assert_probe(self, original, steps, parse_kv=fake_kv):
        probes = normalize_probes([('s', {'message': json.dumps(original)})], steps, parse_kv)
        self.assertEqual(len(probes), len(steps))
        for _name, event in probes:
            normalized = normalized_source(json.loads(event['message']), steps, parse_kv)
            self.assertIn(fcc.NORMALIZE_UNKNOWN, [v for _, v in fcc.flatten(normalized)])
        return probes

    def test_each_kind(self):
        self.assert_probe({'@timestamp': 't', 'message': 'type="LOGIN"'}, [KV])
        entry = base64.b64encode(json.dumps({'insertId': 'x'}).encode()).decode()
        self.assert_probe({'message': {'data': entry}}, [{'kind': 'base64_json_merge', 'path': 'message.data'}])
        self.assert_probe({'logEvents': [{'message': '{"a": 1}'}]},
                          [{'kind': 'unwrap_single', 'path': 'logEvents'},
                           {'kind': 'parse_json_object', 'paths': ['logEvents.message', 'message'], 'target': 'message_json'}])

    def test_probe_tail_key(self):
        step = dict(KV, tail_keys=['representation'])
        samples = [('tail', {'message': json.dumps({'message': 'operationType=CREATE, realmId=r1, representation={"id":"1"}'})})]
        [(_, event)] = normalize_probes(samples, [step], fake_kv)
        planted = json.loads(event['message'])['message']
        self.assertTrue(planted.endswith(', representation={"id":"1"}'), planted)

    def test_unexercised_step_fails(self):
        with self.assertRaises(AssertionError):
            normalize_probes([('s', {'message': json.dumps({'message': 'plain text'})})], [KV], fake_kv)
        self.assertIsNone(inject_probe({'message': 'plain'}, KV))

    def test_probe_catches_a_lossy_parser(self):
        [(_, event)] = self.assert_probe({'@timestamp': 't', 'message': 'type="LOGIN"'}, [KV])
        probe = json.loads(event['message'])
        expected = normalized_source(probe, [KV], fake_kv)
        lossy = {k: v for k, v in expected.items() if k != 'NormalizeProbe'}
        self.assertNotEqual(lossy, expected)
        output = {'activity_name': 'Logon', 'time': 1, 'unmapped': {'@timestamp': 't', 'type': 'LOGIN'}}
        with self.assertRaises(AssertionError):
            check(expected, output, event['message'], [])
        output['unmapped']['normalize_probe'] = fcc.NORMALIZE_UNKNOWN
        check(expected, output, event['message'], [])


TEXT_PARSER = r"""
raw_log = to_string(.message) ?? ""
__raw_body = raw_log
kv = parse_key_value(raw_log, key_value_delimiter: "=", field_delimiter: " ") ?? {}
MASK
__source_kv = kv
. = {"class_uid": 0, "raw_data": RAW, "message": to_string(kv.msg) ?? ""}
"""


class RunParserFidelityTests(unittest.TestCase):
    """End to end: raw_data is the original, and a probe password survives."""

    def run_parser(self, mask='', raw='raw_log', mappings=None, sample='msg=hello user=alice'):
        import residual_spill
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'probe'/'parser.yaml'
            path.parent.mkdir()
            (path.parent/'field-coverage.yaml').write_text(json.dumps({
                'source': 'text', 'mappings': mappings or {'msg': 'message'},
                'probe': {'mode': 'after', 'require': 'msg=', 'source': 'ResidualProbe',
                          'text': ' ResidualProbe=nan2421-text-unknown password=nan2421-secret'}}))
            program = TEXT_PARSER.replace('MASK', mask).replace('RAW', raw)
            body = ''.join('  ' + line + '\n' if line else '\n' for line in program.strip().splitlines())
            path.write_text('parser_vrl: |\n' + body + 'samples: ' + json.dumps([{'raw': sample}]) + '\n')
            residual_spill.update(path)
            fcc.run_parser(path)

    def test_faithful_passes(self):
        self.run_parser()

    def test_masked_probe_password_fails(self):
        for mask in ('if exists(kv.password) { kv.password = "<redacted>" }', '__d = del(kv.password)'):
            with self.subTest(mask=mask), self.assertRaisesRegex(AssertionError, 'credential value'):
                self.run_parser(mask=mask)

    def test_coincidental_mapping_fails_provenance(self):
        # user=alice is declared to map to message, but message carries msg:
        # a sample where both equal would consume user by coincidence. The
        # perturbation check finds no provenance and fails the parser.
        with self.assertRaisesRegex(AssertionError, 'without provenance'):
            self.run_parser(mappings={'msg': 'message', 'user': 'message'}, sample='msg=alice user=alice')

    def test_rewritten_raw_data_fails(self):
        for raw in ('"MASKED"', 'strip_whitespace(raw_log) + "!"'):
            with self.subTest(raw=raw), self.assertRaisesRegex(AssertionError, 'raw_data is not the original'):
                self.run_parser(raw=raw)


JSON_PARSER = r"""
raw = to_string(.message) ?? ""
__raw_body = raw
__source_kv = object(parse_json(raw) ?? {}) ?? {}
. = {"class_uid": 0, "raw_data": raw, "message": to_string(__source_kv.msg) ?? "", "tags": STATIC}
"""


class ProvenanceTests(unittest.TestCase):
    """A declaration needs real provenance: a static value never passes."""

    def run_json(self, mappings, samples, static='[0, 1]'):
        import residual_spill
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'probe'/'parser.yaml'
            path.parent.mkdir()
            (path.parent/'field-coverage.yaml').write_text(json.dumps({'source': 'json', 'mappings': mappings}))
            body = ''.join('  ' + line + '\n' for line in JSON_PARSER.replace('STATIC', static).strip().splitlines())
            path.write_text('parser_vrl: |\n' + body + 'samples: ' + json.dumps([{'raw': json.dumps(s)} for s in samples]) + '\n')
            residual_spill.update(path)
            fcc.run_parser(path)

    def test_static_list_never_proves_a_mapping(self):
        for static, flags in (('[0, 1]', [0, 1]), ('[true, false]', [True, False]), ('["a", "b"]', ['a']), ('["a", "b", "c"]', ['a', 'b'])):
            with self.subTest(static=static), self.assertRaisesRegex(AssertionError, 'without provenance'):
                self.run_json({'msg': 'message', 'flags': 'tags'}, [{'msg': 'hi', 'flags': flags}], static)

    def test_lookup_that_echoes_one_value_fails(self):
        # category = 3 only for id 3: a lookup, not a copy. One sentinel may
        # land on 3, but two distinct sentinels never both arrive.
        program = JSON_PARSER.replace('"tags": STATIC', '"tags": [], "category_uid": 0') + 'if __source_kv.code == 3 { .category_uid = 3 }\n'
        import residual_spill
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'probe'/'parser.yaml'
            path.parent.mkdir()
            (path.parent/'field-coverage.yaml').write_text(json.dumps({'source': 'json', 'mappings': {'msg': 'message', 'code': 'category_uid'}}))
            body = ''.join('  ' + line + '\n' for line in program.strip().splitlines())
            path.write_text('parser_vrl: |\n' + body + 'samples: ' + json.dumps([{'raw': json.dumps({'msg': 'hi', 'code': 0})}, {'raw': json.dumps({'msg': 'ho', 'code': 2})}]) + '\n')
            residual_spill.update(path)
            with self.assertRaisesRegex(AssertionError, 'without provenance'):
                fcc.run_parser(path)

    def test_small_identity_lookup_fails(self):
        # 0->0, 1->1, 2->2, else 99 is a lookup: draws come from outside the
        # values the field takes in the samples, so it never echoes them.
        program = JSON_PARSER.replace('"tags": STATIC', '"tags": [], "category_uid": 99') + 'if includes([0, 1, 2], __source_kv.code) { .category_uid = __source_kv.code }\n'
        import residual_spill
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'probe'/'parser.yaml'
            path.parent.mkdir()
            (path.parent/'field-coverage.yaml').write_text(json.dumps({'source': 'json', 'mappings': {'msg': 'message', 'code': 'category_uid'}}))
            body = ''.join('  ' + line + '\n' for line in program.strip().splitlines())
            path.write_text('parser_vrl: |\n' + body + 'samples: ' + json.dumps([{'raw': json.dumps({'msg': m, 'code': c})} for m, c in (('a', 0), ('b', 1), ('c', 2))]) + '\n')
            residual_spill.update(path)
            with self.assertRaisesRegex(AssertionError, 'without provenance.*PROVENANCE_SEED='):
                fcc.run_parser(path)

    def test_draws_are_deterministic(self):
        import provenance
        draws = []
        for _ in range(2):
            provenance.seed_draw('parser', 'sample', 'key', '', 0)
            draws.append((provenance.sentinels('10.4.5.6'), provenance.sentinels(4812), provenance.sentinels('vty0')))
        self.assertEqual(draws[0], draws[1])
        provenance.seed_draw('parser', 'sample', 'other', '', 0)
        self.assertNotEqual(provenance.sentinels('10.4.5.6'), draws[0][0])
        # A lone digit always changes.
        for draw in range(20):
            provenance.seed_draw('p', 's', 'by', '', draw)
            self.assertTrue(all(v != 'vty0' and v[:3] == 'vty' or not v.startswith('vty') for v in provenance.sentinels('vty0')))

    def test_real_mapping_passes(self):
        self.run_json({'msg': 'message'}, [{'msg': 'hello', 'flags': [0, 1]}])

    def test_sentinels_are_fresh_and_typed(self):
        import provenance
        for value in ('10.4.5.6', '2026-08-18T12:00:00.1234567Z', 'WKS-01.corp', 4812, 2.5, True, 'abc123'):
            got = provenance.sentinels(value)
            self.assertTrue(got, value)
            for new in got:
                self.assertIs(type(new), type(value))
                self.assertNotEqual(new, value)
        # A sub-millisecond clock moves by whole seconds; a us->ms scale moves the result.
        rule = {'kind': 'epoch_ms', 'format': '%+'}
        for new in provenance.rule_mutations(rule, '2026-08-18T12:00:00.1234567Z'):
            self.assertNotEqual(provenance.transform_want(rule, new), provenance.transform_want(rule, '2026-08-18T12:00:00.1234567Z'))
        scale = {'kind': 'scale', 'factor': 0.001}
        for value in (1787043600123456, '1787043600.451'):
            for new in provenance.rule_mutations(scale, value):
                self.assertNotEqual(provenance.transform_want(scale, new), provenance.transform_want(scale, value))


if __name__ == '__main__':
    unittest.main()
