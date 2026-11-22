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
            ({'KnownList': ['one', 2]}, {'a': 'one', 'b': 2}, {}),
            ({'KnownList': ['one', 'unseen']}, {'a': 'one'}, {'known_list': ['one', 'unseen']}),
            ({'DéjàVu': 'unicode', 'HTTPStatus200': 'code'}, {}, {'déjà_vu': 'unicode', 'http_status_200': 'code'}),
            ({}, {'unmapped': {'empty': ''}}, {}),
            ({'Headers': [{'Name': 'Authorization', 'Value': 'private'}]}, {}, {'headers': '[{"Name":"Authorization","Value":"private"}]'}),
            ({'Details': {'Password': 'private'}}, {'unmapped': {'details_json': '{"Password":"private"}'}}, {'details.password': 'private'}),
            # Existing derived evidence under a credential-named key is kept too.
            ({'Other': 'x'}, {'unmapped': {'session_token': 'derived-value'}}, {'other': 'x', 'session_token': 'derived-value'}),
            # NAN-3604: dotted keys inside objects inside arrays keep their dots.
            ({'Records': [{'http://a.example/claims/upn': 'u@example.com', 'x.y': {'p.q~r': 1}}]}, {}, {'records': '[{"http://a.example/claims/upn":"u@example.com","x.y":{"p.q~r":1}}]'}),
        ]
        rules = [{'source': 'Name', 'kind': 'lowercase', 'reason': 'Test normalization must exist in emitted branch.'}]
        program = '__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'transforms': rules, 'consumed_candidates': ['Known', 'KnownList', 'Name']})
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
                    check(source, output, 'raw input', rules, candidates=['Known', 'KnownList', 'Name'])
                    if expected:
                        broken = copy.deepcopy(output)
                        del broken['unmapped'][next(iter(expected))]
                        with self.assertRaises(AssertionError):
                            check(source, broken, 'raw input', rules, candidates=['Known', 'KnownList', 'Name'])


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
        program = '__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'transforms': rules, 'consumed_candidates': []})
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
        base = {'source': 'S', 'reason': 'r'}
        for rule in ({'kind': 'scale', 'factor': 0}, {'kind': 'scale'}, {'kind': 'scale', 'factor': float('inf')},
                     {'kind': 'scale', 'factor': '2'}, {'kind': 'enum', 'values': {}}, {'kind': 'enum'},
                     {'kind': 'epoch_ms', 'format': ''}, {'kind': 'epoch_ms', 'format': 5}):
            with self.subTest(rule=rule), self.assertRaises(AssertionError):
                validate_config({'transforms': [{**base, **rule}]})
        validate_config({'transforms': [{**base, 'kind': 'scale', 'factor': 0.001}, {**base, 'kind': 'enum', 'values': {'a': 1}}, {**base, 'kind': 'epoch_ms'}]})

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


if __name__ == '__main__':
    unittest.main()
