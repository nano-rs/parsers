#!/usr/bin/env python3
"""Focused regression checks for residual preservation and checker rejection."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
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
            ({'List': [{'Name': 'thing', 'ApiToken': 'private'}]}, {}, {'list': '[{"ApiToken":"<redacted>","Name":"thing"}]'}),
            ({'Password': 'private', 'Nested': {'clientSecret': 'private'}}, {}, {'password': '<redacted>', 'nested.client_secret': '<redacted>'}),
            ({'Name': 'UPPER'}, {'user': {'name': 'upper'}}, {}),
            ({'Name': 'UPPER'}, {}, {'name': 'UPPER'}),
            ({'KnownList': ['one', 2]}, {'a': 'one', 'b': 2}, {}),
            ({'KnownList': ['one', 'unseen']}, {'a': 'one'}, {'known_list': ['one', 'unseen']}),
            ({'DéjàVu': 'unicode', 'HTTPStatus200': 'code'}, {}, {'déjà_vu': 'unicode', 'http_status_200': 'code'}),
            ({}, {'unmapped': {'empty': ''}}, {}),
            ({'Headers': [{'Name': 'Authorization', 'Value': 'private'}]}, {}, {'headers': '[{"Name":"Authorization","Value":"<redacted>"}]'}),
            ({'Details': {'Password': 'private'}}, {'unmapped': {'details_json': '{"Password":"private"}'}}, {'details.password': '<redacted>'}),
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

    def test_truncate_kind(self):
        # A bounded copy consumes its source only when it is the character
        # prefix in the named target and, for an over-bound value, the event
        # sets is_truncated and keeps the raw body as raw_data.
        raw = {'raw_data': 'raw input'}
        cases = [
            ({'Query': 'abcdefgh'}, {'query_info': {'query_string': 'abcde'}, 'metadata': {'is_truncated': True}, **raw}, {}),
            ({'Query': 'abcdefgh'}, {'query_info': {'query_string': 'abcde'}, **raw}, {'query': 'abcdefgh'}),
            ({'Query': 'abcdefgh'}, {'query_info': {'query_string': 'abcde'}, 'metadata': {'is_truncated': True}}, {'query': 'abcdefgh'}),
            ({'Query': 'abc'}, {'query_info': {'query_string': 'abc'}}, {}),
            ({'Query': 'h\u00e9llo w\u00f6rld'}, {'query_info': {'query_string': 'h\u00e9llo'}, 'metadata': {'is_truncated': True}, **raw}, {}),
            ({'Query': 'abcdefgh'}, {'query_info': {'query_string': 'abcdX'}, 'metadata': {'is_truncated': True}, **raw}, {'query': 'abcdefgh'}),
            ({'Audit': {'Sql': 'select 1'}}, {'query_info': {'query_string': 'selec'}, 'metadata': {'is_truncated': True}, **raw}, {}),
            ({'Audit': {'Sql': 'select 1'}}, {'query_info': {'query_string': 'selec'}, 'metadata': {'is_truncated': True}, 'raw_data': 'other'}, {'audit.sql': 'select 1'}),
        ]
        rules = [{'source': 'Query', 'kind': 'truncate', 'target': 'query_info.query_string', 'length': 5, 'reason': 'Bounded query text.'},
                 {'source': 'Audit.Sql', 'kind': 'truncate', 'target': 'query_info.query_string', 'length': 5, 'reason': 'Bounded nested SQL text.'}]
        with mock.patch.object(residual_spill, 'TRUNCATE_MIN_LENGTH', 1):
            program = '__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'transforms': rules, 'consumed_candidates': ['Query', 'Audit.Sql']})
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp/'p.vrl').write_text(program)
            (tmp/'events.json').write_text(''.join(json.dumps({'source': s, 'output': o})+'\n' for s,o,_ in cases))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'events.json')], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            outputs = [json.loads(l) for l in run.stdout.splitlines() if l.startswith('{')]
            self.assertEqual(len(outputs), len(cases), run.stdout + run.stderr)
            for (source, mapped, expected), output in zip(cases, outputs):
                with self.subTest(source=source, mapped=mapped):
                    self.assertEqual(output.get('unmapped', {}), expected)
                    check(source, output, 'raw input', rules, candidates=['Query', 'Audit.Sql'])
        # A nested JSON source field bounded at 8192 (a PostgreSQL jsonlog or
        # MySQL JSON audit statement) is consumed the same way, and only so.
        statement = 'SELECT é' + 'x' * 9000
        nested = [{'source': 'audit_record.sql', 'kind': 'truncate', 'target': 'query_info.query_string', 'length': 8192, 'reason': 'Bounded SQL text.'}]
        validate_config({'transforms': nested})
        source = {'audit_record': {'sql': statement, 'id': 1}}
        bounded = {'query_info': {'query_string': statement[:8192]}, 'metadata': {'is_truncated': True, 'uid': 1}, 'raw_data': 'raw input'}
        check(source, bounded, 'raw input', nested, candidates=['audit_record.id'])
        for broken in ({**bounded, 'raw_data': 'other'}, {**bounded, 'metadata': {'uid': 1}}, {**bounded, 'query_info': {'query_string': statement[:8191]}}):
            with self.assertRaises(AssertionError):
                check(source, broken, 'raw input', nested, candidates=['audit_record.id'])
        # Without a target a prefix may not ride on an unrelated mapped scalar.
        untargeted = [{'source': 'Query', 'kind': 'truncate', 'length': 1, 'reason': 'r'}]
        with self.assertRaises(AssertionError):
            check({'Query': '1' + 'x' * 50}, {'status_id': 1, 'metadata': {'is_truncated': True}, 'raw_data': 'raw input'}, 'raw input', untargeted)


class TargetEvidenceTests(unittest.TestCase):
    """A targeted rule is satisfied only by the mapped event (spill.vrl __mapped)."""

    def test_checker_ignores_unmapped_raw_data_and_raw_message(self):
        sql = 'select ' + 'x' * 400
        rule = [{'source': 'Sql', 'kind': 'truncate', 'target': 'unmapped.sql_short', 'length': 256, 'reason': 'r'}]
        output = {'metadata': {'is_truncated': True}, 'raw_data': 'raw input', 'unmapped': {'sql_short': sql[:256]}}
        with self.assertRaises(AssertionError):
            check({'Sql': sql}, output, 'raw input', rule)
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

    def truncate(self, **over):
        rule = {'source': 'Q', 'kind': 'truncate', 'target': 'query_info.query_string', 'length': 4096, 'reason': 'Bounded.'}
        rule.update(over)
        return {'transforms': [rule]}

    def test_valid(self):
        validate_config(self.truncate())
        validate_config({'source_normalize': [
            {'kind': 'unwrap_single', 'path': 'logEvents', 'reason': 'r'},
            {'kind': 'base64_json_merge', 'path': 'message.data', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': ['message'], 'target': 'message_json', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'message', 'match': '^type=', 'key_value_delimiter': '=', 'field_delimiter': ', ', 'reason': 'r'},
            {'kind': 'withhold', 'paths': ['message', 'a.b'], 'match': '^type=', 'reason': 'r'},
        ]})

    def test_truncate_guardrails(self):
        for bad in ({'length': 1}, {'length': 0}, {'length': 255}, {'length': 4096.0}, {'length': True}, {'target': ''}, {'target': None}, {'reason': ''}):
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                validate_config(self.truncate(**bad))
        rule = self.truncate()['transforms'][0]
        del rule['target']
        with self.assertRaises(AssertionError):
            validate_config({'transforms': [rule]})
        with self.assertRaises(AssertionError):
            generated({'transforms': [dict(rule, length=1, target='t')]})

    def test_step_guardrails(self):
        bad = [
            {'kind': 'unwrap_single', 'path': 'logEvents'},
            {'kind': 'unwrap_single', 'path': '', 'reason': 'r'},
            {'kind': 'nope', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': [], 'target': 't', 'reason': 'r'},
            {'kind': 'parse_json_object', 'paths': ['m'], 'target': 'a.b', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'a.b', 'match': '^', 'key_value_delimiter': '=', 'field_delimiter': ' ', 'reason': 'r'},
            {'kind': 'parse_kv_merge', 'path': 'message', 'key_value_delimiter': '=', 'field_delimiter': ' ', 'reason': 'r'},
            {'kind': 'unwrap_single', 'path': 'x', 'reason': 'r', 'extra': 1},
            {'kind': 'withhold', 'paths': ['message'], 'reason': 'r'},
            {'kind': 'withhold', 'paths': ['a..b'], 'match': '.', 'reason': 'r'},
            {'kind': 'withhold', 'paths': ['m'], 'match': '(', 'reason': 'r'},
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
        with self.assertRaises(AssertionError):
            validate_config(self.truncate(target='unmapped.sql_short'))

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
    """field-coverage.yaml `source_normalize`: the declared envelope steps, nothing more."""

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
        inner = {'level': 'ERROR', 'tags': ['a'], 'status': 0}
        env = {'logEvents': [{'message': json.dumps(inner)}]}
        self.assertEqual(normalized_source(env, rules)['message_json'], inner)
        flat = {'message': json.dumps(inner), 'logGroup': 'g'}
        # Moved, not copied: the unredacted JSON text leaves the source.
        self.assertEqual(normalized_source(flat, rules), {'message_json': inner, 'logGroup': 'g'})
        self.assertEqual(normalized_source(env, rules), {'logEvents': {}, 'message_json': inner})
        text = {'message': 'START RequestId: x'}
        self.assertEqual(normalized_source(text, rules), text)
        listed = {'message': '[1, 2]'}
        self.assertEqual(normalized_source(listed, rules), listed)

    def test_parse_json_object_never_overwrites_target(self):
        rules = [{'kind': 'parse_json_object', 'paths': ['message'], 'target': 'message_json'}]
        original = {'message': '{"a": 1}', 'message_json': 'PRE_EXISTING_VALUE'}
        self.assertEqual(normalized_source(original, rules), original)

    def test_parse_kv_merge(self):
        original = {'@timestamp': 't', 'message': 'type="LOGIN", username="a"'}
        self.assertEqual(normalized_source(original, [KV], fake_kv), {'@timestamp': 't', 'type': 'LOGIN', 'username': 'a'})
        # A dropped pair, a dropped outer key, or an unremoved envelope key all differ.
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

    def test_withhold(self):
        import hashlib
        step = {'kind': 'withhold', 'paths': ['logEvents.message', 'message'], 'match': '^type='}
        text = 'type="LOGIN_ERROR", client_secret="s3cr3t" \u00e9'
        out = normalized_source({'message': text, 'level': 'WARN'}, [step])
        self.assertEqual(out, {'level': 'WARN', 'message': {'withheld': True, 'bytes': len(text.encode()), 'sha256': hashlib.sha256(text.encode()).hexdigest()}})
        self.assertNotIn('s3cr3t', json.dumps(out))
        # The first existing path decides; no match keeps the value.
        nested = {'logEvents': {'message': 'plain'}, 'message': 'type=X'}
        self.assertEqual(normalized_source(nested, [step]), nested)
        self.assertEqual(normalized_source({'other': 1}, [step]), {'other': 1})
        # A non-string value is matched and digested as VRL encode_json text.
        batch = {'logEvents': [{'id': '2', 'message': 'b'}, {'id': '1', 'message': 'a'}]}
        out = normalized_source(batch, [{'kind': 'withhold', 'paths': ['logEvents'], 'match': r'^\[[^\]]'}])
        encoded = '[{"id":"2","message":"b"},{"id":"1","message":"a"}]'
        self.assertEqual(out['logEvents']['sha256'], hashlib.sha256(encoded.encode()).hexdigest())
        empty = {'logEvents': []}
        self.assertEqual(normalized_source(empty, [{'kind': 'withhold', 'paths': ['logEvents'], 'match': r'^\[[^\]]'}]), empty)

    def test_withhold_after_failed_unpack(self):
        # A KV line that cannot be unpacked is withheld instead of kept as text.
        steps = [KV, {'kind': 'withhold', 'paths': ['message'], 'match': '^(type|operationType)='}]
        ok = {'@timestamp': 't', 'message': 'type="LOGIN", username="a"'}
        self.assertEqual(normalized_source(ok, steps, fake_kv), {'@timestamp': 't', 'type': 'LOGIN', 'username': 'a'})
        collide = {'type': 'forwarder', 'message': 'type="LOGIN", password="s3cr3t"'}
        out = normalized_source(collide, steps, fake_kv)
        self.assertEqual(out['type'], 'forwarder')
        self.assertTrue(out['message']['withheld'])
        self.assertNotIn('s3cr3t', json.dumps(out))

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
            leaves = [v for _, v in fcc.flatten(normalized)]
            self.assertIn(fcc.NORMALIZE_UNKNOWN, leaves)
            self.assertIn('nan2421-secret', leaves)
        return probes

    def test_each_kind(self):
        self.assert_probe({'@timestamp': 't', 'message': 'type="LOGIN"'}, [KV])
        entry = base64.b64encode(json.dumps({'insertId': 'x'}).encode()).decode()
        self.assert_probe({'message': {'data': entry}}, [{'kind': 'base64_json_merge', 'path': 'message.data'}])
        self.assert_probe({'logEvents': [{'message': '{"a": 1}'}]},
                          [{'kind': 'unwrap_single', 'path': 'logEvents'},
                           {'kind': 'parse_json_object', 'paths': ['logEvents.message', 'message'], 'target': 'message_json'}])

    def test_withhold_probe(self):
        steps = [KV, {'kind': 'withhold', 'paths': ['message'], 'match': '^(type|operationType)='}]
        samples = [('ok', {'message': json.dumps({'message': 'type="LOGIN"'})}),
                   ('collide', {'message': json.dumps({'type': 'f', 'message': 'type="LOGIN"'})})]
        probes = normalize_probes(samples, steps, fake_kv)
        self.assertEqual([n for n, _ in probes], ['normalize_probe_0', 'withhold_probe_1'])
        withheld = normalized_source(json.loads(probes[1][1]['message']), steps, fake_kv)
        self.assertTrue(withheld['message']['withheld'])
        with self.assertRaises(AssertionError):
            normalize_probes(samples[:1], steps, fake_kv)

    def test_unexercised_step_fails(self):
        with self.assertRaises(AssertionError):
            normalize_probes([('s', {'message': json.dumps({'message': 'plain text'})})], [KV], fake_kv)
        self.assertIsNone(inject_probe({'message': 'plain'}, KV))

    def test_probe_catches_a_lossy_parser(self):
        # A parser that drops the injected pair (or leaks the secret) fails.
        [(_, event)] = self.assert_probe({'@timestamp': 't', 'message': 'type="LOGIN"'}, [KV])
        probe = json.loads(event['message'])
        expected = normalized_source(probe, [KV], fake_kv)
        lossy = {k: v for k, v in expected.items() if k != 'NormalizeProbe'}
        self.assertNotEqual(lossy, expected)
        output = {'activity_name': 'Logon', 'time': 1, 'unmapped': {'@timestamp': 't', 'type': 'LOGIN', 'client_secret': '<redacted>'}}
        with self.assertRaises(AssertionError):
            check(expected, output, event['message'], [])
        output['unmapped']['normalize_probe'] = fcc.NORMALIZE_UNKNOWN
        check(expected, output, event['message'], [])


if __name__ == '__main__':
    unittest.main()
