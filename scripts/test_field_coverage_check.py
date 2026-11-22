#!/usr/bin/env python3
"""Focused regression checks for residual preservation and checker rejection."""
import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from field_coverage_check import check, normalized_source
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

    def test_parse_json_object(self):
        rules = [{'kind': 'unwrap_single', 'path': 'logEvents'},
                 {'kind': 'parse_json_object', 'paths': ['logEvents.message', 'message'], 'target': 'message_json'}]
        inner = {'level': 'ERROR', 'tags': ['a'], 'status': 0}
        env = {'logEvents': [{'message': json.dumps(inner)}]}
        self.assertEqual(normalized_source(env, rules)['message_json'], inner)
        flat = {'message': json.dumps(inner)}
        self.assertEqual(normalized_source(flat, rules)['message_json'], inner)
        text = {'message': 'START RequestId: x'}
        self.assertEqual(normalized_source(text, rules), text)
        listed = {'message': '[1, 2]'}
        self.assertEqual(normalized_source(listed, rules), listed)

    def test_unknown_kind_fails(self):
        with self.assertRaises(AssertionError):
            normalized_source({}, [{'kind': 'nope'}])


if __name__ == '__main__':
    unittest.main()
