#!/usr/bin/env python3
"""Focused regression checks for residual preservation and checker rejection."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from field_coverage_check import check
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


if __name__ == '__main__':
    unittest.main()
