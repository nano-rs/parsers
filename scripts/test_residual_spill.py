#!/usr/bin/env python3
"""Regression checks for the generated mapping declarations (__decl).

A source key or target holding an unmatched bracket must not unbalance the
raw ()[]{} counts that nano's deploy validator takes over the whole VRL, and
the runtime lookup must match whole keys only and consume a key only when its
value is at one of its own targets.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from residual_spill import decl_literal, generated

BRACKETS = '()[]{}'


class DeclTests(unittest.TestCase):
    def test_raw_bracket_counts_stay_balanced(self):
        # One unmatched bracket per manifest: a set holding all six would balance by accident.
        for char in BRACKETS:
            for mappings in ({'x' + char + 'y': ['t']}, {'k': ['t' + char + 'u']}):
                source = generated({'mappings': mappings})
                for opening, closing in ('()', '[]', '{}'):
                    self.assertEqual(source.count(opening), source.count(closing), (char, mappings))

    def test_lookup_whole_keys_under_vector(self):
        keys = ['x' + char + 'y' for char in BRACKETS] + ['a.b c#d', 'plain', 'quo"te', 'back\\slash']
        mappings = {key: ['target'] for key in keys}
        near = ['x' + char for char in BRACKETS] + ['plainx', 'xplain', 'a.b c', 'plai']
        cases = [({key: 'v'}, {'target': 'v'}, {}) for key in keys]
        cases += [({key: 'v'}, {'target': 'v'}, {key_name(key): 'v'}) for key in near]
        cases += [({'plain': 'v'}, {'other': 'v'}, {'plain': 'v'})]
        program = '__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'mappings': mappings})
        with tempfile.TemporaryDirectory(prefix='decl-') as tmp:
            tmp = Path(tmp)
            (tmp/'p.vrl').write_text(program)
            (tmp/'in.json').write_text(''.join(json.dumps({'source': s, 'output': o}) + '\n' for s, o, _ in cases))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'in.json'), '--print-object'],
                                 text=True, capture_output=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        outputs = [json.loads(l) for l in run.stdout.splitlines() if l.startswith('{')]
        self.assertEqual(len(outputs), len(cases))
        for (source, _, expected), out in zip(cases, outputs):
            with self.subTest(source=source):
                self.assertEqual(out.get('unmapped', {}), expected)

    def test_decl_is_one_literal(self):
        self.assertTrue(decl_literal({'a': ['b']}).startswith('"\\n'))


def key_name(key):
    import field_coverage_check as fcc
    return '.'.join(fcc.snake(part) for part in key.split('.'))


if __name__ == '__main__':
    unittest.main()
