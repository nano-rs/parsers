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
import residual_spill
from residual_spill import decl_literal, generated

BRACKETS = '()[]{}'


class DeclTests(unittest.TestCase):
    def test_raw_bracket_counts_stay_balanced(self):
        # One unmatched bracket per manifest: a set holding all six would balance by accident.
        for char in BRACKETS:
            with self.assertRaises(AssertionError):
                generated({'mappings': {'k': ['t' + char + 'u']}})  # no OCSF path holds a bracket
            for mappings in ({'x' + char + 'y': ['t']},):
                source = generated({'mappings': mappings})
                for opening, closing in ('()', '[]', '{}'):
                    self.assertEqual(source.count(opening), source.count(closing), (char, mappings))

    def test_lookup_whole_keys_under_vector(self):
        keys = ['x' + char + 'y' for char in BRACKETS] + ['a.b c#d', 'plain', 'quo"te', 'back\\slash']
        # A literal dot in a key is declared escaped (~1), as provenance names it.
        mappings = {key.replace('~', '~0').replace('.', '~1'): ['target'] for key in keys}
        near = ['x' + char for char in BRACKETS] + ['plainx', 'xplain', 'a.b c', 'plai']
        cases = [({key: 'v'}, {'target': 'v'}, {}) for key in keys]
        cases += [({key: 'v'}, {'target': 'v'}, {key_name(key): 'v'}) for key in near]
        cases += [({'plain': 'v'}, {'other': 'v'}, {'plain': 'v'})]
        program = residual_spill.prelude() + '\n__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'mappings': mappings})
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

    def test_path_clash_names_under_vector(self):
        # NAN-5894: a literal dotted key that clashes with a nested path keeps
        # its dots escaped (a~1b), the name nano's ingest step gives it when no
        # parser runs. Only a name still taken after that gets a _N suffix.
        cases = [
            ({'a.b': 1, 'a': {'b': 2}}, {'a.b': 2, 'a~1b': 1}),
            ({'a': {'b': 2}, 'a.b': 1, 'a.c': 3}, {'a.b': 2, 'a~1b': 1, 'a.c': 3}),
            ({'x': {'a.b': 1}, 'x.a': {'b': 2}}, {'x.a~1b': 1, 'x~1a.b': 2}),
            ({'A.b': 1, 'a': {'b': 2}}, {'a.b': 2, 'a~1b': 1}),
            ({'Foo.BarBaz': 1, 'foo': {'bar_baz': 2}}, {'foo.bar_baz': 2, 'foo~1bar_baz': 1}),
            ({'a.b': {'c.d': 1}, 'a': {'b': {'c': {'d': 2}}}}, {'a.b.c.d': 2, 'a~1b.c~1d': 1}),
            ({'a.b': 1, 'a': {'b': 2}, 'A': {'b': 3}}, {'a.b': 3, 'a.b_2': 2, 'a~1b': 1}),
            ({'a.b': 1, 'a': {'b': 2}, 'a.b_2': 9}, {'a.b': 2, 'a~1b': 1, 'a.b_2': 9}),
            ({'nano.x': 1, 'nano': {'x': 2}}, {'source_nano.x': 2, 'source_nano~1x': 1}),
            # No literal dot: only snake-casing clashes, so the suffix stays.
            ({'userName': 1, 'user_name': 2}, {'user_name': 1, 'user_name_2': 2}),
            # Two flat keys that escape alike: escaping cannot tell them apart.
            ({'userName.x': 1, 'user_name.x': 2}, {'user_name.x': 1, 'user_name.x_2': 2}),
            ({'A.b': 1, 'a.b': 2, 'a': {'b': 3}}, {'a.b': 1, 'a.b_2': 3, 'a.b_3': 2}),
            # No clash: dotted keys keep their plain names.
            ({'plain': 1, 'd.x': 2}, {'plain': 1, 'd.x': 2}),
        ]
        program = residual_spill.prelude() + '\n__source_kv = object!(.source)\n__raw_body = "raw input"\n. = .output\n' + generated({'mappings': {}})
        with tempfile.TemporaryDirectory(prefix='clash-') as tmp:
            tmp = Path(tmp)
            (tmp/'p.vrl').write_text(program)
            (tmp/'in.json').write_text(''.join(json.dumps({'source': s, 'output': {}}) + '\n' for s, _ in cases))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'in.json'), '--print-object'],
                                 text=True, capture_output=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        outputs = [json.loads(l) for l in run.stdout.splitlines() if l.startswith('{')]
        self.assertEqual(len(outputs), len(cases))
        for (source, expected), out in zip(cases, outputs):
            with self.subTest(source=source):
                self.assertEqual(out.get('unmapped', {}), expected)

    def test_decl_is_one_literal(self):
        self.assertTrue(decl_literal({'a': ['b']}).startswith('"\\n'))


def key_name(key):
    import field_coverage_check as fcc
    return '.'.join(fcc.snake(part) for part in key.split('.'))


if __name__ == '__main__':
    unittest.main()
