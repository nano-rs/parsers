#!/usr/bin/env python3
"""Regression checks for the generated consumed-candidate regex (NAN-5351).

A candidate holding an unmatched bracket must not unbalance the raw ()[]{}
counts that nano's deploy validator takes over the whole VRL, and the regex
must still compile under Vector and match whole keys only.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from residual_spill import candidate_regex

BRACKETS = '()[]{}'


class CandidateRegexTests(unittest.TestCase):
    def setUp(self):
        self.candidates = ['x' + char + 'y' for char in BRACKETS] + [char for char in BRACKETS] + ['a.b c#d', 'plain']
        self.source = '\n'.join(candidate_regex(self.candidates))

    def test_raw_bracket_counts_stay_balanced(self):
        # One unmatched bracket per manifest: a set holding all six would balance by accident.
        for char in BRACKETS:
            source = '\n'.join(candidate_regex(['x' + char + 'y', 'plain']))
            for opening, closing in ('()', '[]', '{}'):
                self.assertEqual(source.count(opening), source.count(closing), (char, source))

    def test_compiles_and_matches_whole_keys_under_vector(self):
        near_misses = ['x' + char for char in BRACKETS] + ['x' + char + 'yz' for char in BRACKETS] + [char * 2 for char in BRACKETS]
        keys = self.candidates + near_misses + ['xy', 'a.b c', 'a_b c#d', 'plainx', 'xplain', '']
        lines = [self.source]
        for index, key in enumerate(keys):
            lines.append(f'.k{index} = match({json.dumps(key)}, __candidates)')
        program = '\n'.join(lines) + '\n'
        with tempfile.TemporaryDirectory(prefix='candidate-regex-') as tmp:
            tmp = Path(tmp)
            (tmp/'p.vrl').write_text(program)
            (tmp/'in.json').write_text('{}\n')
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'in.json'), '--print-object'],
                                 text=True, capture_output=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
        line = next(l for l in run.stdout.splitlines() if l.startswith('{'))
        out = json.loads(line)
        for index, key in enumerate(keys):
            self.assertEqual(out[f'k{index}'], key in self.candidates, key)


if __name__ == '__main__':
    unittest.main()
