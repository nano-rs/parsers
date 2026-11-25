#!/usr/bin/env python3
"""The load-budget verdict (scripts/compile_budget_verdict.py): a slow runner
does not fail a good parser (up to the cap), a real regression still fails, a
median absorbs one slow sample, and a refused or still-loading program fails."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compile_budget_verdict import verdicts  # noqa: E402

BUDGET, BASE, CAP = 15000, 7600, 1.5


def verdict(runs, refs, slowdown=1.0):
    rows, factor, _ = verdicts({'p': [(ms, st) for ms, st in runs]}, refs, BUDGET, BASE, CAP, slowdown)
    return rows[0][5], round(factor, 2), round(rows[0][3])


CASES = [
    # (name, runs, reference runs, slowdown, want ok, want factor)
    ('a good parser on a normal runner', [(12000, 'ok')], [7600, 7500, 7700], 1.0, True, 1.0),
    ('the same parser on a runner 1.4x slower (synthetic)', [(12000, 'ok')], [7600, 7500, 7700], 1.4, True, 1.4),
    ('a runner faster than the baseline never lowers the bar', [(16000, 'ok')], [5000, 5000, 5000], 1.0, False, 1.0),
    ('a runner 2x slower: the factor stops at the cap', [(12000, 'ok')], [7600, 7600, 7600], 2.0, False, 1.5),
    ('a real regression on a normal runner fails', [(20000, 'ok'), (20500, 'ok'), (19800, 'ok')], [7600, 7600, 7600], 1.0, False, 1.0),
    ('a real regression on a slow runner still fails', [(20000, 'ok'), (20500, 'ok'), (19800, 'ok')], [7600, 7600, 7600], 1.4, False, 1.4),
    ('one slow sample: the median absorbs it', [(16000, 'ok'), (9000, 'ok'), (9500, 'ok')], [7600, 7600, 7600], 1.0, True, 1.0),
    ('a refused program fails', [(100, 'failed')], [7600, 7600, 7600], 1.0, False, 1.0),
    ('still loading in most runs fails', [(30000, 'killed'), (30000, 'killed'), (14000, 'ok')], [7600, 7600, 7600], 1.0, False, 1.0),
    ('the reference median, not one sample, sets the factor', [(14000, 'ok')], [7600, 30000, 7600], 1.0, True, 1.0),
]


def main():
    failures = []
    for name, runs, refs, slowdown, want_ok, want_factor in CASES:
        ok, factor, normalized = verdict(runs, refs, slowdown)
        if ok != want_ok or factor != want_factor:
            failures.append(f'{name}: ok={ok} factor={factor} normalized={normalized} (want ok={want_ok} factor={want_factor})')
    for f in failures:
        print('FAIL', f)
    if failures:
        sys.exit(1)
    print(f'PASS load budget verdict: {len(CASES)} cases (slow runner, cap, real regression, median, refused, killed)')


if __name__ == '__main__':
    main()
