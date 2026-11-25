#!/usr/bin/env python3
"""The parser load-budget verdict (scripts/check-compile-budget.sh).

Input: one or more result files, each a run over parsers with lines
`<path> <ms> <ok|failed|killed>`, and the reference program's load times on the
same runner. Per parser the load time is the MEDIAN of its runs; the runner
factor is median(reference) / baseline, never below 1 and at most the cap; a
parser fails when Vector refused it or kept loading, or when its median divided
by the runner factor is over the budget. A slow runner can thus not fail a good
parser (up to the cap), and a real regression still fails.

`--slowdown X` multiplies every time (parsers and reference) by X: a synthetic
slow runner, for tests.
"""
import argparse
import statistics
import sys


def read_runs(paths):
    runs = {}
    for path in paths:
        for line in open(path):
            parts = line.split()
            if len(parts) != 3:
                continue
            name, ms, status = parts[0], int(parts[1]), parts[2]
            runs.setdefault(name, []).append((ms, status))
    return runs


def verdicts(runs, refs, budget_ms, baseline_ms, cap, slowdown=1.0):
    """[(path, raw_ms, median_ms, normalized_ms, verdict, ok)], factor, ref_ms."""
    ref_ms = statistics.median(r * slowdown for r in refs) if refs else baseline_ms
    factor = min(cap, max(1.0, ref_ms / baseline_ms))
    rows = []
    for path, samples in runs.items():
        times = [ms * slowdown for ms, _ in samples]
        statuses = [s for _, s in samples]
        raw, median = times[0], statistics.median(times)
        normalized = median / factor
        if 'failed' in statuses:
            verdict, ok = 'FAIL: Vector refused the program', False
        elif all(s == 'killed' for s in statuses) or statistics.median([1 if s == 'killed' else 0 for s in statuses]) == 1:
            verdict, ok = 'FAIL: still loading at twice the budget', False
        elif normalized > budget_ms:
            verdict, ok = f'FAIL: over budget ({normalized:.0f} ms normalized > {budget_ms} ms)', False
        else:
            verdict, ok = 'OK', True
        rows.append((path, raw, median, normalized, verdict, ok))
    rows.sort(key=lambda r: -r[3])
    return rows, factor, ref_ms


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--budget-ms', type=int, required=True)
    ap.add_argument('--baseline-ms', type=float, required=True)
    ap.add_argument('--cap', type=float, required=True)
    ap.add_argument('--ref', default='', help='the reference times, comma-separated')
    ap.add_argument('--slowdown', type=float, default=1.0)
    ap.add_argument('--summary')
    ap.add_argument('results', nargs='+')
    a = ap.parse_args()
    runs = read_runs(a.results)
    a.ref = [int(x) for x in a.ref.split(',') if x.strip()]
    rows, factor, ref_ms = verdicts(runs, a.ref, a.budget_ms, a.baseline_ms, a.cap, a.slowdown)
    print(f'Runner factor: {factor:.2f} (reference {ref_ms:.0f} ms median of {len(a.ref)}, baseline {a.baseline_ms:.0f} ms, cap {a.cap})')
    if a.slowdown != 1.0:
        print(f'SYNTHETIC slowdown x{a.slowdown} applied to every time')
    print(f'{"parser":<60} {"raw":>8} {"median":>8} {"norm.":>8} {"runs":>4}  result')
    for path, raw, median, normalized, verdict, _ in rows:
        print(f'{path:<60} {raw:>8.0f} {median:>8.0f} {normalized:>8.0f} {len(runs[path]):>4}  {verdict}')
    if a.summary:
        with open(a.summary, 'a') as f:
            f.write(f'### Parser load budget ({a.budget_ms / 1000:.0f}s, runner factor {factor:.2f})\n\n')
            f.write('| parser | raw (ms) | median (ms) | normalized (ms) |\n|---|---:|---:|---:|\n')
            for path, raw, median, normalized, _, _ in rows[:10]:
                f.write(f'| `{path}` | {raw:.0f} | {median:.0f} | {normalized:.0f} |\n')
    failed = sum(1 for r in rows if not r[5])
    print('')
    if failed:
        print(f'{failed} parser(s) over the load budget or refused by Vector.')
        sys.exit(1)
    print(f'All {len(rows)} parsers load within {a.budget_ms / 1000:.0f}s (normalized).')


if __name__ == '__main__':
    main()
