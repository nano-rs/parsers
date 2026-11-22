#!/usr/bin/env python3
"""Write a parser's field-coverage.yaml `mappings` (and `transforms` targets)
from provenance: perturb each source value and record the OCSF paths whose
value follows it (scripts/provenance.py). Only real mappings are written; a
value that only coincides with an unrelated attribute is never declared, so it
spills.

Usage: infer_mappings.py PARSER... [--all-keys] [--dry-run]

By default the keys considered are the existing `mappings` keys (or a legacy
`consumed_candidates` list); --all-keys considers every captured source key,
for a new parser. Review the result: a declared mapping says "this source
field IS that attribute", and field_coverage_check.py re-verifies each one.
"""
import argparse
import json
from pathlib import Path
import sys

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance  # noqa: E402
from field_coverage_check import samples_for, PROBES  # noqa: E402
from residual_spill import ROOT, norm_path, update  # noqa: E402


def infer(path, all_keys=False):
    config_path = path.with_name('field-coverage.yaml')
    text = config_path.read_text()
    config = yaml.safe_load(text)
    doc = yaml.safe_load(path.read_text())
    samples = [(n, e) for n, e in samples_for(path, doc, None) if n not in PROBES]
    runs = provenance.run_vrl(doc['parser_vrl'], [e for _, e in samples])
    outputs = [o for o, _ in runs]
    sources = [s for _, s in runs]
    seen = list(dict.fromkeys(k for s in sources for k, _ in provenance.esc_flatten(s)))
    # A key named with plain dots (a legacy candidate list) means whichever
    # escaped field it spells: the nested path, or a literal dotted key.
    spelled = {}
    for k in seen:
        spelled.setdefault('.'.join(provenance.unesc(p) for p in k.split('.')), []).append(k)
    resolve = lambda k: [k] if k in seen else spelled.get(k, [k])
    if all_keys:
        keys = seen
    else:
        keys = list(dict.fromkeys(e for k in (list(config.get('mappings') or {}) or list(config.get('consumed_candidates') or [])) for e in resolve(k)))
    rules = []
    for rule in config.get('transforms') or []:
        for source in resolve(rule['source']):
            rules.append({**rule, 'source': source})
    items = [(k, None) for k in keys] + [(r['source'], r) for r in rules]
    found = provenance.probe(doc['parser_vrl'], samples, sources, outputs, items, per_key=40, scope=path.parent.name)
    mappings = {}
    for key in keys:
        targets = sorted(found.get((key, None), {}))
        if targets:
            mappings[key] = targets
    new_rules, dropped = [], []
    for rule in rules:
        targets = sorted(found.get((rule['source'], id(rule)), {}))
        if 'target' in rule and norm_path(rule['target']) in targets:
            new_rules.append(rule)
            continue
        if not targets:
            dropped.append(f"{rule['source']} ({rule['kind']})")
            continue
        for target in targets:
            new_rules.append({**{k: v for k, v in rule.items() if k != 'reason'}, 'target': target, 'reason': rule['reason']})
    unmapped = [k for k in keys if k not in mappings]
    return config, text, mappings, new_rules, dropped, unmapped


def write(config_path, text, config, mappings, rules):
    header = []
    for line in text.splitlines():
        if line.startswith('#') or not line.strip():
            header.append(line)
        else:
            break
    body = {k: v for k, v in config.items() if k not in ('consumed_candidates', 'consumed_reason', 'mappings', 'transforms')}
    if rules:
        body['transforms'] = rules
    body['mappings_reason'] = ('Each source key maps to the OCSF target path(s) its value is copied to; a key is '
                               'consumed only when its value is at one of them (field_coverage_check.py verifies '
                               'each by perturbation). Everything else spills to unmapped.')
    body['mappings'] = mappings
    out = '\n'.join(header) + ('\n' if header else '') + yaml.safe_dump(body, sort_keys=False, allow_unicode=True, width=100)
    config_path.write_text(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('parsers', nargs='+', type=Path)
    ap.add_argument('--all-keys', action='store_true')
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()
    report = {}
    for parser in args.parsers:
        path = parser/'parser.yaml' if parser.is_dir() else parser
        config, text, mappings, rules, dropped, unmapped = infer(path, args.all_keys)
        report[path.parent.name] = {'mapped_keys': len(mappings), 'now_spill': unmapped, 'dropped_rules': dropped}
        if not args.dry_run:
            write(path.with_name('field-coverage.yaml'), text, config, mappings, rules)
            update(path)
        print(f'{path.parent.name}: {len(mappings)} mapped keys; {len(unmapped)} keys now spill; {len(dropped)} rules dropped', flush=True)
    print(json.dumps(report, indent=1))


if __name__ == '__main__':
    main()
