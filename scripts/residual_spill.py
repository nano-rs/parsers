#!/usr/bin/env python3
"""Generate/check inlined residual VRL from the shared template and justified rules."""
import argparse
import json
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
START = '# NAN-2421 residual spill.'
END = '# END NAN-2421 residual spill'


def transformations(config):
    rules = config.get('transforms', [])
    for rule in rules:
        assert rule.get('reason'), rule
        assert rule['kind'] in ('lowercase', 'epoch_ms', 'scale', 'enum', 'hex'), rule
    comments = ['# ' + r['source'] + ': ' + r['reason'] for r in rules]
    if config.get('reference') == 'windows_sysmon':
        comments += ['# ' + config['reference_reason'], '__consumed = append(__consumed, __reference_consumed)']
    # Keep a homogeneous dynamic rule type: source-specific literal objects
    # otherwise make VRL infer a very large union at every closure boundary.
    comments += ['# ' + config.get('consumed_reason', 'Explicit source candidates.'), '__candidates = ' + json.dumps(config.get('consumed_candidates', [])), '__preserve = ' + json.dumps(list(config.get('preserve_unmapped', {})))]
    payload = json.dumps(json.dumps(rules, separators=(',', ':')))
    return '\n'.join(comments) + '\n__rules = array!(parse_json!(' + payload + '))\n' + (ROOT/'scripts/residual/transforms.vrl').read_text().rstrip()


def generated(config):
    return (ROOT / 'scripts/residual/spill.vrl').read_text().replace('__TRANSFORMS__', transformations(config)).rstrip()


def update(path, check=False):
    text = path.read_text()
    config = yaml.safe_load(path.with_name('field-coverage.yaml').read_text())
    block = '\n'.join('  ' + s if s else '' for s in generated(config).splitlines()) + '\n'
    pattern = r'  ' + re.escape(START) + r'.*?  ' + re.escape(END) + r'\n'
    present = re.search(pattern, text, re.S)
    assert present or not check, f'{path}: missing spill block'
    stripped = re.sub(pattern, '', text, flags=re.S)
    start = stripped.index('\n', stripped.index('parser_vrl:')) + 1
    boundary = re.search(r'^\S', stripped[start:], re.M)
    index = start + boundary.start() if boundary else len(stripped)
    new = stripped[:index].rstrip() + '\n\n' + block
    if index < len(stripped):
        new += '\n' + stripped[index:]
    if check:
        assert new == text, f'{path}: generated spill is stale; run scripts/residual_spill.py {path}'
    else:
        path.write_text(new)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('parsers', nargs='*', type=Path)
    ap.add_argument('--check', action='store_true')
    args = ap.parse_args()
    paths = args.parsers or sorted(p.with_name('parser.yaml') for p in (ROOT/'parsers-ocsf').glob('*/field-coverage.yaml'))
    for path in paths:
        update(path, args.check)
    print(f'{"Checked" if args.check else "Generated"} {len(paths)} residual blocks')

if __name__ == '__main__':
    main()
