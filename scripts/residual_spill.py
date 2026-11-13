#!/usr/bin/env python3
"""Generate/check inlined residual VRL from the shared template and justified rules."""
import argparse
import decimal
import json
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
START = '# NAN-2421 residual spill.'
END = '# END NAN-2421 residual spill'


KINDS = ('lowercase', 'epoch_ms', 'scale', 'enum', 'hex')
SENSITIVE = re.compile(r'[\x00-\x1f"\\\'{}]')


def vrl_string(text):
    """A VRL string literal. Keys and enum strings are plain text (checked)."""
    assert isinstance(text, str) and not SENSITIVE.search(text), f'unsupported character in {text!r}'
    return '"' + text + '"'


def vrl_number(value):
    assert type(value) in (int, float), value
    if type(value) is int:
        return str(value)
    # VRL has no exponent literal; the plain decimal parses to the same double.
    text = format(decimal.Decimal(repr(value)), 'f')
    return text if '.' in text else text + '.0'


def vrl_literal(value):
    if isinstance(value, str):
        return vrl_string(value)
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    return vrl_number(value)


def kind_templates():
    """Split transforms.vrl into one template per `# kind: <name>` section."""
    templates, current = {}, None
    for line in (ROOT/'scripts/residual/transforms.vrl').read_text().splitlines():
        marker = re.match(r'# kind: (\w+)$', line)
        if marker:
            current = marker.group(1)
            templates[current] = []
        elif current:
            templates[current].append(line)
    assert set(templates) == set(KINDS), templates.keys()
    return {kind: '\n'.join(lines) for kind, lines in templates.items()}


def unrolled(rule, templates):
    """One rule as straight-line VRL, mirroring the former __rules loop exactly."""
    source = vrl_string(rule['source'])
    if isinstance(rule.get('target'), str):
        path = ''.join('.' + vrl_string(part) for part in rule['target'].split('.'))
        match = path + ' == __expected'
    else:
        match = 'contains(__represented, "," + encode_json(encode_json(__expected)))'
    text = templates[rule['kind']]
    if rule['kind'] == 'epoch_ms':
        fmt = rule.get('format', '%+')
        text = text.replace('__FORMAT__', vrl_string(fmt if isinstance(fmt, str) else '%+'))
    elif rule['kind'] == 'scale':
        text = text.replace('__FACTOR__', vrl_number(float(rule['factor'])))
    elif rule['kind'] == 'enum':
        values = rule['values']
        # The template skips an absent source, which the old loop looked up as "".
        assert '' not in values and all(isinstance(k, str) for k in values), rule
        text = text.replace('__VALUES__', '{' + ', '.join(vrl_string(k) + ': ' + vrl_literal(v) for k, v in values.items()) + '}')
    return text.replace('__SOURCE_STRING__', source).replace('__SOURCE__', source).replace('__MATCH__', match)


REGEX_META = set('\\.+*?()|[]{}^$#&-~ ')


def candidate_regex(candidates):
    """The candidate set as a whole-key regex literal, one candidate per line.

    A regex literal compiles once with the program, so a lookup reads no copy
    of the set (NAN-5351). Verbose mode ignores the layout whitespace; every
    regex metacharacter and space in a candidate is escaped.
    """
    if not candidates:
        return ["__candidates = r'\\b\\B'"]  # matches nothing
    lines = ["__candidates = r'(?x)", '\\A(?:']
    for index, candidate in enumerate(candidates):
        assert isinstance(candidate, str) and candidate and not re.search(r"[\x00-\x1f\x7f']", candidate), candidate
        assert not any(char.isspace() and char != ' ' for char in candidate), candidate
        escaped = ''.join('\\' + char if char in REGEX_META else char for char in candidate)
        lines.append(('  ' if index == 0 else '| ') + escaped)
    return lines + [")\\z'"]


def transformations(config):
    rules = config.get('transforms', [])
    for rule in rules:
        assert rule.get('reason'), rule
        assert rule['kind'] in KINDS, rule
    templates = kind_templates()
    lines = ['__source_flat = flatten(__source_kv)']
    for rule in rules:
        lines += ['# ' + rule['source'] + ': ' + rule['reason'], unrolled(rule, templates)]
    if config.get('reference') == 'windows_sysmon':
        lines += ['# ' + config['reference_reason'], 'for_each(array!(__reference_consumed)) -> |_index, key| {', '    __consumed = __consumed + ("," + encode_json(key))', '}']
    lines += ['# ' + config.get('consumed_reason', 'Explicit source candidates.')] + candidate_regex(config.get('consumed_candidates', []))
    lines += ['__preserve = ' + json.dumps(list(config.get('preserve_unmapped', {})))]
    return '\n'.join(lines)


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
