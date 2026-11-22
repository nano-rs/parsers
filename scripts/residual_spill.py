#!/usr/bin/env python3
"""Generate/check inlined residual VRL from the shared template and justified rules."""
import argparse
import decimal
import math
import json
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[1]
START = '# NAN-2421 residual spill.'
END = '# END NAN-2421 residual spill'
TZ_START = '# NAN source timezone.'
TZ_END = '# END NAN source timezone'


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


def norm_path(path):
    """A target path as __repr names it: dotted, array indices dropped."""
    return '.'.join(part for part in path.split('.') if not part.isdigit())


BRACKETS = {char: '\\u%04x' % ord(char) for char in '()[]{}'}


def json_text(value):
    """Compact JSON whose brackets inside strings are \\u escapes: nano's deploy
    validator counts raw ()[]{} characters across the whole VRL."""
    text = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
    out, in_string, escaped = [], False, False
    for char in text:
        if in_string and not escaped and char in BRACKETS:
            out.append(BRACKETS[char].replace('\\\\', '\\'))
            continue
        out.append(char)
        if escaped:
            escaped = False
        elif char == '\\':
            escaped = in_string
        elif char == '"':
            in_string = not in_string
    return ''.join(out)


def vrl_text(text):
    """Any text as a VRL string literal (no raw brackets expected inside)."""
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t') + '"'


def rule_body(rule, templates):
    """One rule's body, written against the loop's `key` and `value`."""
    # Against __repr: the value must be AT the rule's target path of the mapped
    # event (no raw_data, unmapped, or raw-body message), never just anywhere.
    match = 'contains(__repr, "," + ' + vrl_text(json_text(norm_path(rule['target']))) + ' + "=" + encode_json(encode_json(__expected)))'
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
    return text.replace('__MATCH__', match)


def grouped(rules, templates):
    """Rules that render to the same body, in first-appearance order.

    NAN-5298: one `if` per rule made the program's statement count, and with it
    Vector's compile (reload) time, grow with the rule count; a group costs one
    regex test per source key at run time and one body at compile time.
    """
    groups = {}
    for rule in rules:
        keys = groups.setdefault(rule_body(rule, templates), [])
        if rule['source'] not in keys:
            keys.append(rule['source'])
    return list(groups.items())


REGEX_META = set('\\.+*?|^$#&-~ ')
# nano's deploy validator counts raw ()[]{} characters across the whole VRL, so
# a bracket in a candidate is written as a hex escape, never as \( etc.
REGEX_HEX = {char: '\\x%02X' % ord(char) for char in '()[]{}'}


def key_regex(keys):
    """Whole-key alternation lines for a verbose regex literal.

    Every regex metacharacter and space in a key is escaped, and a bracket is
    hex-escaped so the raw bracket counts stay balanced.
    """
    lines = ['\\A(?:']
    for index, key in enumerate(keys):
        assert isinstance(key, str) and key and not re.search(r"[\x00-\x1f\x7f']", key), key
        assert not any(char.isspace() and char != ' ' for char in key), key
        escaped = ''.join(REGEX_HEX.get(char) or ('\\' + char if char in REGEX_META else char) for char in key)
        lines.append(('  ' if index == 0 else '| ') + escaped)
    return lines + [")\\z'"]


def check_target(source, target):
    assert isinstance(target, str) and target and all(target.split('.')), f'{source}: target must be a dotted path'
    assert norm_path(target), f'{source}: target must name an attribute'
    assert target.split('.')[0] not in ('unmapped', 'raw_data'), f'{source}: target may not be under unmapped or raw_data'
    # OCSF attribute names never hold a bracket; __repr spells paths raw.
    assert not any(c in target for c in '()[]{}'), f'{source}: target may not contain a bracket'


def mappings_of(config):
    """field-coverage.yaml `mappings`: source key -> list of normalized targets."""
    assert 'consumed_candidates' not in config, 'consumed_candidates is replaced by `mappings` (source key -> target paths)'
    raw = config.get('mappings') or {}
    assert isinstance(raw, dict), 'mappings must map a source key to its target path(s)'
    out = {}
    for key, targets in raw.items():
        assert isinstance(key, str) and key, f'mapping source must be a key: {key!r}'
        targets = [targets] if isinstance(targets, str) else targets
        assert isinstance(targets, list) and targets, f'{key}: mapping needs one or more target paths'
        for target in targets:
            check_target(key, target)
        out[key] = list(dict.fromkeys(norm_path(t) for t in targets))
    return out


def decl_literal(mappings):
    """The declared mappings as one VRL string: "\\n" + key JSON + "\\t" + target
    array JSON per key, then "\\n". Looked up with find() (NAN-5351)."""
    text = ''.join('\n' + json_text(key) + '\t' + json_text(targets) for key, targets in mappings.items()) + '\n'
    return vrl_text(text)


def check_rule(rule):
    """One `transforms` rule: a source, a known kind, its parameters, a reason."""
    assert isinstance(rule, dict) and isinstance(rule.get('source'), str) and rule['source'], f'transform needs a source: {rule!r}'
    assert isinstance(rule.get('reason'), str) and rule['reason'].strip(), f'every transformation needs a justification: {rule["source"]}'
    assert rule.get('kind') in KINDS, f'{rule["source"]}: unknown transform kind {rule.get("kind")!r}'
    # Every rule names the attribute its converted value lands in: a value found
    # anywhere else is no evidence (no coincidental consumption).
    check_target(rule['source'], rule.get('target'))
    if rule['kind'] == 'scale':
        factor = rule.get('factor')
        assert type(factor) in (int, float) and math.isfinite(factor) and factor != 0, f'{rule["source"]}: scale needs a finite, non-zero factor'
    if rule['kind'] == 'enum':
        values = rule.get('values')
        assert isinstance(values, dict) and values, f'{rule["source"]}: enum needs a non-empty values mapping'
    if rule['kind'] == 'epoch_ms':
        assert 'format' not in rule or (isinstance(rule['format'], str) and rule['format']), f'{rule["source"]}: epoch_ms format must be a non-empty string'


def transformations(config):
    rules = config.get('transforms', [])
    for rule in rules:
        check_rule(rule)
    templates = kind_templates()
    lines = ['# ' + rule['source'] + ': ' + rule['reason'] for rule in rules]
    groups = grouped(rules, templates)
    if groups:
        lines.append('for_each(__flat) -> |key, value| {')
        for body, keys in groups:
            regex = key_regex(keys)
            lines.append("    if match(key, r'(?x)")
            lines += ['    ' + line for line in regex]
            lines[-1] += ') {'
            lines += ['        ' + line for line in body.splitlines()]
            lines.append('    }')
        lines.append('}')
    if config.get('reference') == 'windows_sysmon':
        lines += ['# ' + config['reference_reason'], 'for_each(array!(__reference_consumed)) -> |_index, key| {', '    __consumed = __consumed + ("," + encode_json(key))', '}']
    lines += ['# Declared source -> target mappings (field-coverage.yaml `mappings`).', '__decl = ' + decl_literal(mappings_of(config))]
    lines += ['__preserve = ' + json.dumps(list(config.get('preserve_unmapped', {})))]
    return '\n'.join(lines)


def generated(config):
    return (ROOT / 'scripts/residual/spill.vrl').read_text().replace('__TRANSFORMS__', transformations(config)).rstrip()


def prelude():
    """The shared source-timezone block every parser starts with."""
    return (ROOT / 'scripts/residual/source_tz.vrl').read_text().rstrip()


def update(path, check=False):
    text = path.read_text()
    # The source-timezone prelude opens parser_vrl, before the parser reads
    # anything (it removes .nano, nano's own input, from the event).
    tz_pattern = r'  ' + re.escape(TZ_START) + r'.*?  ' + re.escape(TZ_END) + r'\n'
    tz_block = '\n'.join('  ' + s if s else '' for s in prelude().splitlines()) + '\n'
    assert re.search(tz_pattern, text, re.S) or not check, f'{path}: missing source-timezone prelude'
    text_wo = re.sub(tz_pattern, '', text, flags=re.S)
    head = text_wo.index('\n', text_wo.index('parser_vrl:')) + 1
    text = text_wo[:head] + tz_block + text_wo[head:]
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
        assert new == path.read_text(), f'{path}: generated spill is stale; run scripts/residual_spill.py {path}'
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
