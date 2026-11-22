#!/usr/bin/env python3
"""Provenance of a source field at an OCSF target path, by perturbation.

A mapping `source key -> target path` is real when changing that source value
(and nothing else) changes the value at the target path to the new value. A
value that merely equals some other attribute never passes: perturb the source
and the unrelated attribute keeps its old value.

field_coverage_check.py uses this to verify every declared mapping and every
`transforms` rule; infer_mappings.py uses it to write the declarations.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile

MISSING = object()
# Vector runs in UTC, so no result depends on the checking host's timezone.
VECTOR_ENV = {**os.environ, 'TZ': 'UTC'}


def obj_flatten(value, prefix=''):
    """VRL flatten(): objects flattened to dotted keys, arrays kept as values."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from obj_flatten(item, prefix + '.' + key if prefix else key)
    else:
        yield prefix, value


def mapped_leaves(event):
    """(normalized path, scalar) for every leaf the residual spill sees: the
    same walk as spill.vrl __repr (array indices dropped, two array levels)."""
    out = []
    for path, value in obj_flatten(event):
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for sub, leaf in obj_flatten(item):
                        p = path + '.' + sub
                        if isinstance(leaf, list):
                            out += [(p, x) for x in leaf if not isinstance(x, (dict, list))]
                        elif not isinstance(leaf, dict):
                            out.append((p, leaf))
                elif not isinstance(item, list):
                    out.append((path, item))
        elif not isinstance(value, dict):
            out.append((path, value))
    return out


def leaf_index(event):
    index = {}
    for path, value in mapped_leaves(event):
        index.setdefault(path, []).append(value)
    return index


def same(a, b):
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    if type(a) is type(b):
        return a == b
    # VRL to_string conversions preserve scalar numeric/boolean values.
    scalar = lambda v: json.dumps(v, separators=(',', ':')) if not isinstance(v, str) else v
    return a is not None and b is not None and not isinstance(a, (dict, list)) and not isinstance(b, (dict, list)) and scalar(a) == scalar(b)


def at(index, target, value):
    """Whether `value` (a scalar, or every element of a scalar array) is at `target`."""
    found = index.get(target, ())
    if isinstance(value, list):
        return bool(value) and all(not isinstance(x, (dict, list)) and any(same(x, v) for v in found) for x in value)
    if isinstance(value, dict):
        return False
    return any(same(value, v) for v in found)


def _shift_letter(char):
    lower = char.lower()
    if lower in 'abcdef':
        new = 'abcdef'[('abcdef'.index(lower) + 1) % 6]
    else:
        new = 'g' if lower == 'z' else chr(ord(lower) + 1)
    return new.upper() if char.isupper() else new


def mutations(value):
    """Small, shape-preserving changes of a scalar (so a parser that validates
    an IP, a timestamp or a hash still accepts it), most conservative first."""
    if isinstance(value, bool):
        return [not value]
    if isinstance(value, int):
        return [value + 1] + ([value - 1] if value > 0 else [])
    if isinstance(value, float):
        return [value + 0.5]
    if not isinstance(value, str):
        return []
    out = []
    digits = [i for i, c in enumerate(value) if c.isascii() and c.isdigit()]
    if digits:
        i = digits[-1]
        d = int(value[i])
        out.append(value[:i] + str(d - 1 if d > 1 else d + 1) + value[i + 1:])
    letters = [i for i, c in enumerate(value) if c.isascii() and c.isalpha()]
    if letters:
        i = letters[-1]
        out.append(value[:i] + _shift_letter(value[i]) + value[i + 1:])
    out.append(value + 'q' if value else 'q')
    return list(dict.fromkeys(m for m in out if m != value))


def array_mutations(value):
    """Element-wise variants of a scalar array (variant j mutates every element)."""
    if not value or any(isinstance(x, (dict, list)) for x in value):
        return []
    per = [mutations(x) for x in value]
    if not all(per):
        return []
    return [[m[min(j, len(m) - 1)] for m in per] for j in range(max(len(m) for m in per))]


def _resolve(obj, key):
    """Container and leaf of a flattened `key` in a raw JSON input, matching
    dotted segments greedily and stepping into one-element arrays."""
    parts = key.split('.')
    holder = obj
    i = 0
    while i < len(parts):
        if isinstance(holder, list) and len(holder) == 1:
            holder = holder[0]
        if not isinstance(holder, dict):
            return None
        for j in range(len(parts), i, -1):
            name = '.'.join(parts[i:j])
            if name in holder:
                if j == len(parts):
                    return holder, name
                holder = holder[name]
                i = j
                break
        else:
            return None
    return None


def _text(value):
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


def mutate_message(message, key, old, new):
    """Inputs with source `key` changed from `old` to `new` (a JSON input is
    edited at the key; text, or a value inside an envelope string, has one
    literal occurrence replaced at a time). The run confirms which one changed
    exactly that key and nothing else."""
    try:
        obj = json.loads(message)
    except json.JSONDecodeError:
        obj = None
    if isinstance(obj, (dict, list)):
        found = _resolve(obj, key)
        if found is not None and same(found[0][found[1]], old) and type(found[0][found[1]]) is type(old):
            obj = copy.deepcopy(obj)
            found = _resolve(obj, key)
            found[0][found[1]] = new
            return [json.dumps(obj)]
    if isinstance(old, list):
        out = message
        for o, n in zip(old, new):
            o, n = _text(o), _text(n)
            if not o or out.count(o) != 1:
                return []
            out = out.replace(o, n)
        return [out]
    o, n = _text(old), _text(new)
    if not o:
        return []
    variants = []
    for src, dst in ((o, n), (json.dumps(o)[1:-1], json.dumps(n)[1:-1])):
        start = 0
        while len(variants) < 8:
            i = message.find(src, start)
            if i < 0:
                break
            variants.append(message[:i] + dst + message[i + len(src):])
            start = i + 1
        if variants:
            break
    return variants


def mutate_event(event, key, old, new):
    """Events with source `key` changed: in the event's own fields (a collector
    envelope next to `message`), or else inside its message."""
    found = _resolve(event, key)
    if found is not None and found[1] != 'message' and same(found[0][found[1]], old) and type(found[0][found[1]]) is type(old):
        mutated = copy.deepcopy(event)
        holder = _resolve(mutated, key)
        holder[0][holder[1]] = new
        return [mutated]
    message = event.get('message')
    if not isinstance(message, str):
        return []
    return [{**event, 'message': m} for m in mutate_message(message, key, old, new)]


def run_vrl(program, messages):
    """Run the instrumented program over events (or bare message strings);
    (output, source) per input."""
    with tempfile.TemporaryDirectory(prefix='provenance-') as tmp:
        tmp = Path(tmp)
        (tmp/'p.vrl').write_text(program + '\n.__coverage_source = __source_kv\n')
        (tmp/'in.json').write_text(''.join(json.dumps(m if isinstance(m, dict) else {'message': m}) + '\n' for m in messages))
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'in.json'), '--print-object'],
                             text=True, capture_output=True, timeout=900, env=VECTOR_ENV)
    assert run.returncode == 0, run.stderr
    outputs = [json.loads(line, strict=False) for line in run.stdout.splitlines() if line.startswith('{')]
    assert len(outputs) == len(messages), f'Vector returned {len(outputs)} events for {len(messages)} inputs'
    return [(o, o.pop('__coverage_source', {})) for o in outputs]


def mapped_view(output, raw):
    return {k: v for k, v in output.items() if k not in ('unmapped', 'raw_data') and not (k == 'message' and v == raw)}


def transform_want(rule, value):
    """The converted value a transforms rule expects, or MISSING."""
    import datetime as dt
    try:
        kind = rule['kind']
        if kind == 'lowercase':
            return value.lower() if isinstance(value, str) else MISSING
        if kind == 'epoch_ms':
            fmt = rule.get('format', '%+')
            if fmt == '%+':
                clock = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
            else:
                # chrono's %e (space-padded day) has no strptime twin; %d
                # accepts the day once the padding space is collapsed.
                if '%e' in fmt:
                    fmt, value = fmt.replace('%e', '%d'), ' '.join(value.split())
                    fmt = ' '.join(fmt.split())
                clock = dt.datetime.strptime(value, fmt)
            # Every parser passes timezone: "UTC" (field_coverage_check
            # enforces it), so a clock without an offset is UTC.
            if clock.tzinfo is None:
                clock = clock.replace(tzinfo=dt.timezone.utc)
            return int(clock.timestamp() * 1000)
        if kind == 'scale':
            return int(float(value) * rule['factor'])
        if kind == 'hex':
            return int(value, 16) if isinstance(value, str) and value.lower().startswith('0x') else MISSING
        if kind == 'enum':
            return rule['values'].get(str(value).lower(), MISSING)
    except (ValueError, TypeError, AttributeError, OverflowError):
        return MISSING
    raise AssertionError(f'unknown transform {rule.get("kind")}')


def rule_mutations(rule, value):
    if rule['kind'] == 'enum':
        here = rule['values'].get(str(value).lower(), MISSING)
        out = []
        for alt in [k for k, v in rule['values'].items() if v != here][:2]:
            if isinstance(value, bool):
                if alt in ('true', 'false') and (alt == 'true') != value:
                    out.append(alt == 'true')
                continue
            if isinstance(value, int):
                if alt.lstrip('-').isdigit():
                    out.append(int(alt))
            elif isinstance(value, str):
                out.append(alt.upper() if value.isupper() else (alt.capitalize() if value[:1].isupper() else alt))
        return out
    return mutations(value)


def probe(program, samples, sources, outputs, items, per_key=6):
    """Perturbation runs for `items`: (key, rule or None) pairs.

    Returns {(key, rule_id): {target: True}} for every normalized target path
    whose value followed the perturbed source value in at least one sample,
    and held the original value before. `rule_id` is None for a plain mapping.
    """
    plans, messages = [], []
    for key, rule in items:
        used = 0
        for (name, event), source, output in zip(samples, sources, outputs):
            if used >= per_key:
                break
            flat = dict(obj_flatten(source))
            if key not in flat:
                continue
            old = flat[key]
            if isinstance(old, dict) or old is None:
                continue
            variants = array_mutations(old) if isinstance(old, list) else (rule_mutations(rule, old) if rule else mutations(old))
            planned = False
            for new in variants:
                for mutated_event in mutate_event(event, key, old, new):
                    if mutated_event == event:
                        continue
                    plans.append((key, rule, old, new, event.get('message'), output, flat))
                    messages.append(mutated_event)
                    planned = True
            used += planned
    found = {}
    if not messages:
        return found
    for (key, rule, old, new, raw, output, flat), (mutated, source) in zip(plans, run_vrl(program, messages)):
        # The perturbation must change exactly this source field, to `new`.
        mflat = dict(obj_flatten(source))
        if not same_value(mflat.get(key, MISSING), new):
            continue
        if set(mflat) != set(flat) or any(not _bystander(k, v, mflat[k], key, old) for k, v in flat.items() if mflat[k] != v):
            continue
        before, after = leaf_index(mapped_view(output, raw)), leaf_index(mapped_view(mutated, None))
        if rule is None:
            want_old, want_new = old, new
        else:
            want_old, want_new = transform_want(rule, old), transform_want(rule, new)
            if want_old is MISSING or want_new is MISSING or same(want_old, want_new):
                continue
        for target in after:
            if at(after, target, want_new) and at(before, target, want_old) and not at(after, target, want_old if not isinstance(want_old, list) else []):
                found.setdefault((key, id(rule) if rule else None), {})[target] = True
    return found


def _bystander(k, before, after, key, old):
    """Whether another source field may change with the perturbed one: only a
    longer text that CONTAINS the perturbed value (a full message, a raw line).
    A field whose value equals it is a separate field (a coincidence), so it
    must not change."""
    if k == key:
        return True
    text = _text(old) if not isinstance(old, list) else None
    return bool(text) and isinstance(before, str) and isinstance(after, str) and text in before and before != text


def same_value(a, b):
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a is not MISSING and same(a, b)
