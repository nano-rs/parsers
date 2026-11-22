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
import hashlib
import json
import math
import os
import random
import re
import secrets
from pathlib import Path
import subprocess
import tempfile

MISSING = object()
# Vector runs in UTC, so no result depends on the checking host's timezone.
VECTOR_ENV = {**os.environ, 'TZ': 'UTC'}


def esc(key):
    """A literal key as one flattened path segment: '~' and '.' escaped, as
    spill.vrl does, so a literal dotted key never names a nested path."""
    return key.replace('~', '~0').replace('.', '~1')


def unesc(segment):
    return segment.replace('~1', '.').replace('~0', '~')


def esc_flatten(value, prefix=''):
    """Source flattening with escaped segments: {"a": {"b": 1}} is "a.b",
    {"a.b": 1} is "a~1b". Mapping keys name source fields this way."""
    if isinstance(value, dict):
        for key, item in value.items():
            yield from esc_flatten(item, prefix + '.' + esc(key) if prefix else esc(key))
    else:
        yield prefix, value


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


# Deterministic, unguessable perturbations: every draw is seeded with SHA-256 of
# (base seed, parser, sample, field, draw), so each run is reproducible and no
# check flakes, while a parser cannot depend on the values. PROVENANCE_SEED
# overrides the base seed ("random" draws a fresh one, for fuzzing); a failure
# prints the seed it used.
BASE_SEED = os.environ.get('PROVENANCE_SEED') or 'nano-provenance-v1'
if BASE_SEED == 'random':
    BASE_SEED = secrets.token_hex(8)
RNG = random.Random(0)


def seed_draw(*parts):
    """Seed RNG for one draw from (BASE_SEED, *parts)."""
    digest = hashlib.sha256(json.dumps([BASE_SEED, *[str(p) for p in parts]]).encode()).digest()
    RNG.seed(int.from_bytes(digest[:16], 'big'))
IPV4 = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
IPV6 = re.compile(r'^[0-9A-Fa-f:]{2,}$')
NUMBER = re.compile(r'^-?\d+(?:\.(\d+))?$')
CLOCK = re.compile(r'(?<!\d)(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?!\d)')
DAY = re.compile(r'(?<!\d)(\d{4}[-/]\d{2}[-/])(\d{2})(?!\d)')
HEX = set('abcdefABCDEF')
DRAWS = 4


def _rand_like(text):
    """The same shape with fresh random characters: a digit becomes a random
    digit, a hex letter a random hex letter, any other letter a random letter
    (case kept); punctuation and separators stay."""
    out = []
    for c in text:
        # Each character always changes (a lone "vty0" digit never stays "0").
        if c.isascii() and c.isdigit():
            out.append(RNG.choice([d for d in '0123456789' if d != c]))
        elif c in HEX:
            pool = 'abcdef' if c.islower() else 'ABCDEF'
            out.append(RNG.choice([h for h in pool if h != c]))
        elif c.isascii() and c.isalpha():
            letters = 'ghijklmnopqrstuvwxyz' if c.islower() else 'GHIJKLMNOPQRSTUVWXYZ'
            out.append(RNG.choice([l for l in letters if l != c]))
        else:
            out.append(c)
    return ''.join(out)


def _number(value, factor=None):
    """A random number of the same type and sign, far enough from `value` that
    a `scale` by `factor` (e.g. 0.001, us -> ms) still moves the result."""
    step = max(1, math.ceil(1 / abs(factor))) if factor else 1
    delta = RNG.randint(1000, 9999) * step
    if isinstance(value, float):
        if factor:
            # A whole number: value * factor is then exact in both Python and
            # VRL (a random fraction can round differently).
            return float(math.floor(value) + delta)
        if 0 <= value <= 1:
            # A probability or ratio stays in range.
            return round(RNG.uniform(0.001, 0.999), 6)
        return value + delta + RNG.randint(1, 99) / 100
    return value + delta if value >= 0 else value - delta


def _code(value, exclude):
    """A small code from 0..31 that the field never takes in any sample (so a
    short lookup table keyed by the observed values cannot echo it back)."""
    pool = [v for v in range(32) if v != value and v not in exclude]
    return RNG.choice(pool) if pool else None


def sentinels(value, kind=None, factor=None, exclude=()):
    """Fresh, type-correct perturbations of a scalar, most specific first. Each
    is random per run, so it cannot coincide with a value the parser holds."""
    if isinstance(value, bool):
        return [not value]
    if isinstance(value, int):
        if kind is None and 0 <= value < 32:
            # Enum-like codes (severity, rcode, logon type) are range-checked.
            # Enum-like codes: drawn from outside the values the field takes in
            # any sample, so a lookup keyed by those values cannot pass.
            code = _code(value, exclude)
            return [code] if code is not None else []
        if kind is None and 0 <= value < 65536:
            # Ports and small ids are range-checked too.
            return list(dict.fromkeys(v for v in (RNG.randint(1, 65535), RNG.randint(1, 65535)) if v != value))
        return [_number(value, factor)]
    if isinstance(value, float):
        return list(dict.fromkeys(v for v in (_number(value, factor), _number(value, factor)) if v != value))
    if not isinstance(value, str) or not value:
        return []
    out = []
    num = NUMBER.match(value)
    if num and kind is None and not num.group(1) and 0 <= int(value) < 32:
        # An enum-like code written as text ("3", "10").
        # A text code is drawn the same way and ONLY that way (no shape
        # variants), so a short lookup keyed by the observed codes cannot pass.
        code = _code(int(value), {int(x) for x in exclude if isinstance(x, str) and x.isdigit()} | {x for x in exclude if type(x) is int})
        return [str(code)] if code is not None else []
    if num and kind == 'scale':
        decimals = len(num.group(1) or '')
        new = _number(float(value) if decimals else int(value), factor)
        out.append(f'{new:.{decimals}f}' if decimals else str(new))
        out.append(f'{_number(float(value) if decimals else int(value), factor):.{decimals}f}' if decimals else str(_number(int(value), factor)))
    if kind == 'scale':
        # Only a whole-number move is certain to move the scaled result.
        return list(dict.fromkeys(v for v in out if v != value))
    if CLOCK.search(value):
        # A clock keeps its format and fraction; only the time of day moves.
        out.append(CLOCK.sub(lambda m: '%02d:%02d:%02d' % (RNG.randint(0, 23), RNG.randint(0, 59), RNG.randint(0, 59)), value, count=1))
    if DAY.search(value):
        out.append(DAY.sub(lambda m: m.group(1) + '%02d' % RNG.randint(1, 28), value, count=1))
    if kind == 'epoch_ms':
        return list(dict.fromkeys(v for v in out if v != value))
    if IPV4.match(value):
        out.append('%d.%d.%d.%d' % (RNG.randint(11, 223), RNG.randint(0, 255), RNG.randint(0, 255), RNG.randint(1, 254)))
    elif kind == 'hex' and value.lower().startswith('0x'):
        out.append(value[:2] + ''.join(RNG.choice('0123456789abcdef') for _ in value[2:]))
    else:
        # Narrowest first: only the tail (a prefix such as "hmac-sha256:" or a
        # drive and directory stays), only the digits ("CVE-" stays), then the
        # whole shape, then a suffix for free text.
        half = len(value) // 2
        out.append(value[:half] + _rand_like(value[half:]))
        if any(c.isascii() and c.isdigit() for c in value):
            out.append(''.join(RNG.choice('0123456789') if c.isascii() and c.isdigit() else c for c in value))
        out.append(_rand_like(value))
        if not IPV6.match(value) and kind is None:
            out.append(value + '-' + ''.join(RNG.choice('ghijklmnopqrstuvwxyz') for _ in range(6)))
    return list(dict.fromkeys(v for v in out if v != value))


def mutations(value):
    return sentinels(value)


def array_mutations(value, exclude=()):
    """A fresh sentinel for every element of a scalar array (variant j uses
    each element's j-th sentinel)."""
    if not value or any(isinstance(x, (dict, list)) for x in value):
        return []
    per = [sentinels(x, exclude=exclude) for x in value]
    if not all(per):
        return []
    return [[m[min(j, len(m) - 1)] for m in per] for j in range(max(len(m) for m in per))]


def _resolve(obj, key):
    """Container and leaf of an escaped flattened `key` in a raw JSON input,
    stepping into one-element arrays (an unwrapped envelope)."""
    parts = [unesc(p) for p in key.split('.')]
    holder = obj
    for i, part in enumerate(parts):
        if isinstance(holder, list) and len(holder) == 1:
            holder = holder[0]
        if not isinstance(holder, dict) or part not in holder:
            return None
        if i == len(parts) - 1:
            return holder, part
        holder = holder[part]
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


def run_vrl(program, messages, tolerant=False):
    """Run the instrumented program over events (or bare message strings);
    (output, source) per input. With `tolerant`, an input the program aborts
    on (a perturbation it rejects) yields None instead of failing the run:
    each input carries an id the program removes before the parser sees it."""
    events = [dict(m) if isinstance(m, dict) else {'message': m} for m in messages]
    head = '__probe_id = del(.__probe_id)\n' if tolerant else ''
    tail = '\n.__coverage_source = __source_kv\n' + ('.__probe_id = __probe_id\n' if tolerant else '')
    if tolerant:
        for i, e in enumerate(events):
            e['__probe_id'] = i
    with tempfile.TemporaryDirectory(prefix='provenance-') as tmp:
        tmp = Path(tmp)
        (tmp/'p.vrl').write_text(head + program + tail)
        (tmp/'in.json').write_text(''.join(json.dumps(e) + '\n' for e in events))
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'in.json'), '--print-object'],
                             text=True, capture_output=True, timeout=900, env=VECTOR_ENV)
    assert run.returncode == 0 or tolerant, run.stderr
    outputs = [json.loads(line, strict=False) for line in run.stdout.splitlines() if line.startswith('{')]
    if not tolerant:
        assert len(outputs) == len(messages), f'Vector returned {len(outputs)} events for {len(messages)} inputs'
        return [(o, o.pop('__coverage_source', {})) for o in outputs]
    by_id = {}
    for o in outputs:
        pid = o.pop('__probe_id', None)
        if isinstance(pid, int):
            by_id[pid] = (o, o.pop('__coverage_source', {}))
    return [by_id.get(i) for i in range(len(events))]


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


def rule_mutations(rule, value, exclude=()):
    if rule['kind'] == 'enum':
        # One alternative per distinct target value (every one, not the first few).
        here = rule['values'].get(str(value).lower(), MISSING)
        seen, out = set(), []
        for alt, target in rule['values'].items():
            key = json.dumps(target, sort_keys=True)
            if target == here or key in seen:
                continue
            if isinstance(value, bool):
                if alt in ('true', 'false') and (alt == 'true') != value:
                    out.append(alt == 'true')
                    seen.add(key)
                continue
            if isinstance(value, int):
                if alt.lstrip('-').isdigit():
                    out.append(int(alt))
                    seen.add(key)
            elif isinstance(value, str):
                out.append(alt.upper() if value.isupper() else (alt.capitalize() if value[:1].isupper() else alt))
                seen.add(key)
        return out
    return sentinels(value, rule['kind'], rule.get('factor'), exclude)


def _count(index, target, value):
    return sum(1 for x in index.get(target, ()) if same(value, x))


def followed(before, after, target, want_old, want_new):
    """The value at `target` moved WITH the source: the old value left it and
    exactly the new (fresh, random) value arrived. For a list, element by
    element as a multiset, so a static list can never pass."""
    olds = want_old if isinstance(want_old, list) else [want_old]
    news = want_new if isinstance(want_new, list) else [want_new]
    if len(olds) != len(news) or not olds:
        return False
    moved = False
    for o, n in zip(olds, news):
        if isinstance(o, (dict, list)) or isinstance(n, (dict, list)):
            return False
        if same(o, n):
            continue
        if not (_count(after, target, n) > _count(before, target, n) and _count(after, target, o) < _count(before, target, o)):
            return False
        moved = True
    return moved


def probe(program, samples, sources, outputs, items, per_key=40, declared=None, scope=''):
    """Perturbation runs for `items`: (key, rule or None) pairs.

    Returns {(key, rule_id): {target: True}} for every normalized target path
    whose value followed the perturbed source value (fresh random sentinels)
    in at least one sample. `rule_id` is None for a plain mapping. Only a
    sample whose mapped event holds the current value counts toward
    `per_key` (at a declared target, when `declared` maps item -> targets), so
    branches that ignore the field do not use up the budget.
    """
    plans, messages = [], []
    flats = [dict(esc_flatten(source)) for source in sources]
    for key, rule in items:
        used = 0
        # Every value the field takes in any sample: a draw avoids them.
        observed = set()
        for flat in flats:
            v = flat.get(key)
            for x in (v if isinstance(v, list) else [v]):
                if x is not None and not isinstance(x, (dict, list)):
                    observed.add(x)
        for (name, event), source, output in zip(samples, sources, outputs):
            if used >= per_key:
                break
            flat = dict(esc_flatten(source))
            if key not in flat:
                continue
            old = flat[key]
            if isinstance(old, dict) or old is None:
                continue
            want_old = old if rule is None else transform_want(rule, old)
            if want_old is MISSING:
                continue
            before = leaf_index(mapped_view(output, event.get('message')))
            targets = (declared or {}).get((key, id(rule) if rule else None))
            places = targets if targets is not None else list(before)
            if not any(at(before, target, want_old) for target in places):
                continue
            # Several fresh draws: a parser that accepts only some values (an
            # enum code, a range) still sees one it maps.
            variants = []
            for draw in range(DRAWS):
                seed_draw(scope, name, key, rule['kind'] + '>' + rule.get('target', '') if rule else '', draw)
                variants += array_mutations(old, observed) if isinstance(old, list) else (rule_mutations(rule, old, observed) if rule else sentinels(old, exclude=observed))
            variants = [v for i, v in enumerate(variants) if v not in variants[:i]]
            planned = False
            for new in variants:
                for mutated_event in mutate_event(event, key, old, new):
                    if mutated_event == event:
                        continue
                    plans.append((key, rule, old, new, event, output, flat))
                    messages.append(mutated_event)
                    planned = True
            used += planned
    found, hits, single = {}, {}, set()
    if not messages:
        return found
    for (key, rule, old, new, event, output, flat), mutated_event, result in zip(plans, messages, run_vrl(program, messages, tolerant=True)):
        if result is None:
            continue
        mutated, source = result
        # The perturbation must change exactly this source field, to `new`.
        mflat = dict(esc_flatten(source))
        if not same_value(mflat.get(key, MISSING), new):
            continue
        if set(mflat) != set(flat) or any(not _bystander(k, v, mflat[k], key, old) for k, v in flat.items() if mflat[k] != v):
            continue
        before = leaf_index(mapped_view(output, event.get('message')))
        after = leaf_index(mapped_view(mutated, mutated_event.get('message')))
        if rule is None:
            want_old, want_new = old, new
        else:
            want_old, want_new = transform_want(rule, old), transform_want(rule, new)
            if want_old is MISSING or want_new is MISSING or same(want_old, want_new):
                continue
        for target in set(after) | set(before):
            if followed(before, after, target, want_old, want_new):
                hits.setdefault((key, id(rule) if rule else None), {}).setdefault(target, set()).add(json.dumps(want_new, sort_keys=True))
                # A boolean has one other value; an enum rule's own table fixes the
                # expected value, so one arrival of a different outcome proves it.
                lone = isinstance(old, bool) or (rule is not None and rule['kind'] == 'enum')
                single.add((key, id(rule) if rule else None, lone))
    # Two distinct sentinels must arrive: one could be a lookup (an id mapped
    # to a class) that happens to output the new value. A boolean, or an enum
    # rule (its table names the expected value), needs one.
    for item, targets in hits.items():
        boolean = (item[0], item[1], True) in single
        for target, seen in targets.items():
            if len(seen) >= 2 or boolean:
                found.setdefault(item, {})[target] = True
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
