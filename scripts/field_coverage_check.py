#!/usr/bin/env python3
"""Check parser provenance using Vector, excluding raw_data as coverage evidence.

Usage: field_coverage_check.py PARSER [SAMPLES] [--output-dir DIR]
       field_coverage_check.py --all
SAMPLES is a sidecar directory or file; by default check inline AND sidecar samples.
Transformed values require a justified field-coverage.yaml rule and actual output.

Parsers never mask, redact or withhold anything: every source field must be
mapped or spilled unaltered, and no check here makes an exception for a key
that looks like a credential. Masking is an opt-in pipeline step.

field-coverage.yaml has exactly two opt-in lists, both validated by
validate_config() and both requiring a one-line `reason` per entry:
- `transforms`: per-field value transforms (residual_spill.KINDS); a rule
  consumes a source field only when its transformed value is in the emitted
  event (never in unmapped, raw_data or a raw-body message).
- `source_normalize`: envelope steps (NORMALIZE_KINDS) a JSON parser applies to
  its input before capturing `__source_kv`. Every step is lossless: the capture
  must EQUAL the input after exactly those steps, no step overwrites a key (it
  is skipped instead), and each step is probed with an unknown field injected
  inside the payload it unwraps.
"""
import argparse
import base64
import binascii
import copy
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import tempfile
import yaml
from residual_spill import ROOT, check_rule, mappings_of, norm_path, update
import provenance
from provenance import MISSING, VECTOR_ENV, at, leaf_index, same, transform_want

# source_normalize step kinds and their required parameters (and types).
NORMALIZE_KINDS = {
    'unwrap_single': {'path': str},
    'base64_json_merge': {'path': str},
    'parse_json_object': {'paths': list, 'target': str},
    'parse_kv_merge': {'path': str, 'match': str, 'key_value_delimiter': str, 'field_delimiter': str},
}
# Optional source_normalize parameters (and types).
NORMALIZE_OPTIONAL = {'parse_json_object': {'arrays': bool}, 'parse_kv_merge': {'tail_keys': list}}
NORMALIZE_UNKNOWN = 'nan2421-normalize-unknown'
# The value text and JSON probes give credential-named keys; it must survive unaltered.
PROBE_SECRET = 'nan2421-secret'
NORMALIZE_PROBE = {'NormalizeProbe': NORMALIZE_UNKNOWN}


def flatten(value, prefix=''):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from flatten(item, prefix + '.' + key if prefix else key)
    else:
        yield prefix, value


def values(value):
    if isinstance(value, dict):
        for item in value.values():
            yield item
            yield from values(item)
    elif isinstance(value, list):
        for item in value:
            yield item
            yield from values(item)


def snake(key):
    # Mirror VRL snakecase boundaries, including Unicode letters, while keeping
    # punctuation such as @ and / which are legitimate source key characters.
    out = []
    for i, char in enumerate(key):
        prev = key[i-1] if i else ''
        following = key[i+1] if i+1 < len(key) else ''
        if char in '_-' or char.isspace():
            if out and out[-1] != '_': out.append('_')
            continue
        boundary = ((prev.islower() and char.isupper()) or
                    (prev.isupper() and char.isupper() and following.islower()) or
                    (prev.isalpha() and char.isdigit()) or
                    (prev.isdigit() and char.isalpha()))
        if boundary and out and out[-1] != '_': out.append('_')
        out.append(char.lower())
    return ''.join(out).strip('_')


def mapped_view(output, raw):
    """The event as coverage evidence: never raw_data, unmapped, or a message
    that is just the raw body (spill.vrl's __mapped)."""
    return {k: v for k, v in output.items() if k not in ('unmapped', 'raw_data') and not (k == 'message' and v == raw)}


def local_to_utc(ms, setting):
    """A clock read as UTC (ms) moved to real UTC by a log source timezone
    setting, as local_clock.vrl does: a fixed +HH:MM offset by arithmetic; an
    IANA zone with fold=0 (an ambiguous time's first occurrence, a gap time
    moved forward); anything else (absent, "local", unknown) unchanged."""
    import datetime as dt
    import zoneinfo
    setting = (setting or '').strip() if isinstance(setting, str) else ''
    m = re.fullmatch(r'([+-])(\d{2}):?(\d{2})', setting)
    if m:
        h, mi = int(m.group(2)), int(m.group(3))
        if h > 14 or mi > 59:
            return ms
        return ms - (1 if m.group(1) == '+' else -1) * (h * 3600 + mi * 60) * 1000
    if not setting or setting.lower() == 'local':
        return ms
    try:
        zone = zoneinfo.ZoneInfo(setting)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return ms
    naive = dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).replace(tzinfo=None)
    return int(naive.replace(tzinfo=zone, fold=0).timestamp() * 1000)


def transformed(rule, value, index, setting=None):
    """A rule consumes its source only when the converted value is AT its
    target. An epoch_ms clock may have been moved to real UTC by the log
    source's timezone setting (the parser read it without an offset)."""
    want = transform_want(rule, value)
    if want is MISSING:
        return False
    target = norm_path(rule['target'])
    if at(index, target, want):
        return True
    return rule['kind'] == 'epoch_ms' and setting is not None and at(index, target, local_to_utc(want, setting))


def check(source, output, raw, rules, consumed=(), mappings=None, setting=None):
    """Every source field is consumed by an explicit mapping (its value at one of
    its declared target paths), a transforms rule (its converted value at the
    rule's target) or a reference check, or it is in unmapped unaltered. A value
    that merely appears elsewhere in the event never counts."""
    assert '__coverage_source' not in output
    residual = output.get('unmapped', {})
    assert isinstance(residual, dict), 'unmapped must be an object'
    assert 'unmapped' not in output or residual, 'empty unmapped'
    index = leaf_index(mapped_view(output, raw))
    mappings = mappings or {}
    # Escaped keys: a literal dotted key ("a~1b") and the nested path ("a.b")
    # are different fields, mapped and spilled independently.
    fields = list(provenance.esc_flatten(source))
    used = set()
    for key, value in fields:
        if key in consumed or any(at(index, target, value) for target in mappings.get(key, ())) or any(r['source'] == key and transformed(r, value, index, setting) for r in rules):
            continue
        if value == raw: continue
        base = '.'.join(snake(provenance.unesc(part)) for part in key.split('.'))
        # A name nano owns in unmapped is spilled as source_<name> (no forged marker).
        if base in RESERVED or base.startswith('nano.'):
            base = 'source_' + base
        bases = [base]
        if '~1' in key:
            # NAN-5894: a literal dotted key whose name another key also gets
            # keeps its dots escaped ("a~1b"), as nano's ingest step names it.
            escaped = '.'.join('~1'.join(provenance.esc(snake(provenance.unesc(piece))) for piece in part.split('~1')) for part in key.split('.'))
            bases.append('source_' + escaped if escaped.startswith(('nano~1', 'nano.')) else escaped)
        matched = False
        for slot, actual in residual.items():
            if slot in used or not any(slot == b or re.fullmatch(re.escape(b)+r'_\d+', slot) for b in bases): continue
            if isinstance(value, (list, dict)) and isinstance(actual, str):
                try: actual = json.loads(actual)
                except json.JSONDecodeError: continue
            if type(actual) is type(value) and actual == value:
                used.add(slot)
                matched = True
                break
        assert matched, f'{key}: missing or altered residual (source value not printed)'
    return len(fields)


def reference_consumed(source, output):
    consumed = []
    from sysmon_coverage_check import mappings, get, milliseconds
    for key, (target, want) in mappings(source).items():
        assert get(output, target) == want, f'{key}: incorrect Sysmon destination {target}'
        consumed.append('event_data.' + key)
    # The reference also accepts UTC EventData clocks when a
    # top-level timestamp is malformed, and UTC file clocks.
    for key, target in [('UtcTime', 'time'), ('CreationUtcTime', 'file.created_time')]:
        try:
            if get(output, target) == milliseconds(source.get('event_data', {}).get(key)):
                consumed.append('event_data.' + key)
        except (ValueError, TypeError, AttributeError):
            pass
    record = source.get('record_id')
    uid = output.get('metadata', {}).get('original_event_uid', '')
    if record is not None and uid.startswith('windows_sysmon|') and uid.split('|')[-2] == str(record):
        consumed.append('record_id')
    return consumed


def _get(obj, path):
    for part in path.split('.'):
        if not isinstance(obj, dict) or part not in obj:
            return MISSING
        obj = obj[part]
    return obj


def _locate(obj, path):
    """(value, holder, leaf) at `path` in a raw input, stepping into a
    one-element array the way unwrap_single would; value is MISSING if absent."""
    holder, leaf = None, None
    for part in path.split('.'):
        if isinstance(obj, list) and len(obj) == 1:
            obj = obj[0]
        if not isinstance(obj, dict) or part not in obj:
            return MISSING, None, None
        holder, leaf, obj = obj, part, obj[part]
    return obj, holder, leaf


def check_step(step):
    """One `source_normalize` step: a known kind, its parameters, a reason."""
    assert isinstance(step, dict) and step.get('kind') in NORMALIZE_KINDS, f'unknown source_normalize step {step!r}'
    kind, params = step['kind'], NORMALIZE_KINDS[step['kind']]
    assert isinstance(step.get('reason'), str) and step['reason'].strip(), f'source_normalize {kind} needs a reason'
    optional = NORMALIZE_OPTIONAL.get(kind, {})
    extra = set(step) - set(params) - set(optional) - {'kind', 'reason'}
    assert not extra, f'source_normalize {kind}: unknown parameters {sorted(extra)}'
    for name, typ in params.items():
        assert isinstance(step.get(name), typ) and step[name], f'source_normalize {kind} needs a non-empty {name}'
    for name, typ in optional.items():
        assert name not in step or isinstance(step[name], typ), f'source_normalize {kind}: {name} must be {typ.__name__}'
    if kind == 'parse_json_object':
        assert all(isinstance(p, str) and p for p in step['paths']), 'parse_json_object paths are dotted strings'
        assert '.' not in step['target'], 'parse_json_object target is a top-level key'
        assert step['target'] not in step['paths'], 'parse_json_object target is not one of its paths'
    if kind == 'parse_kv_merge':
        assert '.' not in step['path'], 'parse_kv_merge unpacks a top-level key'
        assert 'tail_keys' not in step or (step['tail_keys'] and all(isinstance(k, str) and re.fullmatch(r'\w+', k) for k in step['tail_keys'])), 'parse_kv_merge tail_keys are plain key names'
    if 'match' in params:
        try:
            re.compile(step['match'])
        except re.error as error:
            raise AssertionError(f'source_normalize {kind}: bad match regex: {error}') from error


def validate_config(config):
    """The two opt-in lists of a field-coverage.yaml, validated."""
    assert isinstance(config, dict), 'field-coverage.yaml must be a mapping'
    assert 'json_envelope' not in config, 'json_envelope is replaced by a source_normalize parse_kv_merge step'
    rules = config.get('transforms') or []
    assert isinstance(rules, list), 'transforms must be a list'
    for rule in rules:
        check_rule(rule)
    steps = config.get('source_normalize') or []
    assert isinstance(steps, list), 'source_normalize must be a list'
    for step in steps:
        check_step(step)
    return rules, steps


KV_PROGRAM = '''r, err = parse_key_value(string!(.s), key_value_delimiter: string!(.k), field_delimiter: string!(.f), whitespace: "strict")
# The result goes back JSON-encoded: a parsed key may hold any character.
. = {"ok": err == null && is_object(r), "r": encode_json(r)}
'''
_KV_CACHE = {}


def vrl_parse_kv(items):
    """Parse (text, key_value_delimiter, field_delimiter) items with VRL's own
    parse_key_value (whitespace strict), so the checker's expectation is exactly
    what the parser can get. None for a parse error. Results are cached."""
    todo = [item for item in dict.fromkeys(items) if item not in _KV_CACHE]
    if todo:
        with tempfile.TemporaryDirectory(prefix='field-coverage-kv-') as tmp:
            tmp = Path(tmp)
            (tmp/'kv.vrl').write_text(KV_PROGRAM)
            (tmp/'kv.json').write_text(''.join(json.dumps({'s': s, 'k': k, 'f': f})+'\n' for s, k, f in todo))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'kv.vrl'), '--input', str(tmp/'kv.json'), '--print-object'], text=True, capture_output=True, timeout=180, env=VECTOR_ENV)
        assert run.returncode == 0, run.stderr
        outputs = [json.loads(line, strict=False) for line in run.stdout.splitlines() if line.startswith('{')]
        assert len(outputs) == len(todo), f'Vector returned {len(outputs)} KV parses for {len(todo)} inputs'
        for item, out in zip(todo, outputs):
            _KV_CACHE[item] = json.loads(out['r']) if out.get('ok') else None
    return [_KV_CACHE[item] for item in items]


def vrl_kv(text, step):
    return vrl_parse_kv([(text, step['key_value_delimiter'], step['field_delimiter'])])[0]


def _unquote(value):
    if value.startswith('"'):
        try:
            unquoted = json.loads(value)
        except ValueError:
            unquoted = None
        if isinstance(unquoted, str):
            return unquoted
    return value


def _kv_parts(text, step):
    """(text to parse, {tail key: value}) for a parse_kv_merge step.

    `tail_keys` are keys a line ends with, in order, whose values may hold the
    field delimiter (Keycloak: representation JSON, requestUri, cookies=[...],
    stackTrace). From the last to the first, each is cut off the end at its
    `<fd><key><kvd>` marker: the LAST occurrence for every key but the first,
    the FIRST occurrence for the first key (its JSON may hold anything). Each
    takes its text verbatim (a JSON string literal unquoted), never split.
    """
    tails = {}
    keys = step.get('tail_keys') or []
    for index in range(len(keys) - 1, -1, -1):
        marker = step['field_delimiter'] + keys[index] + step['key_value_delimiter']
        at = text.find(marker) if index == 0 else text.rfind(marker)
        if at > 0:
            text, tails[keys[index]] = text[:at], _unquote(text[at + len(marker):])
    return text, tails


def _kv_text(source, step):
    value = source.get(step['path'], MISSING) if isinstance(source, dict) else MISSING
    return value if isinstance(value, str) and re.search(step['match'], value) else None


def normalized_source(original, rules, parse_kv=vrl_kv):
    """The source a parser is expected to capture for a JSON input.

    By default that is the parsed input itself. A parser that unwraps a known
    envelope declares each step in `source_normalize` (field-coverage.yaml), and
    its `__source_kv` must equal the input after exactly these steps. Every step
    is lossless and no step overwrites a key: on a collision the step is skipped
    and the input kept as it was, so a colliding field can never vanish.

    - unwrap_single {path}: a one-element array of an object becomes the object
      (a CloudWatch Logs envelope carrying one logEvent).
    - base64_json_merge {path}: a base64 string that decodes to a JSON object is
      removed and the decoded object merged with the remaining keys (a Pub/Sub
      push wrapper's `message.data`); skipped if any top-level key collides.
    - parse_json_object {paths, target, arrays?}: the first path holding a
      string that parses to a JSON object (or array, with arrays: true) is
      moved, parsed, to the top-level `target` (a JSON log message passed
      through for spill; the JSON text itself is removed like the other
      envelope steps, and raw_data keeps it); skipped if `target` exists.
    - parse_kv_merge {path, match, key_value_delimiter, field_delimiter}: a
      top-level string matching `match` that VRL parse_key_value (whitespace
      strict) parses to a non-empty object is removed and its pairs merged in;
      with `tail_keys`, the keys a line ends with are cut off first and keep
      their text verbatim (_kv_parts), never split on the field delimiter
      (Keycloak's JSON log `message`); skipped on a parse error, an empty
      result, or a key colliding with the remaining keys.
    """
    source = copy.deepcopy(original)
    for rule in rules or ():
        kind = rule['kind']
        if kind == 'unwrap_single':
            parent, _, leaf = rule['path'].rpartition('.')
            holder = _get(source, parent) if parent else source
            value = holder.get(leaf, MISSING) if isinstance(holder, dict) else MISSING
            if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                holder[leaf] = value[0]
        elif kind == 'base64_json_merge':
            rest = copy.deepcopy(source)
            parent, _, leaf = rule['path'].rpartition('.')
            holder = _get(rest, parent) if parent else rest
            value = holder.get(leaf, MISSING) if isinstance(holder, dict) else MISSING
            if not isinstance(value, str) or not value:
                continue
            try:
                decoded = json.loads(base64.b64decode(value, validate=True).decode('utf-8'))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if isinstance(decoded, dict) and not decoded.keys() & rest.keys():
                del holder[leaf]
                source = {**decoded, **rest}
        elif kind == 'parse_json_object':
            for path in rule['paths']:
                value = _get(source, path)
                if isinstance(value, str):
                    try:
                        # VRL parse_json skips a leading UTF-8 byte order mark.
                        parsed = json.loads(value.removeprefix('\ufeff'))
                    except ValueError:
                        break
                    if (isinstance(parsed, dict) or (rule.get('arrays') and isinstance(parsed, list))) and rule['target'] not in source:
                        parent, _, leaf = path.rpartition('.')
                        del (_get(source, parent) if parent else source)[leaf]
                        source[rule['target']] = parsed
                    break
        elif kind == 'parse_kv_merge':
            text = _kv_text(source, rule)
            if text is None:
                continue
            text, tails = _kv_parts(text, rule)
            pairs = parse_kv(text, rule)
            rest = {k: v for k, v in source.items() if k != rule['path']}
            if isinstance(pairs, dict) and pairs and tails:
                pairs = None if pairs.keys() & tails.keys() else {**pairs, **tails}
            if isinstance(pairs, dict) and pairs and not pairs.keys() & rest.keys():
                source = {**rest, **pairs}
        else:
            raise AssertionError(f'unknown source_normalize kind {kind}')
    return source


def json_object(text):
    try: obj = json.loads(text)
    except json.JSONDecodeError: return None
    return obj if isinstance(obj, dict) and obj else None


def inject_probe(original, step):
    """A copy of `original` with NORMALIZE_PROBE planted INSIDE the payload that
    `step` unwraps, or None when this input has no such payload."""
    probe = copy.deepcopy(original)
    kind = step['kind']
    if kind == 'parse_kv_merge':
        if _kv_text(probe, step) is None:
            return None
        kd, fd = step['key_value_delimiter'], step['field_delimiter']
        pairs = ''.join(f'{fd}{k}{kd}"{v}"' for k, v in NORMALIZE_PROBE.items())
        text = probe[step['path']]
        head, _tails = _kv_parts(text, step)
        # Before the tail keys, which take the rest of the line verbatim.
        probe[step['path']] = head + pairs + text[len(head):]
        return probe
    for path in step['paths'] if kind == 'parse_json_object' else [step['path']]:
        value, holder, leaf = _locate(probe, path)
        if kind == 'unwrap_single':
            if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
                value[0].update(copy.deepcopy(NORMALIZE_PROBE))
                return probe
        elif kind == 'base64_json_merge':
            try:
                decoded = json.loads(base64.b64decode(value, validate=True).decode('utf-8'))
            except (TypeError, binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if isinstance(decoded, dict):
                decoded.update(copy.deepcopy(NORMALIZE_PROBE))
                holder[leaf] = base64.b64encode(json.dumps(decoded).encode()).decode()
                return probe
        elif kind == 'parse_json_object':
            if not isinstance(value, str):
                continue
            parsed = json_object(value)
            if parsed is not None:
                parsed.update(copy.deepcopy(NORMALIZE_PROBE))
                holder[leaf] = json.dumps(parsed)
                return probe
            break
    return None


def applied(probe, step, steps, parse_kv=vrl_kv):
    """Whether `step` (the last of `steps`) ITSELF acts on the probe planted for
    it: run the steps before it, then it alone. It must change the source and
    surface the unknown field. A step an earlier one already made a no-op is
    never counted as exercised."""
    before = normalized_source(probe, steps[:-1], parse_kv)
    after = normalized_source(before, [step], parse_kv)
    return after != before and NORMALIZE_UNKNOWN in [v for _, v in flatten(after)]


def normalize_probes(samples, steps, parse_kv=vrl_kv):
    """One probe per declared step: a real sample with an unknown field
    injected inside the payload the step unwraps. A declared step that no
    sample exercises fails, so an opt-in can never go untested."""
    probes = []
    for index, step in enumerate(steps):
        for _name, event in samples:
            original = json_object(event['message'])
            probe = original and inject_probe(original, step)
            if probe and applied(probe, step, steps[:index + 1], parse_kv):
                probes.append((f'normalize_probe_{index}', {'message': json.dumps(probe)}))
                break
        else:
            raise AssertionError(f'source_normalize step {index} ({step["kind"]}) is exercised by no sample')
    return probes


def envelope(raw):
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and isinstance(obj.get('message'), str): return obj
    except json.JSONDecodeError:
        pass
    return {'message': raw}


def samples_for(path, doc, supplied):
    found = []
    if supplied is None:
        for index, sample in enumerate(doc.get('samples', [])):
            raw = sample['raw']
            found.append((f'inline_{index:03}', {'message': raw if isinstance(raw, str) else json.dumps(raw)}))
        paths = sorted(path.parent.glob('samples/*.json'))
    else:
        paths = sorted(supplied.glob('*.json')) if supplied.is_dir() else [supplied]
    for sample in paths:
        found.append((sample.stem, envelope(sample.read_text().strip())))
    return found


def run_parser(path, supplied=None, output_dir=None):
    config_path = path.with_name('field-coverage.yaml')
    assert config_path.exists(), f'{path.parent.name}: missing field-coverage.yaml'
    config = yaml.safe_load(config_path.read_text())
    update(path, check=True)
    vrl = yaml.safe_load(path.read_text())['parser_vrl']
    naive = naive_timestamps(vrl)
    assert not naive, f'{path.parent.name}: parse_timestamp without timezone: "UTC" reads a clock in the host timezone: {naive[:3]}'
    local = unconverted_clocks(vrl)
    assert not local, f'{path.parent.name}: an offset-less clock read as UTC without the local-clock contract (add `# NAN local clock: <var>`, or `# utc-by-spec: <reason>` when the format is UTC by specification): {local[:3]}'
    rules, steps = validate_config(config)
    mappings = mappings_of(config)
    doc = yaml.safe_load(path.read_text())
    samples = samples_for(path, doc, supplied)
    assert samples, f'{path}: no samples'
    assert not steps or config['source'] in ('json', 'mixed'), 'source_normalize needs a JSON source'
    real_samples = list(samples)
    # Probe unseen keys, nested values, scalar/object arrays, credential-named
    # keys (which spill as-is, like any other) and snake-case collisions on
    # real JSON branch input.
    if config['source'] in ('json', 'mixed'):
        for _name, event in samples:
            try: obj = json.loads(event['message'])
            except json.JSONDecodeError: continue
            if not isinstance(obj, dict): continue
            obj = copy.deepcopy(obj)
            obj['ResidualProbe'] = {'UnknownLeaf': 'nan2421-unknown-5d38', 'Scalars': ['nan2421-a', 987654321, False], 'Objects': [{'Field': 'nan2421-b', 'apiToken': 'nan2421-secret'}, {'name': 'Authorization', 'value': 'nan2421-secret'}], 'Password': 'nan2421-secret', 'Deep': {'clientSecret': 'nan2421-secret'}}
            obj['Dotted.Probe'] = 'nan2421-dotted'
            obj['Dotted'] = {'Probe': 'nan2421-nested'}
            obj['UnknownZero'] = 0
            obj['UnknownFalse'] = False
            obj['CollisionProbe'] = 'nan2421-first'
            obj['collision_probe'] = 'nan2421-second'
            samples.append(('residual_probe', {'message': json.dumps(obj)}))
            break
    probe = config.get('probe')
    if probe:
        raw = probe.get('raw')
        if raw is None:
            candidates = [event['message'] for _, event in samples if probe.get('require', '') in event['message']]
            assert candidates, 'no sample fits configured text probe'
            raw = candidates[0]
            if probe['mode'] == 'before':
                before, anchor, after = raw.rpartition(probe['anchor'])
                assert anchor, 'text probe anchor absent'
                raw = before + probe['text'] + anchor + after
            else:
                raw += probe['text']
        samples.append(('text_residual_probe', {'message': raw}))
    samples += normalize_probes(real_samples, steps)
    # One VRL call parses every KV payload the steps below will look at.
    vrl_parse_kv([(_kv_parts(text, s)[0], s['key_value_delimiter'], s['field_delimiter'])
                  for _, event in samples for s in steps if s['kind'] == 'parse_kv_merge'
                  for text in [_kv_text(json_object(event['message']) or {}, s)] if text is not None])
    program = doc['parser_vrl'] + '\n.__coverage_source = __source_kv\n'
    with tempfile.TemporaryDirectory(prefix='field-coverage-') as tmp:
        tmp = Path(tmp)
        (tmp/'parser.vrl').write_text(program)
        (tmp/'input.json').write_text(''.join(json.dumps(event)+'\n' for _, event in samples))
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'parser.vrl'), '--input', str(tmp/'input.json'), '--print-object'], text=True, capture_output=True, timeout=180, env=VECTOR_ENV)
        assert run.returncode == 0, run.stderr
        outputs = []
        for line in run.stdout.splitlines():
            if not line.startswith('{'): continue
            outputs.append(json.loads(line, strict=False))
        assert len(outputs) == len(samples), f'Vector returned {len(outputs)} events for {len(samples)} samples: {run.stdout[:500]}'
        count = 0
        spill_keys = set()
        outputs_sources = []
        for (name, event), output in zip(samples, outputs):
            source = output.pop('__coverage_source')
            outputs_sources.append((name, event, output, source))
            if config['source'] in ('json', 'mixed'):
                try: original = json.loads(event['message'])
                except json.JSONDecodeError: original = {}
                if not isinstance(original, dict): original = {}
                if isinstance(original, dict) and original:
                    assert source == normalized_source(original, steps), f'{name}: JSON source capture changed fields'
            try:
                consumed = []
                if config.get('reference') == 'windows_sysmon':
                    consumed = reference_consumed(source, output)
                nano = event.get('nano')
                setting = nano.get('source_timezone') if isinstance(nano, dict) else None
                count += check(source, output, event['message'], rules, consumed, mappings, setting)
            except AssertionError as error:
                raise AssertionError(f'{path.parent.name}/{name}: {error}') from error
            # raw_data, when emitted, is the untouched original (never masked,
            # trimmed or rewritten).
            assert 'raw_data' not in output or output['raw_data'] == event['message'], f'{path.parent.name}/{name}: raw_data is not the original input'
            if name == 'text_residual_probe':
                leaves = [v for _, v in flatten(source)]
                assert dict(flatten(source)).get(probe['source']) == 'nan2421-text-unknown', 'text probe missing from parsed source'
                # A credential-named probe field (password=...) is captured
                # unaltered like any other; check() then requires it mapped or
                # spilled with that exact value.
                if PROBE_SECRET in event['message']:
                    assert PROBE_SECRET in leaves, 'text probe credential value missing or altered in parsed source'
            if name.startswith('normalize_probe_'):
                assert NORMALIZE_UNKNOWN in [v for _, v in flatten(source)], f'{name}: unwrapped probe field missing from parsed source'
            if name not in ('residual_probe', 'text_residual_probe') and not name.startswith('normalize_probe_'):
                spill_keys.update(output.get('unmapped', {}))
            if output_dir:
                dest = output_dir/path.parent.name
                dest.mkdir(parents=True, exist_ok=True)
                (dest/(name+'.json')).write_text(json.dumps(output, indent=2)+'\n')
                source_dir = dest/'sources'
                source_dir.mkdir(exist_ok=True)
                (source_dir/(name+'.json')).write_text(json.dumps(source, indent=2)+'\n')
        assert count > 0, f'{path.parent.name}: no parsed source fields were assessed'
        verify_provenance(path, doc['parser_vrl'], samples, outputs_sources, mappings, rules)
        print(f'PASS {path.parent.name}: {len(samples)} samples, {count} source fields; spilled: {", ".join(sorted(spill_keys))}')


TIMESTAMP_CALL = re.compile(r'parse_timestamp!?\(')


def strip_comments(vrl):
    """VRL with every # comment removed (a '#' inside a string is kept)."""
    out, i, n = [], 0, len(vrl)
    while i < n:
        c = vrl[i]
        if c == '"':
            j = i + 1
            while j < n and vrl[j] != '"':
                j += 2 if vrl[j] == '\\' else 1
            out.append(vrl[i:j + 1]); i = j + 1
        elif c == "'" and i and vrl[i - 1] == 'r':
            j = vrl.find("'", i + 1)
            j = n if j < 0 else j
            out.append(vrl[i:j + 1]); i = j + 1
        elif c == '#':
            j = vrl.find('\n', i)
            i = n if j < 0 else j
        else:
            out.append(c); i += 1
    return ''.join(out)


def split_args(args):
    """Top-level comma-separated arguments of a call (strings and nesting kept)."""
    parts, depth, cur, i = [], 0, [], 0
    while i < len(args):
        c = args[i]
        if c == '"':
            j = i + 1
            while j < len(args) and args[j] != '"':
                j += 2 if args[j] == '\\' else 1
            cur.append(args[i:j + 1]); i = j + 1; continue
        if c == "'" and i and args[i - 1] == 'r':
            j = args.find("'", i + 1); j = len(args) if j < 0 else j
            cur.append(args[i:j + 1]); i = j + 1; continue
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(''.join(cur)); cur = []; i += 1; continue
        cur.append(c); i += 1
    parts.append(''.join(cur))
    return parts


def call_args(text, start):
    """The argument text of the call whose "(" ends at start, and the index
    after its closing ")": balanced parentheses, quoted and raw strings skipped,
    across lines."""
    i, depth = start, 1
    while i < len(text) and depth:
        c = text[i]
        if c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
        elif c == "'" and text[i - 1] == 'r':
            i += 1
            while i < len(text) and text[i] != "'":
                i += 1
        elif c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        i += 1
    return text[start:i - 1], i


def named_args(parts):
    return {p.split(':', 1)[0].strip(): p.split(':', 1)[1].strip() for p in parts if re.match(r'\s*\w+\s*:', p)}


def naive_timestamps(vrl):
    """parse_timestamp(...) calls (comments ignored) without a named timezone:
    argument. Without one VRL reads an offset-less clock in the HOST timezone,
    so the same line gets a different time on every Vector host. The argument
    may be a literal or a variable (a source's own timezone field)."""
    text = strip_comments(vrl)
    bad = []
    for m in TIMESTAMP_CALL.finditer(text):
        args, i = call_args(text, m.end())
        parts = split_args(args)
        fmt = parts[1].strip() if len(parts) > 1 else ''
        named = named_args(parts[2:])
        # "local" is the Vector host's zone: the host-dependence the rule exists to stop.
        if named.get('timezone', '').strip('"').lower() == 'local':
            bad.append(text[m.start():i][:80])
            continue
        # A FORMAT (the second argument) that carries an offset needs no timezone.
        if 'timezone' not in named and not re.fullmatch(r'"[^"]*(?:%\+|%:?z)[^"]*"', fmt):
            bad.append(text[m.start():i][:80])
    return bad


# Names nano owns in unmapped: parser markers and the nano.* namespace.
RESERVED = {'nano', 'nano_time_assumed_tz', 'nano_time_source', 'nano_operational'}

GENERATED = [(r'# NAN source timezone\.', r'# END NAN source timezone'), (r'# NAN-2421 residual spill\.', r'# END NAN-2421 residual spill')]


# A format that carries its own zone: an offset (%z, %:z, %::z, %#z), RFC 3339
# (%+), epoch seconds (%s), or a literal Z closing it.
ZONED_FORMAT = re.compile(r'"(?:[^"]*(?:%\+|%:{0,2}z|%#z|%s)[^"]*|[^"]*(?<!%)Z)"')
UTC_BY_SPEC = re.compile(r'#\s*utc-by-spec:\s*\S')
NO_STRINGS = re.compile(r'"(?:\\.|[^"\\])*"|r\'[^\']*\'')


def unconverted_clocks(vrl):
    """Offset-less clocks that skip the local-clock contract.

    A parse_timestamp(...) with a fixed timezone literal ("UTC", "Etc/UTC",
    "+00:00", ...) whose format carries no zone reads a LOCAL clock in that
    zone, ignoring the log source's timezone setting. Unless the line (or the
    one before) carries `# utc-by-spec: <reason>`, the call must assign its
    result to a variable, and on the same branch before that variable is used,
    reassigned (other than by a retry parse) or its branch left, the parser must
    set `__lc_pending = true` and place `# NAN local clock: <var>`. Generated
    blocks are ignored. A variable timezone (the source's own field, the
    prelude's __src_tz) is the source's zone and passes.
    """
    keep, skip = [], False
    for line in vrl.split('\n'):
        s = line.strip()
        if any(re.match(a, s) for a, _ in GENERATED):
            skip = True
        if not skip:
            keep.append(line)
        if any(re.match(b, s) for _, b in GENERATED):
            skip = False
    raw = '\n'.join(keep)
    # The expanded local-clock bodies are generated too: keep only the markers.
    raw = re.sub(r'(# NAN local clock: [^\n]*\n).*?# END NAN local clock\n', r'\1', raw, flags=re.S)
    lines = raw.split('\n')
    code_lines = [strip_comments(l) for l in lines]
    code = '\n'.join(code_lines)
    starts = [0]
    for l in code_lines:
        starts.append(starts[-1] + len(l) + 1)
    line_of = lambda off: max(k for k, st in enumerate(starts) if st <= off)
    bad = []
    for m in TIMESTAMP_CALL.finditer(code):
        args, end = call_args(code, m.end())
        parts = split_args(args)
        named = named_args(parts[2:])
        tz = named.get('timezone', '')
        if not tz.startswith('"'):
            continue  # no timezone (naive_timestamps) or a variable one
        fmt = parts[1].strip() if len(parts) > 1 else ''
        if ZONED_FORMAT.fullmatch(fmt):
            continue
        li = line_of(m.start())
        if UTC_BY_SPEC.search(lines[li]) or (li and UTC_BY_SPEC.search(lines[li - 1])):
            continue
        call = ' '.join(code[m.start():end].split())[:90]
        prefix = code[starts[li]:m.start()]
        var = re.search(r'(?:^|[{;]|\bthen\b)\s*(\w+)\s*(?:,\s*\w+)?\s*=\s*$', prefix)
        if not var:
            bad.append(call + ' (result not assigned to a variable)')
            continue
        v = re.escape(var.group(1))
        retry = re.compile(r'\b' + v + r'\s*(?:,\s*\w+)?\s*=\s*parse_timestamp\b')
        # Walk forward: brace depth relative to the call; the base is the
        # shallower of the call and the end of its line (a one-line retry block).
        end_line = line_of(end - 1)
        rest = [code[end:starts[end_line + 1] - 1]] + code_lines[end_line + 1:]
        depth, base, pending, why = 0, None, False, 'no `# NAN local clock: ' + var.group(1) + '` marker follows'
        for k, chunk in enumerate(rest):
            j = end_line + k
            if k and re.match(r'\s*# NAN local clock: ' + v + r'\b', lines[j]):
                why = None if pending else 'marker without `__lc_pending = true` before it'
                break
            flat = NO_STRINGS.sub('""', chunk)
            if re.search(r'__lc_pending\s*=\s*true', flat):
                pending = True
            if re.search(r'\b' + v + r'\b', flat) and not retry.search(flat):
                why = f'{var.group(1)} is used before its local-clock marker'
                break
            if re.search(r'(?<![\w.])' + v + r'\s*(?:,\s*\w+)?\s*=(?!=)', flat) and not retry.search(flat):
                why = f'{var.group(1)} is reassigned before its local-clock marker'
                break
            left = False
            for tok in re.findall(r'[{}]|\belse\b', flat):
                if tok == '{':
                    depth += 1
                elif tok == '}':
                    depth -= 1
                elif base is not None and depth < base:
                    left = True
            if k == 0:
                base = min(0, depth)
            if left:
                why = 'the branch ends before its local-clock marker'
                break
        if why:
            bad.append(f'{call} ({why})')
    return bad


PROBES = ('residual_probe', 'text_residual_probe')


def verify_provenance(path, program, samples, outputs_sources, mappings, rules):
    """Every declared mapping and every transforms rule must be demonstrated: in
    some sample, perturbing the source value moves the value at the declared
    target with it. A declaration that only ever matches by coincidence (or
    that no sample exercises) fails."""
    real = [(n, e, o, s) for n, e, o, s in outputs_sources if n not in PROBES and not n.startswith('normalize_probe_')]
    samples = [(n, e) for n, e, _, _ in real]
    sources = [s for _, _, _, s in real]
    outputs = [o for _, _, o, _ in real]
    items = [(key, None) for key in mappings] + [(rule['source'], rule) for rule in rules]
    declared = {(key, None): targets for key, targets in mappings.items()}
    declared.update({(rule['source'], id(rule)): [norm_path(rule['target'])] for rule in rules})
    found = provenance.probe(program, samples, sources, outputs, items, per_key=40, declared=declared, scope=path.parent.name)
    missing = []
    for key, targets in mappings.items():
        for target in targets:
            if target not in found.get((key, None), {}):
                missing.append(f'{key} -> {target}')
    for rule in rules:
        if norm_path(rule['target']) not in found.get((rule['source'], id(rule)), {}):
            missing.append(f'{rule["source"]} ({rule["kind"]}) -> {rule["target"]}')
    assert not missing, f'{path.parent.name}: declared mapping(s) without provenance in any sample (perturbing the source does not move the target; PROVENANCE_SEED={provenance.BASE_SEED}): ' + ', '.join(missing[:12]) + (' ...' if len(missing) > 12 else '')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('parser', nargs='?', type=Path)
    ap.add_argument('samples', nargs='?', type=Path)
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--output-dir', type=Path)
    args = ap.parse_args()
    if args.all:
        paths = sorted((ROOT/'parsers-ocsf').glob('*/parser.yaml'))
    elif args.parser:
        paths = [args.parser/'parser.yaml' if args.parser.is_dir() else args.parser]
    else:
        ap.error('provide PARSER or --all')
    failures = []
    for path in paths:
        try: run_parser(path, args.samples, args.output_dir)
        except (AssertionError, subprocess.SubprocessError, ValueError) as error:
            print(f'FAIL {path.parent.name}: {error}')
            failures.append(path.parent.name)
    if failures:
        print('FAILED: '+', '.join(failures))
        raise SystemExit(1)
    print(f'PASS {len(paths)} parsers; no lost source fields')

if __name__ == '__main__':
    main()
