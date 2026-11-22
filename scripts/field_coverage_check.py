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
from residual_spill import ROOT, check_rule, update

MISSING = object()
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


def same(a, b):
    if type(a) in (int, float) and type(b) in (int, float):
        return a == b
    if type(a) is type(b):
        return a == b
    # VRL to_string conversions preserve scalar numeric/boolean values.
    scalar = lambda v: json.dumps(v, separators=(',', ':')) if not isinstance(v, str) else v
    return a is not None and b is not None and not isinstance(a, (dict, list)) and not isinstance(b, (dict, list)) and scalar(a) == scalar(b)


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


def represented(value, mapped):
    if any(same(value, item) for item in mapped): return True
    return isinstance(value, list) and bool(value) and all(
        not isinstance(item, (dict, list)) and any(same(item, output) for output in mapped)
        for item in value)


def mapped_view(output, raw):
    """The event as coverage evidence: never raw_data, unmapped, or a message
    that is just the raw body (spill.vrl's __mapped)."""
    return {k: v for k, v in output.items() if k not in ('unmapped', 'raw_data') and not (k == 'message' and v == raw)}


def transformed(rule, value, output, mapped, raw=MISSING):
    try:
        kind = rule['kind']
        if kind == 'lowercase':
            if not isinstance(value, str): return False
            want = value.lower()
        elif kind == 'epoch_ms':
            clock = dt.datetime.fromisoformat(value.replace('Z', '+00:00')) if rule.get('format', '%+') == '%+' else dt.datetime.strptime(value, rule['format'])
            want = int(clock.timestamp() * 1000)
        elif kind == 'scale':
            want = int(float(value) * rule['factor'])
        elif kind == 'hex':
            if not isinstance(value, str) or not value.lower().startswith('0x'): return False
            want = int(value, 16)
        elif kind == 'enum':
            want = rule['values'].get(str(value).lower(), MISSING)
        else:
            raise AssertionError(f'unknown transform {kind}')
    except (ValueError, TypeError, AttributeError, OverflowError):
        return False
    if 'target' in rule:
        # The target is looked up in the mapped event only, so a rule can never
        # be satisfied by unmapped, raw_data or a message equal to the raw body.
        actual = mapped_view(output, raw)
        for part in rule['target'].split('.'):
            if not isinstance(actual, dict) or part not in actual: return False
            actual = actual[part]
        return want is not MISSING and same(want, actual)
    return any(same(want, item) for item in mapped)


def check(source, output, raw, rules, consumed=(), candidates=None):
    assert '__coverage_source' not in output
    residual = output.get('unmapped', {})
    assert isinstance(residual, dict), 'unmapped must be an object'
    assert 'unmapped' not in output or residual, 'empty unmapped'
    mapped_event = mapped_view(output, raw)
    mapped = list(values(mapped_event))
    fields = list(flatten(source))
    used = set()
    for key, value in fields:
        if key in consumed or ((candidates is None or key in candidates) and represented(value, mapped)) or any(r['source'] == key and transformed(r, value, output, mapped, raw) for r in rules):
            continue
        if value == raw: continue
        base = '.'.join(snake(part) for part in key.split('.'))
        matched = False
        for slot, actual in residual.items():
            if slot in used or not (slot == base or re.fullmatch(re.escape(base)+r'_\d+', slot)): continue
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
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'kv.vrl'), '--input', str(tmp/'kv.json'), '--print-object'], text=True, capture_output=True, timeout=180)
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
    rules, steps = validate_config(config)
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
        run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'parser.vrl'), '--input', str(tmp/'input.json'), '--print-object'], text=True, capture_output=True, timeout=180)
        assert run.returncode == 0, run.stderr
        outputs = []
        for line in run.stdout.splitlines():
            if not line.startswith('{'): continue
            outputs.append(json.loads(line, strict=False))
        assert len(outputs) == len(samples), f'Vector returned {len(outputs)} events for {len(samples)} samples: {run.stdout[:500]}'
        count = 0
        spill_keys = set()
        for (name, event), output in zip(samples, outputs):
            source = output.pop('__coverage_source')
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
                count += check(source, output, event['message'], rules, consumed, config['consumed_candidates'])
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
        print(f'PASS {path.parent.name}: {len(samples)} samples, {count} source fields; spilled: {", ".join(sorted(spill_keys))}')


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
