#!/usr/bin/env python3
"""Check parser provenance using Vector, excluding raw_data as coverage evidence.

Usage: field_coverage_check.py PARSER [SAMPLES] [--output-dir DIR]
       field_coverage_check.py --all
SAMPLES is a sidecar directory or file; by default check inline AND sidecar samples.
Transformed values require a justified field-coverage.yaml rule and actual output.

field-coverage.yaml has exactly two opt-in lists, both validated by
validate_config() and both requiring a one-line `reason` per entry:
- `transforms`: per-field value transforms (residual_spill.KINDS, including the
  bounded `truncate` copy); a rule consumes a source field only when its
  transformed value is in the emitted event.
- `source_normalize`: envelope steps (NORMALIZE_KINDS) a JSON parser applies to
  its input before capturing `__source_kv`. The capture must EQUAL the input
  after exactly those steps, no step overwrites a key (it is skipped instead),
  and each step is probed with an unknown field and a secret injected inside
  the payload it unwraps.
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

# Keys that hold a secret value; mirrors spill.vrl (descriptive credential_* keys are not secrets).
SECRET = re.compile(r'password|secret|authorization|token|(?:^|[^a-z0-9\s]|client)credentials?(?:$|[^a-z0-9_\s])|credential_?(?:data|value|val|blob|hash|key)(?:$|[^a-z0-9_\s])', re.I)
MISSING = object()
# source_normalize step kinds and their required parameters (and types).
NORMALIZE_KINDS = {
    'unwrap_single': {'path': str},
    'base64_json_merge': {'path': str},
    'parse_json_object': {'paths': list, 'target': str},
    'parse_kv_merge': {'path': str, 'match': str, 'key_value_delimiter': str, 'field_delimiter': str},
    'withhold': {'paths': list, 'match': str},
    'allowlist': {'keep': list},
}
# A sample or probe credential: never emitted outside raw_data.
SECRET_MARKER = 'nan2421-secret'
# Optional source_normalize parameters (and types).
NORMALIZE_OPTIONAL = {'parse_json_object': {'arrays': bool, 'keep': list}, 'parse_kv_merge': {'tail_keys': list},
                      'allowlist': {'nested': dict, 'urls': list}}
NORMALIZE_UNKNOWN = 'nan2421-normalize-unknown'
NORMALIZE_PROBE = {'NormalizeProbe': NORMALIZE_UNKNOWN, 'clientSecret': 'nan2421-secret'}


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


def redact(value):
    if isinstance(value, dict):
        sensitive_pair = any(k.lower() in ('name', 'key') and isinstance(v, str) and SECRET.search(v) for k, v in value.items())
        return {k: '<redacted>' if SECRET.search(k) or (sensitive_pair and k.lower() in ('value', 'values')) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


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
        elif kind == 'truncate':
            # A bounded copy: the first `length` characters, in a named target.
            # An over-bound value counts only when the event flags itself
            # metadata.is_truncated AND keeps the raw body as raw_data, its one
            # lossless copy.
            if not isinstance(value, str) or not rule.get('target'): return False
            want = value[:rule['length']]
            if len(value) > rule['length']:
                if (output.get('metadata') or {}).get('is_truncated') is not True: return False
                if raw is MISSING or output.get('raw_data') != raw: return False
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
    safe = list(flatten(redact(source)))
    used = set()
    for key, value in safe:
        original = value
        if value != '<redacted>' and (key in consumed or ((candidates is None or key in candidates) and represented(original, mapped)) or any(r['source'] == key and transformed(r, original, output, mapped, raw) for r in rules)):
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
    return len(safe)


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
        if 'keep' in step:
            assert step['keep'] and all(isinstance(k, str) and k for k in step['keep']), 'parse_json_object keep lists key names'
            assert 'withheld_fields' not in step['keep'], 'parse_json_object keep may not name withheld_fields'
            assert not step.get('arrays'), 'parse_json_object keep moves objects only'
    if kind == 'parse_kv_merge':
        assert '.' not in step['path'], 'parse_kv_merge unpacks a top-level key'
        assert 'tail_keys' not in step or (step['tail_keys'] and all(isinstance(k, str) and re.fullmatch(r'\w+', k) for k in step['tail_keys'])), 'parse_kv_merge tail_keys are plain key names'
    if kind == 'allowlist':
        names = step['keep'] + [k for keys in step.get('nested', {}).values() for k in keys] + list(step.get('nested', {})) + step.get('urls', [])
        assert all(isinstance(k, str) and k for k in names), 'allowlist names are non-empty strings'
        assert all(isinstance(v, list) and v for v in step.get('nested', {}).values()), 'allowlist nested maps a key to its allowed keys'
        assert 'withheld_fields' not in names, 'allowlist may not name withheld_fields'
    if kind == 'withhold':
        assert all(isinstance(p, str) and p and all(p.split('.')) for p in step['paths']), 'withhold paths are dotted strings'
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
    for index, step in enumerate(steps):
        check_step(step)
        # withhold is a fallback for what an unpack step could not unpack, never
        # a way to drop a field outright.
        if step['kind'] == 'withhold':
            # Each withheld path is one an earlier unpack step reads, so withhold
            # only ever catches what that step could not unpack.
            unpacked = {p for s in steps[:index] if s['kind'] != 'withhold' for p in ([s['path']] if 'path' in s else s.get('paths', []))}
            assert unpacked, 'withhold must follow an unpack step'
            stray = [p for p in step['paths'] if p not in unpacked]
            assert not stray, f'withhold paths {stray} are not read by an earlier unpack step'
        # After an allowlist only allowlisted keys exist: a step reading any other
        # key could never act, so it is rejected as dead.
        for earlier in steps[:index]:
            if earlier['kind'] == 'allowlist':
                allowed = set(earlier['keep']) | set(earlier.get('nested', {}))
                reads = [step['path']] if 'path' in step else step.get('paths', [])
                dead = [p for p in reads if p.split('.')[0] not in allowed]
                assert not dead, f'source_normalize {step["kind"]} after an allowlist reads {dead}, which the allowlist removes'
    probe = config.get('probe')
    if probe is not None:
        assert isinstance(probe, dict), 'probe must be a mapping'
        if 'expect_withheld' in probe:
            assert isinstance(probe['expect_withheld'], bool), 'probe expect_withheld must be true or false'
            if probe['expect_withheld']:
                assert any(s['kind'] == 'allowlist' for s in steps), 'probe expect_withheld needs an allowlist step'
                assert isinstance(probe.get('source'), str) and probe['source'] in probe.get('text', ''), 'an expect_withheld probe names a source key its text injects'
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


WITHHOLD_PROGRAM = '''t = if is_string(.v) { string!(.v) } else { encode_json(.v) }
. = {"t": t, "bytes": length(t), "sha256": sha2(t, variant: "SHA-256")}
'''
_WITHHOLD_CACHE = {}


def vrl_withhold(values):
    """For each value, its text (the string itself, else VRL encode_json) and
    that text's UTF-8 byte length and sha256, computed by Vector so the checker
    expects exactly what a parser's sha2/length/encode_json produce. Cached."""
    keys = [json.dumps(v, sort_keys=True) for v in values]
    todo = {k: v for k, v in zip(keys, values) if k not in _WITHHOLD_CACHE}
    if todo:
        with tempfile.TemporaryDirectory(prefix='field-coverage-withhold-') as tmp:
            tmp = Path(tmp)
            (tmp/'w.vrl').write_text(WITHHOLD_PROGRAM)
            (tmp/'w.json').write_text(''.join(json.dumps({'v': v})+'\n' for v in todo.values()))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'w.vrl'), '--input', str(tmp/'w.json'), '--print-object'], text=True, capture_output=True, timeout=180)
        assert run.returncode == 0, run.stderr
        outputs = [json.loads(line, strict=False) for line in run.stdout.splitlines() if line.startswith('{')]
        assert len(outputs) == len(todo), f'Vector returned {len(outputs)} digests for {len(todo)} values'
        for key, out in zip(todo, outputs):
            _WITHHOLD_CACHE[key] = out
    return [_WITHHOLD_CACHE[k] for k in keys]


def vrl_digest(value):
    return vrl_withhold([value])[0]


_WITHHELD = {'count': 0}


def withheld(digest):
    """What a withheld value is replaced by (parsers emit the same object).

    The ONE place any step withholds data (withhold, parse_json_object keep, and
    any future kind): it counts each use, so withholds_data() sees every one.
    """
    _WITHHELD['count'] += 1
    return {'withheld': True, 'bytes': digest['bytes'], 'sha256': digest['sha256']}


def withheld_markers(value):
    """Every {withheld: true, ...} object in a source, at any depth."""
    found = []
    if isinstance(value, dict):
        if value.get('withheld') is True:
            found.append(value)
        for item in value.values():
            found += withheld_markers(item)
    elif isinstance(value, list):
        for item in value:
            found += withheld_markers(item)
    return found


def well_formed(marker):
    return (isinstance(marker, dict) and marker.get('withheld') is True and set(marker) == {'withheld', 'bytes', 'sha256'}
            and type(marker['bytes']) is int and marker['bytes'] > 0
            and isinstance(marker['sha256'], str) and re.fullmatch(r'[0-9a-f]{64}', marker['sha256']) is not None)


def withholds_data(original, steps, **kwargs):
    """(normalized source, whether any step withheld data while building it).
    A sample where data was withheld must keep the raw body as raw_data."""
    before = _WITHHELD['count']
    source = normalized_source(original, steps, **kwargs)
    return source, _WITHHELD['count'] != before


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


def normalized_source(original, rules, parse_kv=vrl_kv, digest=vrl_digest, url=None):
    """The source a parser is expected to capture for a JSON input.

    By default that is the parsed input itself. A parser that unwraps a known
    envelope declares each step in `source_normalize` (field-coverage.yaml), and
    its `__source_kv` must equal the input after exactly these steps. No step
    overwrites a key: on a collision the step is skipped and the input kept as
    it was, so a colliding field can never vanish from the capture.

    - unwrap_single {path}: a one-element array of an object becomes the object
      (a CloudWatch Logs envelope carrying one logEvent).
    - base64_json_merge {path}: a base64 string that decodes to a JSON object is
      removed and the decoded object merged with the remaining keys (a Pub/Sub
      push wrapper's `message.data`); skipped if any top-level key collides.
    - parse_json_object {paths, target, arrays?, keep?}: the first path holding a
      string that parses to a JSON object (or array, with arrays: true) is moved;
      with `keep`, only an object is moved (an already-decoded one too) and it is
      cut to its allowlisted scalar fields, the rest withheld as withheld_fields, parsed, to the top-level `target` (a
      JSON log message passed through for spill and redaction; the raw text is
      removed like the other envelope steps); skipped if `target` exists.
    - parse_kv_merge {path, match, key_value_delimiter, field_delimiter}: a
      top-level string matching `match` that VRL parse_key_value (whitespace
      strict) parses to a non-empty object is removed and its pairs merged in;
      with `tail_keys`, the keys a line ends with are cut off first and keep
      their text verbatim (_kv_parts), never split on the field delimiter
    - allowlist {keep, nested?, urls?}: only `keep` top-level keys with scalar
      values stay, plus each `nested` key's object cut to its own key list;
      a `urls` key keeps only scheme://host[:port]path (VRL parse_url); every
      other key is withheld together as withheld_fields. Fail closed for a
      source whose secrets have no secret-looking key (cookies, URLs, stack
      traces, a hostile pre-existing key)
      (Keycloak's JSON log `message`); skipped on a parse error, an empty
      result, or a key colliding with the remaining keys.
    - withhold {paths, match}: at the first listed path that exists, a string
      or array whose text (the string, else its VRL encode_json) matches
      `match` is replaced by {withheld: true, bytes, sha256} of that text. An
      object or scalar is never withheld, a withhold step must follow an
      unpack step, and the event must keep the raw body as raw_data. For text that
      may carry credentials and that an earlier step could not unpack (so key
      redaction cannot reach it): it is kept only in raw_data.
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
                if rule.get('keep') and isinstance(value, dict) and rule['target'] not in source:
                    # With `keep`, an already-decoded object is filtered the same way.
                    parent, _, leaf = path.rpartition('.')
                    del (_get(source, parent) if parent else source)[leaf]
                    source[rule['target']] = kept_fields(value, rule['keep'], digest)
                    break
                if isinstance(value, str):
                    try:
                        # VRL parse_json skips a leading UTF-8 byte order mark.
                        parsed = json.loads(value.removeprefix('\ufeff'))
                    except ValueError:
                        break
                    if (isinstance(parsed, dict) or (rule.get('arrays') and isinstance(parsed, list))) and rule['target'] not in source:
                        # Moved, not copied: the unredacted JSON text leaves the
                        # source, so only its redacted fields can spill.
                        parent, _, leaf = path.rpartition('.')
                        if rule.get('keep'):
                            if not isinstance(parsed, dict):
                                break
                            parsed = kept_fields(parsed, rule['keep'], digest)
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
        elif kind == 'allowlist':
            source = allowlisted(source, rule, digest, url)
        elif kind == 'withhold':
            for path in rule['paths']:
                value = _get(source, path)
                if value is MISSING:
                    continue
                if not isinstance(value, (str, list)):
                    # An object is structured: the spill key-redacts it, so it is
                    # never withheld (and neither is a scalar).
                    break
                found = digest(value)
                if re.search(rule['match'], found['t']):
                    parent, _, leaf = path.rpartition('.')
                    (_get(source, parent) if parent else source)[leaf] = withheld(found)
                break
        else:
            raise AssertionError(f'unknown source_normalize kind {kind}')
    return source


URL_PROGRAM = '''v = string!(.v)
ok = false
r = ""
# Fail closed: a URL with whitespace, quotes, backslashes, braces, brackets,
# angle brackets or control characters is not a plain URL (parse_url would
# percent-encode them), and only http(s) is kept (a data: URI is withheld).
if !match(v, r'[\\s"\\\\{}\\x5B\\x5D<>\\x00-\\x1F\\x7F]') {
    u, err = parse_url(v)
    if err == null && includes(["http", "https"], downcase(string(u.scheme) ?? "")) && is_string(u.host) && string!(u.host) != "" {
        ok = true
        # Scheme and host, plus the path up to its first ';' (a ;jsessionid=
        # matrix parameter is a session id). No port, query or fragment.
        r = downcase(string!(u.scheme)) + "://" + string!(u.host) + (string(split(string(u.path) ?? "", ";")[0]) ?? "")
    }
}
. = {"ok": ok, "r": r}
'''
_URL_CACHE = {}


def vrl_urls(values):
    """Each URL reduced to scheme://host[:port]path by VRL parse_url, or None."""
    todo = [v for v in dict.fromkeys(values) if v not in _URL_CACHE]
    if todo:
        with tempfile.TemporaryDirectory(prefix='field-coverage-url-') as tmp:
            tmp = Path(tmp)
            (tmp/'u.vrl').write_text(URL_PROGRAM)
            (tmp/'u.json').write_text(''.join(json.dumps({'v': v})+'\n' for v in todo))
            run = subprocess.run(['vector', 'vrl', '--program', str(tmp/'u.vrl'), '--input', str(tmp/'u.json'), '--print-object'], text=True, capture_output=True, timeout=180)
        assert run.returncode == 0, run.stderr
        outputs = [json.loads(line, strict=False) for line in run.stdout.splitlines() if line.startswith('{')]
        assert len(outputs) == len(todo), f'Vector returned {len(outputs)} URLs for {len(todo)} inputs'
        for value, out in zip(todo, outputs):
            _URL_CACHE[value] = out['r'] if out.get('ok') else None
    return [_URL_CACHE[v] for v in values]


def vrl_url(value):
    return vrl_urls([value])[0]


def allowlisted(source, rule, digest=vrl_digest, url=None):
    """The allowlist step: see normalized_source."""
    url = url or vrl_url
    urls = set(rule.get('urls', []))
    nested = rule.get('nested', {})
    kept, rest = {}, {}

    def scalar(key, value, into, spill):
        if isinstance(value, (dict, list)):
            spill[key] = value
        elif key in urls:
            short = url(value) if isinstance(value, str) else None
            if short is None:
                spill[key] = value
            else:
                into[key] = short
                if short != value:
                    spill[key] = value
        else:
            into[key] = value

    for key, value in source.items():
        if key in nested and isinstance(value, dict):
            inner, inner_rest = {}, {}
            for k, v in value.items():
                if k in nested[key]:
                    scalar(k, v, inner, inner_rest)
                else:
                    inner_rest[k] = v
            kept[key] = inner
            if inner_rest:
                rest[key] = inner_rest
        elif key in rule['keep']:
            scalar(key, value, kept, rest)
        else:
            rest[key] = value
    if rest:
        kept['withheld_fields'] = withheld(digest(rest))
    return kept


def kept_fields(obj, keep, digest=vrl_digest):
    """An object cut to its allowlisted scalar fields; every other field is
    withheld together as `withheld_fields` ({withheld, bytes, sha256} of their
    VRL encode_json), so nothing outside the allowlist can spill."""
    kept = {k: v for k, v in obj.items() if k in keep and not isinstance(v, (dict, list))}
    rest = {k: v for k, v in obj.items() if k not in kept}
    if rest:
        kept['withheld_fields'] = withheld(digest(rest))
    return kept


def json_object(text):
    try: obj = json.loads(text)
    except json.JSONDecodeError: return None
    return obj if isinstance(obj, dict) and obj else None


def inject_probe(original, step):
    """A copy of `original` with NORMALIZE_PROBE planted INSIDE the payload that
    `step` unwraps, or None when this input has no such payload."""
    probe = copy.deepcopy(original)
    kind = step['kind']
    if kind == 'allowlist':
        # The probe fields are not on the allowlist: they must be withheld.
        probe.update(copy.deepcopy(NORMALIZE_PROBE))
        return probe
    if kind == 'withhold':
        # The secret goes into the value itself; the step must then withhold it.
        for path in step['paths']:
            value, holder, leaf = _locate(probe, path)
            if value is MISSING:
                continue
            if isinstance(value, str):
                holder[leaf] = value + ' clientSecret="nan2421-secret"'
            elif isinstance(value, list):
                value.append({'message': 'clientSecret="nan2421-secret"'})
            else:
                return None
            return probe
        return None
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
            if step.get('keep') and isinstance(value, dict):
                value.update(copy.deepcopy(NORMALIZE_PROBE))
                return probe
            if not isinstance(value, str):
                continue
            parsed = json_object(value)
            if parsed is not None:
                parsed.update(copy.deepcopy(NORMALIZE_PROBE))
                holder[leaf] = json.dumps(parsed)
                return probe
            break
    return None


def applied(probe, step, steps, parse_kv=vrl_kv, digest=vrl_digest):
    """Whether `step` (the last of `steps`) ITSELF acts on the probe planted for
    it: run the steps before it, then it alone. It must change the source; an
    unpacking step surfaces the unknown field, a withholding step is the one
    that removes the secret (present before it, gone after). A step an earlier
    one already made a no-op is never counted as exercised."""
    before = normalized_source(probe, steps[:-1], parse_kv, digest)
    after = normalized_source(before, [step], parse_kv, digest)
    if after == before:
        return False
    if step['kind'] in ('withhold', 'allowlist') or step.get('keep'):
        return SECRET_MARKER in json.dumps(before) and SECRET_MARKER not in json.dumps(after) and '"withheld": true' in json.dumps(after)
    return NORMALIZE_UNKNOWN in [v for _, v in flatten(after)]


def normalize_probes(samples, steps, parse_kv=vrl_kv, digest=vrl_digest):
    """One probe per declared step: a real sample with an unknown field and a
    secret injected inside the payload the step unwraps (or into the value a
    withhold step withholds). A declared step that no sample exercises fails,
    so an opt-in can never go untested."""
    probes = []
    for index, step in enumerate(steps):
        prefix = 'withhold_probe' if step['kind'] in ('withhold', 'allowlist') or step.get('keep') else 'normalize_probe'
        for _name, event in samples:
            original = json_object(event['message'])
            probe = original and inject_probe(original, step)
            # Judged on the steps up to this one: a later step may withhold it.
            if probe and applied(probe, step, steps[:index + 1], parse_kv, digest):
                probes.append((f'{prefix}_{index}', {'message': json.dumps(probe)}))
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
    # Probe unseen keys, nested values, scalar/object arrays, redaction and
    # snake-case collisions on real JSON branch input.
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
    probe_base = None
    if probe:
        raw = probe.get('raw')
        assert raw is None or not probe.get('expect_withheld'), 'an expect_withheld probe is built from a sample'
        if raw is None:
            candidates = [event['message'] for _, event in samples if probe.get('require', '') in event['message']]
            assert candidates, 'no sample fits configured text probe'
            raw = probe_base = candidates[0]
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
    # And one more computes the digest of every value a withhold step may see.
    if steps:
        seen, seen_urls = [], []
        def collect(value):
            seen.append(value)
            return {'t': '', 'bytes': 0, 'sha256': ''}
        def collect_url(value):
            seen_urls.append(value)
            return None
        for _, event in samples:
            original = json_object(event['message'])
            if original:
                normalized_source(original, steps, digest=collect, url=collect_url)
        vrl_withhold(seen)
        vrl_urls(seen_urls)
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
        sources_by_raw = {}
        spill_keys = set()
        for (name, event), output in zip(samples, outputs):
            source = output.pop('__coverage_source')
            withheld_any = False
            if config['source'] in ('json', 'mixed'):
                try: original = json.loads(event['message'])
                except json.JSONDecodeError: original = {}
                if not isinstance(original, dict): original = {}
                if isinstance(original, dict) and original:
                    expected, withheld_any = withholds_data(original, steps)
                    assert source == expected, f'{name}: JSON source capture changed fields'
                    # Whatever any step withheld survives only in raw_data, so the
                    # event must carry the raw body there, unchanged.
                    if withheld_any:
                        assert output.get('raw_data') == event['message'], f'{name}: a withheld value needs raw_data equal to the raw body'
            # Central rule for every sample, text or JSON: a source carrying any
            # withheld marker keeps the raw body as raw_data, and every marker is
            # well formed (withheld: true, a byte count, a sha256).
            markers = withheld_markers(source)
            if markers:
                assert all(well_formed(m) for m in markers), f'{name}: malformed withheld marker'
                assert output.get('raw_data') == event['message'], f'{name}: a withheld value needs raw_data equal to the raw body'
            sources_by_raw.setdefault(event['message'], source)
            try:
                consumed = []
                if config.get('reference') == 'windows_sysmon':
                    consumed = reference_consumed(source, output)
                count += check(source, output, event['message'], rules, consumed, config['consumed_candidates'])
            except AssertionError as error:
                raise AssertionError(f'{path.parent.name}/{name}: {error}') from error
            if name == 'text_residual_probe':
                flat = dict(flatten(source))
                if probe.get('expect_withheld'):
                    # A parser that allowlists its fields withholds the unknown one:
                    # gone from the source, kept in raw_data, and counted in
                    # withheld_fields: its byte count grows over the unprobed sample
                    # by at least every injected key and value (a dropped field
                    # would not be counted).
                    assert probe['source'] not in flat and well_formed(source.get('withheld_fields')), 'text probe not withheld'
                    assert output.get('raw_data') == event['message'], 'a withheld text probe needs raw_data equal to the raw body'
                    base = (sources_by_raw.get(probe_base) or {}).get('withheld_fields') or {'bytes': 0}
                    pairs = re.findall(r'(\w+)="([^"]*)"', probe['text'])
                    assert probe['source'] in [k for k, _ in pairs], 'text probe source not injected as key="value"'
                    grown = source['withheld_fields']['bytes'] - base['bytes']
                    assert grown >= sum(len(k) + len(v) + 5 for k, v in pairs), 'text probe fields not all counted in withheld_fields'
                else:
                    assert flat.get(probe['source']) == 'nan2421-text-unknown', 'text probe missing from parsed source'
            if name.startswith('normalize_probe_'):
                # Unpacked into the source, or withheld by a later step (and then
                # kept in raw_data, checked above).
                assert withheld_any or NORMALIZE_UNKNOWN in [v for _, v in flatten(source)], f'{name}: unwrapped probe field missing from parsed source'
            # SECRET_MARKER, injected by every probe and used by samples for a
            # credential, may survive only in raw_data: never in unmapped, never in
            # a mapped OCSF attribute (a message echoing the raw body included).
            kept = {k: v for k, v in output.items() if k != 'raw_data'}
            assert SECRET_MARKER not in json.dumps(kept), 'secret leaked outside raw_data'
            if name in ('residual_probe', 'text_residual_probe') or name.startswith(('normalize_probe_', 'withhold_probe_')):
                assert 'nan2421-secret' not in json.dumps(output.get('unmapped', {})), 'secret leaked in spill'
            else:
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
