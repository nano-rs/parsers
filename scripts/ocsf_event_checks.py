#!/usr/bin/env python3
"""OCSF-level checks for one emitted event. Driven by scripts/validate-ocsf.sh.

This is the JSON half of the OCSF gate; the bash driver owns discovery, running
`vector vrl`, and the report format. Two subcommands:

    wrap  <sample-file>
        Print the `{"message": <raw>}` event to feed `vector vrl`. A sample may
        be the raw log line, an already-wrapped {"message": ...} object, or a
        JSON record (which gets wrapped as its own raw line).

    check --parser <parser.yaml> --event <emitted.json> [--label NAME]
        Run the tree-wide consistency rules against ONE emitted event, and —
        when nano's OCSF contract validator is available — the official 1.9
        schema check too. Prints `FAIL …` / `WARN …` lines; exit 1 on any FAIL.

Why the emitted event and never a row read back from the lake: a stored row has
been through column promotion and null-stripping, and validating one produces
dozens of bogus "required attribute missing" errors.
"""

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
CLASS_CATALOG = HERE / "ocsf-1.9.0-classes.json"
PROMOTED_FIELDS = HERE / "ocsf-1.9.0-promoted-fields.txt"

# nano's OCSF contract validator. Not vendored — it is a nano build artifact, so
# the schema gate runs wherever it is available and is reported as SKIPPED where
# it is not. The static rules below always run.
VALIDATOR_ENV = "OCSF_VALIDATOR"


def load_yaml(path):
    import yaml

    return yaml.safe_load(pathlib.Path(path).read_text())


def find_validator():
    explicit = os.environ.get(VALIDATOR_ENV)
    if explicit and pathlib.Path(explicit).is_file():
        return explicit
    found = shutil.which("ocsf_event_validate")
    return found


def read_event(path):
    """Parse the emitted event.

    `vector vrl --print-object` leaves raw control characters (TAB in particular)
    inside strings, so a Windows PrivilegeList or any multi-line raw_data makes
    the output technically invalid JSON. That is a printer artifact, not a parser
    defect, so parse leniently and re-serialize before handing anything on.
    """
    raw = pathlib.Path(path).read_text()
    # `--print-object` renders timestamps as VRL literals t'…', not JSON.
    raw = re.sub(r"t'([^']*)'", r'"\1"', raw)
    return json.loads(raw, strict=False)


def leaf_paths(obj, prefix=""):
    """Every leaf path in the event, with array indices collapsed to the parent."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = f"{prefix}.{key}" if prefix else key
            yield from leaf_paths(value, child)
    elif isinstance(obj, list):
        if not obj:
            yield prefix
        for item in obj:
            if isinstance(item, (dict, list)):
                yield from leaf_paths(item, prefix)
            else:
                yield prefix
    else:
        yield prefix


def promoted_set():
    entries = set()
    for line in PROMOTED_FIELDS.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        entries.add(line)
        # `resources[].name` and `enrichments[name=x].value` address the same
        # column as `resources.name` / `enrichments.value`.
        entries.add(re.sub(r"\[[^\]]*\]", "", line))
    return entries


def check(args):
    parser_doc = load_yaml(args.parser)
    event = read_event(args.event)
    label = args.label or pathlib.Path(args.event).name

    fails, warns = [], []

    # ---- rule 1: metadata.version matches the parser's declared ocsf_version.
    # Read from the YAML rather than hardcoded: `main` carries OCSF 1.8 parsers
    # and the ocsf-1.9 branch carries 1.9 ones, and both must be checkable.
    want_version = str(parser_doc.get("ocsf_version") or "").strip()
    got_version = str(((event.get("metadata") or {}).get("version")) or "")
    if not want_version:
        fails.append("parser.yaml has no `ocsf_version` key — cannot pin metadata.version")
    elif got_version != want_version:
        fails.append(
            f"metadata.version is {got_version!r}, parser declares ocsf_version {want_version!r}"
        )

    # ---- rule 2: type_uid == class_uid * 100 + activity_id
    class_uid = event.get("class_uid")
    activity_id = event.get("activity_id")
    type_uid = event.get("type_uid")
    if isinstance(class_uid, int) and isinstance(activity_id, int) and isinstance(type_uid, int):
        expect = class_uid * 100 + activity_id
        if type_uid != expect:
            fails.append(
                f"type_uid {type_uid} != class_uid*100+activity_id ({class_uid}*100+{activity_id}={expect})"
            )
    else:
        fails.append("class_uid / activity_id / type_uid must all be present integers")

    # ---- rule 3: no UDM leakage in the emitted event
    if "udm" in event:
        fails.append("event carries a `udm` object — OCSF parsers must not emit `.udm.*`")
    if "source_type" in event:
        fails.append("event carries `source_type` — use metadata.log_source instead")

    # ---- rule 4: class_uid is a real, non-deprecated OCSF class
    catalog = json.loads(CLASS_CATALOG.read_text())
    classes = catalog["classes"]
    if isinstance(class_uid, int):
        entry = classes.get(str(class_uid))
        if entry is None:
            fails.append(f"class_uid {class_uid} is not an OCSF {catalog['ocsf_version']} class")
        elif entry.get("deprecated"):
            fails.append(
                f"class_uid {class_uid} ({entry.get('caption')}) is DEPRECATED in OCSF "
                f"{catalog['ocsf_version']} — pick its replacement "
                "(3001/3005 -> 3007 User Management, 3001 group edits -> 3006 Group Management)"
            )

    # ---- rule 5: every written path is promoted, or under unmapped.*
    promoted = promoted_set()
    unqueryable = []
    for path in sorted(set(leaf_paths(event))):
        if not path or path.startswith("unmapped."):
            continue
        if path in promoted:
            continue
        unqueryable.append(path)
    if unqueryable:
        warns.append(
            "written but NOT promoted (silently unqueryable): " + ", ".join(unqueryable)
        )

    # ---- gate 2: the official OCSF contract, when the validator is present
    validator = find_validator()
    schema_state = "SKIPPED"
    if validator:
        proc = subprocess.run(
            [validator],
            input=json.dumps(event),
            capture_output=True,
            text=True,
        )
        lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
        if not lines:
            fails.append(f"OCSF validator produced no verdict: {proc.stderr.strip()[:200]}")
        else:
            verdict = json.loads(lines[0])
            if verdict.get("parse_error"):
                fails.append(f"validator could not parse the event: {verdict['parse_error'][:200]}")
            else:
                validation = verdict["validation"]
                if validation["valid"]:
                    schema_state = "OK"
                else:
                    schema_state = "INVALID"
                    for err in validation["errors"][:8]:
                        fails.append(
                            f"OCSF {validation['schema_version']}: {err['code']} "
                            f"{err['attribute_path']} — {err['message'][:110]}"
                        )

    for line in fails:
        print(f"      FAIL {label}: {line}")
    for line in warns:
        print(f"      WARN {label}: {line}")
    if not fails:
        print(
            f"      OK   {label}: class_uid={class_uid} activity_id={activity_id} "
            f"type_uid={type_uid} schema={schema_state}"
        )
    return 1 if fails else 0


def source_checks(args):
    """Static rules that hold even for a parser that has no samples yet."""
    path = pathlib.Path(args.parser)
    doc = load_yaml(path)
    vrl = doc.get("parser_vrl") or doc.get("normalize_vrl") or ""
    fails, warns = [], []

    name = str(doc.get("name") or "")
    if not name.endswith("_ocsf"):
        warns.append(f"name {name!r} does not end in `_ocsf`")
    if not str(doc.get("ocsf_version") or "").strip():
        fails.append("missing `ocsf_version` key (the OCSF version this parser emits)")

    # Comments legitimately talk about `.udm.*`; assignments must not exist.
    body = "\n".join(ln for ln in vrl.splitlines() if not ln.strip().startswith("#"))
    for match in re.finditer(r"\.udm\b[^\n]*", body):
        fails.append(f"assigns/reads `.udm.*`: {match.group(0).strip()[:90]}")
    for match in re.finditer(r'(^|[^\w.])\.source_type\b|"source_type"\s*:', body, re.M):
        snippet = body[match.start() : match.start() + 80].strip().splitlines()[0]
        fails.append(f"writes `source_type` (use metadata.log_source): {snippet[:90]}")

    # type_uid == class_uid * 100 + activity_id, wherever all three are literal.
    catalog = json.loads(CLASS_CATALOG.read_text())
    classes = catalog["classes"]
    # `"type_uid": 400200 + activity_id` is the correct idiom for a computed
    # uid — only a bare literal (nothing arithmetic after it) is checkable here.
    lit = lambda field: {
        int(m) for m in re.findall(field + r'"?\s*[:=]\s*(\d+)(?!\s*[\d.+*-])', body)
    }
    class_literals = lit("class_uid")
    activity_literals = lit("activity_id")
    # A parser may legitimately assign `"class_uid": class_uid` from a variable
    # it computed above — the Base Event fallback in the syslog-shaped parsers
    # does exactly that. There is then no literal to correlate against, and
    # demanding one fails a correct parser: linux_journald, routeros and zeek
    # all emit class_uid=0 / activity_id=99 / type_uid=99, which the real
    # validator accepts. Only correlate when the parser actually states its
    # class_uid literally; the per-event rule above already checks the
    # arithmetic on emitted output, which is the authoritative test.
    # A parser may assign `"class_uid": class_uid` from a variable it computed
    # above (the Base Event fallback in the syslog-shaped parsers does exactly
    # that) while still using literals on its other branches. When any such
    # dynamic assignment exists, a type_uid literal cannot be correlated
    # statically — demanding it fails correct parsers: linux_journald, routeros
    # and zeek all emit class_uid=0 / activity_id=99 / type_uid=99, which the
    # real validator accepts. The per-event rule above already checks the
    # arithmetic on emitted output, which is the authoritative test.
    dynamic_class = re.search(r'"class_uid"\s*:\s*[A-Za-z_]', body) is not None
    if class_literals and not dynamic_class:
        for literal in sorted(lit("type_uid")):
            cls, act = literal // 100, literal % 100
            if cls not in class_literals or act not in activity_literals:
                fails.append(
                    f"literal type_uid {literal} has no matching class_uid {cls} + activity_id {act} "
                    "in this parser"
                )

    for literal in sorted(class_literals):
        entry = classes.get(str(literal))
        if entry is None:
            fails.append(f"literal class_uid {literal} is not an OCSF {catalog['ocsf_version']} class")
        elif entry.get("deprecated"):
            fails.append(
                f"literal class_uid {literal} ({entry.get('caption')}) is DEPRECATED in OCSF "
                f"{catalog['ocsf_version']}"
            )

    for line in fails:
        print(f"    FAIL source: {line}")
    for line in warns:
        print(f"    WARN source: {line}")
    return 1 if fails else 0


def wrap(args):
    raw = pathlib.Path(args.sample).read_text().strip()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict) and "message" in parsed:
            print(json.dumps(parsed))
            return 0
    except json.JSONDecodeError:
        pass
    print(json.dumps({"message": raw}))
    return 0



def extract_inline(args) -> int:
    """Write a parser's inline `samples:` block out as individual .json files.

    `validate-vrl.sh` reads inline samples; this gate reads a sidecar
    `samples/` directory. Both are legitimate coverage, so rather than force
    one convention on 64 existing parsers, normalize the inline form into the
    shape this gate already understands.
    """
    import yaml

    doc = yaml.safe_load(pathlib.Path(args.parser).read_text()) or {}
    samples = doc.get("samples") or []
    if not samples:
        return 1
    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = 0
    for index, sample in enumerate(samples):
        raw = sample.get("raw") if isinstance(sample, dict) else sample
        if raw is None:
            continue
        # The gate's `wrap` step expects the sample file to hold the raw log
        # line, exactly as a sidecar sample does.
        (out / f"inline_{index:03d}.json").write_text(raw if isinstance(raw, str) else json.dumps(raw))
        written += 1
    return 0 if written else 1

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_wrap = sub.add_parser("wrap")
    p_wrap.add_argument("sample")
    p_wrap.set_defaults(func=wrap)

    p_check = sub.add_parser("check")
    p_check.add_argument("--parser", required=True)
    p_check.add_argument("--event", required=True)
    p_check.add_argument("--label")
    p_check.set_defaults(func=check)

    p_source = sub.add_parser("source")
    p_source.add_argument("--parser", required=True)
    p_source.set_defaults(func=source_checks)

    # Normalizes a parser's inline `samples:` block into the sidecar shape this
    # gate reads, so both conventions in the tree get real OCSF validation.
    p_inline = sub.add_parser("extract-inline")
    p_inline.add_argument("parser")
    p_inline.add_argument("out_dir")
    p_inline.set_defaults(func=extract_inline)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
