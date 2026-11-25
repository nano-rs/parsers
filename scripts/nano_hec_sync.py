#!/usr/bin/env python3
"""Copy nano's HEC delivery VRL into scripts/nano-hec/, or check the copy.

scripts/test_input_contract.py runs every declared parser through what nano
(v2.0.36+, NAN-5891 / NAN-5902) actually hands it over Splunk HEC, for both
answers nano can give: the lossless record view a parser that DECLARES its
input contract gets, and the v2.0.35 delivery an undeclared JSON-input parser
gets. Those steps are nano's own VRL, copied here verbatim from a nanosiem
commit (scripts/nano-hec/nano-hec.lock) so CI needs no nanosiem checkout:

- hec_normalize.vrl: the `hec_normalize` remap (config/vector/02-hec-source.toml);
- hec_json_payload.vrl: `HEC_JSON_PAYLOAD_VRL` (hec_record_view_vrl! plus the
  record step), the `<parser>_hec_payload` step of a declared json parser;
- hec_legacy_json_payload.vrl: `HEC_LEGACY_JSON_PAYLOAD_VRL`, the same step for
  an undeclared parser that v2.0.35 reads as JSON.

Usage:
  scripts/nano_hec_sync.py <nanosiem git dir> [<ref>]          # write the copy
  scripts/nano_hec_sync.py --check <nanosiem git dir> [<ref>]  # fail on drift
The nanosiem checkout is only read (`git -C <dir> show <ref>:<path>`).
"""
import re
import subprocess
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / 'nano-hec'
HEC_SOURCE = 'config/vector/02-hec-source.toml'
MOD_RS = 'nanosiem-core/src/parsers/vector_config/mod.rs'
PAYLOAD_RS = 'nanosiem-core/src/parsers/vector_config/hec_payload.rs'


def show(repo, ref, path):
    return subprocess.run(['git', '-C', repo, 'show', f'{ref}:{path}'], check=True, capture_output=True, text=True).stdout


def one(pattern, text, what):
    hits = re.findall(pattern, text, re.S)
    if len(hits) != 1:
        sys.exit(f'nano_hec_sync: expected one {what}, found {len(hits)} (nano changed shape; update this script)')
    return hits[0]


def extract(repo, ref):
    toml = show(repo, ref, HEC_SOURCE)
    normalize = one(r"\[transforms\.hec_normalize\]\n.*?\nsource = '''\n(.*?)'''", toml, 'hec_normalize source')
    mod_rs = show(repo, ref, MOD_RS)
    view = one(r'macro_rules! hec_record_view_vrl \{\s*\(\) => \{\s*r#"(.*?)"#\s*\};\s*\}', mod_rs, 'hec_record_view_vrl!')
    payload_rs = show(repo, ref, PAYLOAD_RS)
    record = one(r'const HEC_JSON_PAYLOAD_VRL: &str = concat!\(\s*hec_record_view_vrl!\(\),\s*r#"(.*?)"#\s*\);', payload_rs,
                 'HEC_JSON_PAYLOAD_VRL')
    legacy = one(r'const HEC_LEGACY_JSON_PAYLOAD_VRL: &str = r#"(.*?)"#;', payload_rs, 'HEC_LEGACY_JSON_PAYLOAD_VRL')
    commit = subprocess.run(['git', '-C', repo, 'rev-parse', ref], check=True, capture_output=True, text=True).stdout.strip()
    return commit, {
        'hec_normalize.vrl': normalize,
        'hec_json_payload.vrl': view + record + '\n',
        'hec_legacy_json_payload.vrl': legacy + '\n',
    }


def main():
    args = sys.argv[1:]
    check = bool(args) and args[0] == '--check'
    if check:
        args = args[1:]
    if not args:
        sys.exit(__doc__)
    repo, ref = args[0], (args[1] if len(args) > 1 else 'origin/main')
    commit, files = extract(repo, ref)
    if check:
        drift = [n for n, body in files.items() if not (OUT / n).exists() or (OUT / n).read_text() != body]
        if drift:
            sys.exit(f'scripts/nano-hec is not nano {ref} ({commit}): {", ".join(drift)} differ; '
                     f'rerun scripts/nano_hec_sync.py {repo} {ref}')
        print(f'scripts/nano-hec matches nano {ref} ({commit})')
        return
    OUT.mkdir(exist_ok=True)
    for name, body in files.items():
        (OUT / name).write_text(body)
    (OUT / 'nano-hec.lock').write_text(
        '# nano\'s HEC delivery VRL, copied verbatim by scripts/nano_hec_sync.py.\n'
        '# Check the copy against a nanosiem checkout with\n'
        '#   scripts/nano_hec_sync.py --check <nanosiem git dir> [<ref>]\n'
        f'nanosiem_commit={commit}\n')
    print(f'wrote scripts/nano-hec from nano {ref} ({commit})')


if __name__ == '__main__':
    main()
