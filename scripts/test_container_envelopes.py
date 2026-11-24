#!/usr/bin/env python3
"""Container collector envelopes: nothing withheld, nothing schema-invalid.

kubernetes_container and docker read collector fields that sit beside
`message` on the event root (Vector kubernetes_logs / file / docker_logs). An
envelope field is left out of unmapped.envelope only when its value is an
attribute the event emits; a value the parser cannot emit (an image without its
ID, a pod uid that is not one, a namespace with no container) stays. docker
never builds a container from an image name alone (OCSF needs uid or name).
The events are the samples/envelope_*.json sidecars.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_source_timezone import ROOT, run  # noqa: E402

# (parser, sample file, {dotted path: value}); flattened unmapped keys hold dots.
CASES = [
    ('kubernetes_container', 'envelope_kept_1.json', {
        'unmapped.envelope.kubernetes.container_image': 'acme/app:v1',
        'unmapped.envelope.kubernetes.pod_uid': 'bad-uid',
        'unmapped.envelope.kubernetes.container_name': '<missing>',
        'device.container.name': 'app'}),
    ('kubernetes_container', 'envelope_kept_2.json', {
        'unmapped.envelope.kubernetes.container_image_id': 'sha256:onlyid'}),
    ('kubernetes_container', 'envelope_kept_3.json', {
        'device.hostname': 'node-1',
        'unmapped.envelope.kubernetes.pod_namespace': 'prod',
        'unmapped.envelope.kubernetes.pod_name': 'p1',
        'unmapped.envelope.kubernetes.pod_node_name': '<missing>'}),
    ('docker', 'envelope_image_only.json', {
        'device.hostname': 'h1', 'device.container': '<missing>', 'unmapped.envelope.image': 'nginx:1.27'}),
    ('docker', 'envelope_image_only_no_host.json', {
        'device': '<missing>', 'unmapped.envelope.image': 'nginx:1.27'}),
]


def at(obj, path):
    """A dotted path; a key may itself hold dots (unmapped keys are flattened)."""
    if path == '':
        return obj
    if not isinstance(obj, dict):
        return '<missing>'
    parts = path.split('.')
    for k in range(len(parts), 0, -1):
        key = '.'.join(parts[:k])
        if key in obj:
            found = at(obj[key], '.'.join(parts[k:]))
            if found != '<missing>':
                return found
    return '<missing>'


def main():
    failures = []
    for parser, sample, want in CASES:
        event = json.loads((ROOT / 'parsers-ocsf' / parser / 'samples' / sample).read_text())
        (out, _), = run(parser, [event])
        for path, value in want.items():
            got = at(out, path)
            if got != value:
                failures.append(f'{parser}/{sample}: {path} = {got!r}, want {value!r}')
    for f in failures:
        print('FAIL', f)
    if failures:
        sys.exit(1)
    print(f'PASS container envelopes: {len(CASES)} events keep every envelope field they do not emit')


if __name__ == '__main__':
    main()
