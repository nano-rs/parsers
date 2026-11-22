#!/usr/bin/env python3
"""The log source's timezone setting (.nano.source_timezone) reaches every
clock that carries no offset, and nothing else.

For each parser below, its first sample whose time was read without an offset
(unmapped.nano_time_assumed_tz is set) runs with no setting and with several
settings, and the test asserts:
- the time moves by exactly the zone's UTC offset at that local time
  (zoneinfo), and unmapped.nano_time_assumed_tz names the zone used;
- any fixed offset ("+05:30", "+03:30", "-09:30", "+0430") is applied as
  given (not looked up), and an out-of-range one is rejected;
- an absent or invalid setting reads the clock as UTC (marker "UTC");
- .nano never reaches the event or the parsed source, in ANY parser.
A clock that carries its own offset or inline timezone ignores the setting
and sets no marker (fortinet / sophos / cisco_ios / sonicwall inline zones).
"""
import datetime as dt
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zoneinfo

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from field_coverage_check import samples_for  # noqa: E402
from provenance import VECTOR_ENV  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ['palo_alto', 'syslog', 'zscaler_zia', 'windows_event_text', 'checkpoint', 'cyberark', 'cisco_asa', 'f5_waf',
         'infoblox_dhcp', 'routeros', 'bind_dns', 'cisco_ftd', 'fail2ban', 'juniper_junos', 'pfsense', 'kafka',
         'pingfederate', 'elasticsearch', 'json_generic', 'fortinet', 'sophos', 'cisco_ios', 'sonicwall']
# (setting, marker): any +-HH:MM offset is applied as given; an invalid
# setting or a zero offset is UTC.
SETTINGS = [('America/New_York', 'America/New_York'), ('Asia/Tokyo', 'Asia/Tokyo'), ('+05:30', '+05:30'),
            ('-04:00', '-04:00'), ('+03:30', '+03:30'), ('-09:30', '-09:30'), ('+0430', '+04:30'), ('+14:00', '+14:00'),
            ('+0000', 'UTC'), ('+15:00', 'UTC'), ('+05:61', 'UTC'), ('Mars/Olympus_Mons', 'UTC'), ('', 'UTC')]


def run(parser, events):
    doc = yaml.safe_load((ROOT/'parsers-ocsf'/parser/'parser.yaml').read_text())
    with tempfile.TemporaryDirectory(prefix='source-tz-') as tmp:
        tmp = Path(tmp)
        (tmp/'p.vrl').write_text(doc['parser_vrl'] + '\n.__coverage_source = __source_kv\n')
        (tmp/'in.json').write_text(''.join(json.dumps(e) + '\n' for e in events))
        out = subprocess.run(['vector', 'vrl', '--program', str(tmp/'p.vrl'), '--input', str(tmp/'in.json'), '--print-object'],
                             text=True, capture_output=True, timeout=300, env=VECTOR_ENV)
    assert out.returncode == 0, out.stderr
    events = [json.loads(l, strict=False) for l in out.stdout.splitlines() if l.startswith('{')]
    return [(e, e.pop('__coverage_source', {})) for e in events]


def offset_ms(zone, utc_ms):
    """UTC minus local, in ms, for a clock read as `utc_ms` in UTC."""
    if zone == 'UTC':
        return 0
    if zone[0] in '+-':
        h, m = int(zone[1:3]), int(zone[4:6])
        return -(1 if zone[0] == '+' else -1) * (h * 3600 + m * 60) * 1000
    naive = dt.datetime.fromtimestamp(utc_ms / 1000, dt.timezone.utc).replace(tzinfo=None)
    local = naive.replace(tzinfo=zoneinfo.ZoneInfo(zone))
    return -int(local.utcoffset().total_seconds() * 1000)


def main():
    failures = []
    checked = 0
    for parser in sorted(p.parent.name for p in (ROOT/'parsers-ocsf').glob('*/parser.yaml')):
        path = ROOT/'parsers-ocsf'/parser/'parser.yaml'
        doc = yaml.safe_load(path.read_text())
        samples = samples_for(path, doc, None)
        base = run(parser, [e for _, e in samples])
        with_nano = run(parser, [{**e, 'nano': {'source_timezone': 'America/Argentina/Ushuaia'}} for _, e in samples])
        for (name, _), (out, src), (nout, nsrc) in zip(samples, base, with_nano):
            if 'nano' in nout or 'nano' in nsrc or 'source_timezone' in json.dumps(nout) + json.dumps(nsrc) or 'Ushuaia' in json.dumps({k: v for k, v in nout.items() if k != 'unmapped'}) + json.dumps(nsrc) or (nout.get('unmapped') or {}).get('nano_time_assumed_tz') not in (None, 'America/Argentina/Ushuaia'):
                failures.append(f'{parser}/{name}: .nano leaked into the event or the source')
            if src != nsrc:
                failures.append(f'{parser}/{name}: the timezone setting changed the parsed source')
        if parser not in LOCAL:
            continue
        pick = next(((n, e, o) for (n, e), (o, _) in zip(samples, base) if (o.get('unmapped') or {}).get('nano_time_assumed_tz') == 'UTC' and o.get('time')), None)
        if pick is None:
            failures.append(f'{parser}: no sample reads a clock without an offset')
            continue
        name, event, out = pick
        runs = run(parser, [{**event, 'nano': {'source_timezone': s}} if s else event for s, _ in SETTINGS])
        for (setting, zone), (o, _) in zip(SETTINGS, runs):
            want = out['time'] + offset_ms(zone, out['time'])
            got = o.get('time')
            mark = (o.get('unmapped') or {}).get('nano_time_assumed_tz')
            if got != want or mark != zone:
                failures.append(f'{parser}/{name} with {setting!r}: time {got} (want {want}), marker {mark!r} (want {zone!r})')
        checked += 1
    if failures:
        print('\n'.join('FAIL ' + f for f in failures))
        raise SystemExit(1)
    print(f'PASS source timezone: {checked} local-time parsers shift by the setting; no parser leaks .nano')


if __name__ == '__main__':
    main()
