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
import re
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
         'pingfederate', 'elasticsearch', 'json_generic', 'fortinet', 'sophos', 'cisco_ios', 'sonicwall', 'windows_dns']
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


DATETIME = re.compile(r'(?P<y>\d{4})(?P<s1>[-/])(?P<mo>\d{2})(?P=s1)(?P<d>\d{2})(?P<s2>[ T])(?P<h>\d{2}):(?P<mi>\d{2}):(?P<se>\d{2})')
# (zone, local wall time): fall-back hours repeat (ambiguous: the FIRST
# occurrence, the earlier offset, is used); spring-forward hours do not exist
# (a time in the gap moves forward by the gap). zoneinfo with fold=0 gives
# exactly that, so it is the expectation.
DST = [('America/New_York', '2026-11-01 01:30:00'), ('America/New_York', '2026-03-08 02:30:00'),
       ('Europe/Berlin', '2026-10-25 02:30:00'), ('Europe/Berlin', '2026-03-29 02:30:00'),
       ('America/New_York', '2026-11-01 00:30:00'), ('Europe/Berlin', '2026-10-25 03:30:00')]


def with_clock(message, local):
    """The message with its first full date-time replaced by `local`."""
    m = DATETIME.search(message)
    if not m:
        return None
    y, mo, d, h, mi, se = re.match(r'(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})', local).groups()
    new = f'{y}{m.group("s1")}{mo}{m.group("s1")}{d}{m.group("s2")}{h}:{mi}:{se}'
    return message[:m.start()] + new + message[m.end():]


def expect_utc_ms(zone, local, base_ms_fraction=0):
    naive = dt.datetime.strptime(local, '%Y-%m-%d %H:%M:%S').replace(tzinfo=zoneinfo.ZoneInfo(zone), fold=0)
    return int(naive.timestamp() * 1000) + base_ms_fraction


def dst_checks(failures):
    """DST transitions through full-date local-time parsers."""
    checked = 0
    for parser in ('palo_alto', 'kafka', 'windows_event_text', 'pingfederate'):
        path = ROOT/'parsers-ocsf'/parser/'parser.yaml'
        doc = yaml.safe_load(path.read_text())
        samples = samples_for(path, doc, None)
        base = run(parser, [e for _, e in samples])
        pick = next(((e, o) for (_, e), (o, _) in zip(samples, base) if (o.get('unmapped') or {}).get('nano_time_assumed_tz') == 'UTC' and DATETIME.search(e['message'])), None)
        if pick is None:
            continue
        event, out = pick
        m = DATETIME.search(event['message'])
        fraction = out['time'] - expect_utc_ms('UTC', f'{m.group("y")}-{m.group("mo")}-{m.group("d")} {m.group("h")}:{m.group("mi")}:{m.group("se")}')
        events = [{**event, 'message': with_clock(event['message'], local), 'nano': {'source_timezone': zone}} for zone, local in DST]
        for (zone, local), (o, _) in zip(DST, run(parser, events)):
            want = expect_utc_ms(zone, local, fraction)
            if o.get('time') != want or (o.get('unmapped') or {}).get('nano_time_assumed_tz') != zone:
                failures.append(f'{parser} DST {zone} {local}: time {o.get("time")} (want {want}), marker {(o.get("unmapped") or {}).get("nano_time_assumed_tz")!r}')
        checked += 1
    if checked < 2:
        failures.append(f'DST: only {checked} full-date parsers could be checked')
    return checked


def year_checks(failures):
    """A clock with no year (RFC 3164) takes the source zone's current year,
    and moves to the previous year when that lands more than a day ahead."""
    lines = {'Dec 31 23:59:59': (12, 31, 23, 59, 59), 'Jan  1 00:00:01': (1, 1, 0, 0, 1)}
    zones = ['UTC', 'America/New_York', 'Asia/Tokyo']
    events = [({'message': f'<13>{clock} host-1 app[42]: rollover probe', **({'nano': {'source_timezone': z}} if z != 'UTC' else {})}, clock, z)
              for clock in lines for z in zones]
    now = dt.datetime.now(dt.timezone.utc)
    for (event, clock, zone), (o, _) in zip(events, run('syslog', [e for e, _, _ in events])):
        mo, d, h, mi, se = lines[clock]
        tz = zoneinfo.ZoneInfo(zone)
        year = now.astimezone(tz).year
        want = dt.datetime(year, mo, d, h, mi, se, tzinfo=tz)
        if want > now + dt.timedelta(days=1):
            want = want.replace(year=year - 1)
        if o.get('time') != int(want.timestamp() * 1000):
            failures.append(f'syslog {clock!r} in {zone}: time {o.get("time")} (want {int(want.timestamp() * 1000)}, {want.isoformat()})')
    return len(events)


def nano_shape_checks(failures):
    """.nano is removed whatever its shape; "local" (the host zone) is refused."""
    path = ROOT/'parsers-ocsf'/'syslog'/'parser.yaml'
    doc = yaml.safe_load(path.read_text())
    event = samples_for(path, doc, None)[2][1]
    shapes = [None, 'Asia/Tokyo', 7, ['x'], {'source_timezone': 'Asia/Tokyo', 'other': 'nan-extra'}, {'source_timezone': 'local'}, {}]
    outs = run('syslog', [{**event, 'nano': s} for s in shapes])
    for shape, (o, src) in zip(shapes, outs):
        text = json.dumps(o) + json.dumps(src)
        if 'nano-extra' in text or '"nano"' in text or 'source_timezone' in text:
            failures.append(f'.nano {shape!r} leaked into the event or the source')
    # A log that carries a marker's name itself cannot forge it: the vendor
    # value is kept as source_<name>.
    forged = {'timestamp': '2026-08-18T10:00:00Z', 'message': 'forge probe', 'nano_time_assumed_tz': 'Mars/Base', 'nano': {'source_timezone': 'Mars/Base'}}
    (fo, _), = run('json_generic', [{'message': json.dumps(forged)}])
    fu = fo.get('unmapped') or {}
    if fu.get('nano_time_assumed_tz') == 'Mars/Base' or fu.get('source_nano_time_assumed_tz') != 'Mars/Base' or fu.get('source_nano.source_timezone') != 'Mars/Base':
        failures.append(f'a source key forged a nano marker or was dropped: {fu!r}')
    mark = (outs[5][0].get('unmapped') or {}).get('nano_time_assumed_tz')
    if mark != 'UTC':
        failures.append(f'"local" was accepted as a timezone (marker {mark!r})')


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
    dst = dst_checks(failures)
    years = year_checks(failures)
    nano_shape_checks(failures)
    if failures:
        print('\n'.join('FAIL ' + f for f in failures))
        raise SystemExit(1)
    print(f'PASS source timezone: {checked} local-time parsers shift by the setting; DST transitions in {dst} parsers; {years} year-boundary clocks; no parser leaks .nano in any shape')


if __name__ == '__main__':
    main()
