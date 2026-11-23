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


NOW = '__src_now_ms = to_unix_timestamp(now(), unit: "milliseconds")'


def run(parser, events, now_ms=None):
    """Run a parser; now_ms pins the prelude's "now" (the no-year decision)."""
    doc = yaml.safe_load((ROOT/'parsers-ocsf'/parser/'parser.yaml').read_text())
    program = doc['parser_vrl']
    if now_ms is not None:
        assert NOW in program, f'{parser}: no pinnable now'
        program = program.replace(NOW, f'__src_now_ms = {now_ms}')
    with tempfile.TemporaryDirectory(prefix='source-tz-') as tmp:
        tmp = Path(tmp)
        (tmp/'p.vrl').write_text(program + '\n.__coverage_source = __source_kv\n')
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
       ('America/New_York', '2026-11-01 00:30:00'), ('Europe/Berlin', '2026-10-25 03:30:00'),
       # Offsets beyond +12: the probe window must still bracket the instant.
       ('Pacific/Auckland', '2026-04-05 02:30:00'), ('Pacific/Auckland', '2026-09-27 02:30:00'),
       ('Pacific/Auckland', '2026-07-01 12:00:00'), ('Pacific/Chatham', '2026-04-05 02:15:00'),
       ('Pacific/Chatham', '2026-04-05 03:15:00'), ('Pacific/Chatham', '2026-09-27 03:15:00'),
       ('Pacific/Kiritimati', '2026-07-01 12:00:00'), ('Antarctica/McMurdo', '2026-04-05 02:30:00')]


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


def nearest_year(now, mo, d, h, mi, se, tz):
    """The expected year for a clock without one: this year in the source's
    zone; more than a day ahead is last year, more than 180 days back is next
    year when that is not ahead; Feb 29 takes the latest leap year."""
    import calendar
    year = now.astimezone(tz).year
    base = year if not (mo == 2 and d == 29) or calendar.isleap(year) else max(y for y in range(year - 4, year + 1) if calendar.isleap(y))
    def at(y):
        try:
            return dt.datetime(y, mo, d, h, mi, se, tzinfo=tz)
        except ValueError:
            return None
    want = at(base)
    if want > now + dt.timedelta(days=1) and at(base - 1):
        want = at(base - 1)
    elif want < now - dt.timedelta(days=180) and at(base + 1) and at(base + 1) <= now + dt.timedelta(days=1):
        want = at(base + 1)
    return int(want.timestamp() * 1000)


def year_checks(failures):
    """No-year clocks against a pinned "now": New Year in both directions (a
    sender a little fast or slow), Feb 29 in a non-leap year, and a replayed
    clock whose DST offset differs between the two years."""
    cases = [
        ('2026-12-31T23:59:58-05:00', 'Jan  1 00:00:01', 'America/New_York'),
        ('2027-01-01T00:00:05-05:00', 'Dec 31 23:59:59', 'America/New_York'),
        ('2026-12-31T19:05:00-05:00', 'Dec 31 19:05:00', 'America/New_York'),
        ('2027-01-01T00:05:00+09:00', 'Jan  1 00:05:00', 'Asia/Tokyo'),
        ('2027-03-10T12:00:00+00:00', 'Mar 12 12:00:00', 'America/New_York'),
        ('2026-06-01T12:00:00+00:00', 'Feb 29 12:00:00', 'UTC'),
        ('2028-03-01T12:00:00+00:00', 'Feb 29 12:00:00', 'Europe/Berlin'),
        ('2026-11-22T12:00:00+00:00', 'Dec 31 23:59:59', 'UTC'),
        ('2026-11-22T12:00:00+00:00', 'Jan  1 00:00:01', 'Asia/Tokyo'),
    ]
    months = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
    checked = 0
    for now_iso, clock, zone in cases:
        now = dt.datetime.fromisoformat(now_iso)
        event = {'message': f'<13>{clock} host-1 app[42]: rollover probe', **({'nano': {'source_timezone': zone}} if zone != 'UTC' else {})}
        (o, _), = run('syslog', [event], now_ms=int(now.timestamp() * 1000))
        mon, d, hms = clock.split()
        h, mi, se = map(int, hms.split(':'))
        want = nearest_year(now, months[mon], int(d), h, mi, se, zoneinfo.ZoneInfo(zone))
        if o.get('time') != want:
            failures.append(f'syslog {clock!r} in {zone} at {now_iso}: time {o.get("time")} (want {want})')
        checked += 1
    return checked


def unmapped_checks(failures):
    """A source timezone changes the time, never what spills: the unmapped key
    set of every sample is the same under UTC, a zone and a fixed offset."""
    checked = 0
    for parser in LOCAL:
        path = ROOT/'parsers-ocsf'/parser/'parser.yaml'
        doc = yaml.safe_load(path.read_text())
        samples = samples_for(path, doc, None)
        events = [{k: v for k, v in e.items() if k != 'nano'} for _, e in samples]
        base = run(parser, events)
        for zone in ('America/New_York', '+05:30'):
            for (name, _), (b, _), (o, _) in zip(samples, base, run(parser, [{**e, 'nano': {'source_timezone': zone}} for e in events])):
                keys_b = set(b.get('unmapped') or {}) - {'nano_time_assumed_tz'}
                keys_o = set(o.get('unmapped') or {}) - {'nano_time_assumed_tz'}
                if keys_b != keys_o:
                    failures.append(f'{parser}/{name} under {zone}: unmapped keys differ from UTC: +{sorted(keys_o - keys_b)} -{sorted(keys_b - keys_o)}')
        checked += 1
    return checked


def ios_checks(failures):
    """cisco_ios show-timezone: an inline zone name, and an inline offset that
    still gets the no-year rollover and the Feb 29 leap year."""
    cases = [  # (pinned now, header clock, zone the clock is in)
        ('2026-07-02T00:00:00+00:00', 'Jul  1 2026 12:00:00.000 America/New_York', 'America/New_York'),
        ('2026-06-01T12:00:00+00:00', 'Feb 29 12:00:00.000 EST', '-05:00'),
        ('2027-01-01T00:00:05-05:00', 'Dec 31 23:59:59.000 EST', '-05:00'),
        ('2026-11-22T12:00:00+00:00', 'Nov 22 11:00:00.000 CET', '+01:00'),
    ]
    for now_iso, clock, zone in cases:
        now = dt.datetime.fromisoformat(now_iso)
        line = f'<189>123: {clock}: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.0.2.10)'
        (o, _), = run('cisco_ios', [{'message': line, 'nano': {'source_timezone': 'Asia/Tokyo'}}], now_ms=int(now.timestamp() * 1000))
        parts = clock.split()
        mon, d = parts[0], int(parts[1])
        year = int(parts[2]) if len(parts) == 5 else None
        h, mi, se = (int(float(x)) for x in parts[-2].split(':'))
        tz = zoneinfo.ZoneInfo(zone) if '/' in zone else dt.timezone(dt.timedelta(hours=int(zone[:3]), minutes=int(zone[0] + zone[4:])))
        months = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
        want = int(dt.datetime(year, months[mon], d, h, mi, se, tzinfo=tz).timestamp() * 1000) if year else nearest_year(now, months[mon], d, h, mi, se, tz)
        mark = (o.get('unmapped') or {}).get('nano_time_assumed_tz')
        if o.get('time') != want or mark is not None:
            failures.append(f'cisco_ios {clock!r} at {now_iso}: time {o.get("time")} (want {want}), marker {mark!r} (want none)')
    return len(cases)


def inline_checks(failures):
    """An inline timezone the zone database does not know never drops the
    event: the clock uses the log source's setting, marked as assumed."""
    garbage = [('fortinet', 'tz="Mars/Base"'), ('fortinet', 'tz="GMT/UTC"'), ('fortinet', 'tz="America/NewYork"'),
               ('sophos', 'timezone="Mars/Base"'), ('sonicwall', 'Mars/Base')]
    for parser, inline in garbage:
        path = ROOT/'parsers-ocsf'/parser/'parser.yaml'
        doc = yaml.safe_load(path.read_text())
        samples = samples_for(path, doc, None)
        if parser == 'sonicwall':
            event = next(e for _, e in samples if '09:47:12 UTC' in e['message'])
            msg = event['message'].replace('09:47:12 UTC', '09:47:12 ' + inline)
        elif parser == 'sophos':
            event = next(e for _, e in samples if 'timezone="UTC"' in e['message'])
            msg = event['message'].replace('timezone="UTC"', inline)
        else:
            event = next(e for _, e in samples if 'time=09:54:00' in e['message'] and 'tz=' not in e['message'])
            msg = event['message'].replace('time=09:54:00', 'time=09:54:00 ' + inline)
        outs = run(parser, [{**event, 'message': msg, 'nano': {'source_timezone': 'Asia/Tokyo'}}])
        if len(outs) != 1 or (outs[0][0].get('unmapped') or {}).get('nano_time_assumed_tz') != 'Asia/Tokyo':
            failures.append(f'{parser} inline {inline!r}: event dropped or not marked with the source zone ({outs[:1]!r})')
    # fail2ban: a header clock WITH an offset and an offset-less "Found" clock
    # holding the same instant: only the offset-less one is converted.
    line = '2026-07-01T12:00:00+02:00 fail2ban.filter [1234]: INFO [sshd] Found 203.0.113.5 - 2026-07-01 10:00:00'
    (o, _), = run('fail2ban', [{'message': line, 'nano': {'source_timezone': 'America/New_York'}}])
    first_seen = (o.get('finding_info') or {}).get('first_seen_time')
    if o.get('time') != expect_utc_ms('UTC', '2026-07-01 10:00:00') or first_seen != expect_utc_ms('America/New_York', '2026-07-01 10:00:00'):
        failures.append(f'fail2ban: header time {o.get("time")} (must stay 10:00Z), Found clock {first_seen} (want 14:00Z)')
    return len(garbage)


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
    inline = inline_checks(failures)
    same = unmapped_checks(failures)
    ios = ios_checks(failures)
    nano_shape_checks(failures)
    if failures:
        print('\n'.join('FAIL ' + f for f in failures))
        raise SystemExit(1)
    print(f'PASS source timezone: {checked} local-time parsers shift by the setting; DST transitions in {dst} parsers; {years} year-boundary clocks; {inline} garbage inline zones; {ios} cisco_ios inline clocks; unmapped unchanged by the setting in {same} parsers; no parser leaks .nano in any shape')


if __name__ == '__main__':
    main()
