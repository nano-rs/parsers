#!/usr/bin/env python3
"""Check Sysmon field provenance against emitted Vector JSON (never raw_data).

Usage: sysmon_coverage_check.py SAMPLE VECTOR_OUTPUT
       sysmon_coverage_check.py SAMPLE_DIRECTORY --parser PARSER [--output-dir DIR]
The second form executes Vector for every sidecar sample. Requires yq and vector.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re
import subprocess
import tempfile

MISSING = object()


def get(obj, path):
    for part in path.split('.'):
        try:
            obj = obj[int(part)] if isinstance(obj, list) else obj[part]
        except (KeyError, IndexError, TypeError, ValueError):
            return MISSING
    return obj


def snake(key):
    key = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', key)
    key = re.sub(r'([a-z])([0-9])|([0-9])([a-zA-Z])', lambda m: '_'.join(x for x in m.groups() if x), key)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', key).replace('-', '_').lower()


def milliseconds(value):
    clock = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    return int(clock.replace(tzinfo=clock.tzinfo or dt.timezone.utc).timestamp() * 1000)


def mappings(source):
    """Independent source-to-output expectations, including EID-specific roles."""
    ed = source.get('event_data', {})
    eid = int(source.get('event_id', 0))
    proc = 'process' if eid in (1, 5) or eid not in (3, 7, 10, 11, 12, 13, 22, 23) else 'actor.process'
    paths = {}
    if eid != 10:
        paths.update(Image=proc+'.file.path', CommandLine=proc+'.cmd_line', ProcessId=proc+'.pid', ProcessGuid=proc+'.uid', User='actor.user.name', IntegrityLevel=proc+'.integrity', CurrentDirectory=proc+'.working_directory')
        if eid != 5:
            parent = 'actor.process' if eid == 1 else 'actor.process.parent_process'
            paths.update({k: parent+'.'+v for k, v in {'ParentImage':'file.path', 'ParentCommandLine':'cmd_line', 'ParentProcessId':'pid', 'ParentProcessGuid':'uid', 'ParentUser':'user.name'}.items()})
        file = 'module.file' if eid == 7 else proc+'.file'
        paths.update({k: file+'.'+v for k,v in {'Company':'company_name','Product':'product.name','Description':'desc','OriginalFileName':'internal_name','FileVersion':'version'}.items()})
    paths.update(LogonId='actor.session.uid', LogonGuid='actor.session.uuid')
    if eid == 10:
        paths.update(SourceImage='actor.process.file.path', SourceProcessGUID='actor.process.uid', SourceProcessId='actor.process.pid', TargetImage='process.file.path', TargetProcessGUID='process.uid', TargetProcessId='process.pid', User='actor.user.name', SourceThreadId='actor.process.ptid', SourceUser='actor.process.user.name', TargetUser='process.user.name')
    if eid == 3:
        paths.update({side+suffix: endpoint+'.'+attribute for side, endpoint in [('Source','src_endpoint'),('Destination','dst_endpoint')] for suffix,attribute in [('Ip','ip'),('Port','port'),('Hostname','hostname'),('PortName','svc_name')]})
    if eid == 7:
        paths['ImageLoaded'] = 'module.file.path'
        if isinstance(ed.get('Signed'),str) and ed['Signed'].lower() == 'true':
            paths.update(Signature='module.file.signatures.0.developer_uid', SignatureStatus='module.file.signatures.0.state')
    if eid in (11,23): paths['TargetFilename'] = 'file.path'
    if eid == 12: paths['TargetObject'] = 'reg_key.path'
    if eid == 13: paths.update(Details='reg_value.data', TargetObject='reg_value.name')
    if eid == 22: paths.update(QueryName='query.hostname', QueryResults='answers.0.rdata')
    result = {}
    for key, path in paths.items():
        value = ed.get(key, MISSING)
        if path.endswith(('.pid','.port','.ptid')):
            if type(value) not in (int,str): continue
            try: value = int(value)
            except ValueError: continue
        elif not isinstance(value,str): continue
        if key == 'User': value = value.split('\\')[1] if '\\' in value else value
        if key in ('SourceIp','DestinationIp','SourceHostname','DestinationHostname','QueryName'): value = value.lower()
        if key == 'SignatureStatus' and value.lower() in ('valid','expired','revoked','untrusted'): value = value.capitalize()
        if key == 'TargetObject' and eid == 13: value = value.rsplit('\\',1)[-1]
        if key == 'QueryResults' and not value: continue
        result[key] = (path,value)
    if isinstance(ed.get('UtcTime'),str) and not source.get('timestamp') and not source.get('time_created'):
        try: result['UtcTime'] = ('time', milliseconds(ed['UtcTime']))
        except ValueError: pass
    if eid == 11 and isinstance(ed.get('CreationUtcTime'),str):
        try: result['CreationUtcTime'] = ('file.created_time', milliseconds(ed['CreationUtcTime']))
        except ValueError: pass
    if eid == 10 and isinstance(ed.get('GrantedAccess'),str):
        try: result['GrantedAccess'] = ('actual_permissions', int(ed['GrantedAccess'],16))
        except ValueError: pass
    if eid == 3:
        if str(ed.get('Initiated','')).lower() in ('true','false'): result['Initiated'] = ('connection_info.direction_id',2 if str(ed['Initiated']).lower() == 'true' else 1)
        if str(ed.get('Protocol','')).lower() in ('tcp','udp'): result['Protocol'] = ('connection_info.protocol_num',6 if ed['Protocol'].lower() == 'tcp' else 17)
    if eid == 7 and isinstance(ed.get('Signed'),str) and ed['Signed'].lower() == 'true': result['Signed'] = ('module.file.signatures.0.serialization','Authenticode')
    if eid == 12 and ed.get('EventType') in ('CreateKey','DeleteKey'): result['EventType'] = ('activity_id',1 if ed['EventType']=='CreateKey' else 4)
    if eid == 13 and ed.get('EventType') == 'SetValue': result['EventType'] = ('activity_id',2)
    if eid == 22:
        try:
            status = int(ed.get('QueryStatus',''))
            if status == 0 or status in (*range(9001,9011),9017,9018): result['QueryStatus'] = ('rcode_id',0 if status == 0 else status-9000)
        except (TypeError,ValueError): pass
    hashes = ed.get('Hashes','')
    if eid != 10 and isinstance(hashes,str) and re.fullmatch(r'SHA256=[0-9a-fA-F]+',hashes):
        file = 'module.file' if eid == 7 else 'file' if eid in (11,23) else proc+'.file'
        result['Hashes'] = (file+'.hashes.0.value', hashes.split('=')[1].lower())
    return result


def check(sample, output):
    source = json.loads(Path(sample).read_text())
    if 'message' in source:
        try: source = json.loads(source['message'])
        except json.JSONDecodeError:
            assert output['class_uid'] == 1007 and output['activity_id'] == 99
            return 0
    ed = source.get('event_data',{})
    expected = mappings(source)
    # NAN-2421 shares source/residual checks with every parser. Keep the
    # independent EID-specific destination expectations and role assertions.
    import yaml
    from field_coverage_check import check as check_fields, reference_consumed
    config = yaml.safe_load((Path(__file__).resolve().parents[1] / 'parsers-ocsf/windows_sysmon/field-coverage.yaml').read_text())
    check_fields(source, output, output.get('raw_data', ''), config['transforms'], reference_consumed(source, output), config['consumed_candidates'])
    if Path(sample).stem == '05_no_residual': assert 'unmapped' not in output
    if source.get('event_id') == 999: assert output['class_uid'] == 1007 and output['activity_id'] == 99
    if source.get('event_id') in (7,11,23):
        assert get(output,'actor.process.file.hashes') is MISSING
    if 'IntegrityLevel' in expected:
        path, value = expected['IntegrityLevel']
        level_id = {'unknown':0,'untrusted':1,'low':2,'medium':3,'high':4,'system':5,'protected':6}.get(value.lower(),99)
        assert get(output,path+'_id') == level_id
    if source.get('event_id') == 7 and str(ed.get('Signed','')).lower() != 'true':
        assert get(output,'module.file.signatures') is MISSING
    return len(ed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample',type=Path)
    parser.add_argument('vector_output',nargs='?',type=Path)
    parser.add_argument('--parser',type=Path)
    parser.add_argument('--output-dir',type=Path)
    args = parser.parse_args()
    if args.vector_output:
        count = check(args.sample,json.loads(args.vector_output.read_text()))
        print(f'PASS {args.sample.name}: {count} EventData fields')
        return
    if not args.parser: parser.error('provide VECTOR_OUTPUT or --parser')
    samples = sorted(args.sample.glob('*.json')) if args.sample.is_dir() else [args.sample]
    assert samples, 'no samples found'
    program = subprocess.check_output(['yq','.parser_vrl',str(args.parser)],text=True)
    total = 0
    with tempfile.TemporaryDirectory(prefix='sysmon-coverage-') as tmp:
        vrl = Path(tmp)/'parser.vrl';vrl.write_text(program)
        for sample in samples:
            source = json.loads(sample.read_text())
            envelope = source if 'message' in source else {'message':sample.read_text().strip()}
            inp = Path(tmp)/'input.json';inp.write_text(json.dumps(envelope)+'\n')
            run = subprocess.run(['vector','vrl','--program',str(vrl),'--input',str(inp),'--print-object'],text=True,capture_output=True,check=True)
            output = json.loads(run.stdout)
            count = check(sample,output);total += count
            if args.output_dir:
                args.output_dir.mkdir(parents=True,exist_ok=True)
                (args.output_dir/sample.name).write_text(json.dumps(output,indent=2)+'\n')
            print(f'PASS {sample.name}: {count} EventData fields')
    print(f'PASS {len(samples)} samples, {total} EventData fields; no lost fields')


if __name__ == '__main__':
    main()
