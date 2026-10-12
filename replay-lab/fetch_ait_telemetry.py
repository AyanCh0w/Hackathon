#!/usr/bin/env python3
"""Retrieve selected public ZIP members by HTTP Range, without extracting labels."""
import argparse
import binascii
import hashlib
import io
import json
import re
import ssl
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from telemetry import SCENARIOS

RECORD = 'https://zenodo.org/records/19483937'
TLS = ssl.create_default_context(cafile='/etc/ssl/cert.pem' if Path('/etc/ssl/cert.pem').is_file() else None)


def ranged(url, spec, maximum, expected_start=None):
    """Validate bounded partial responses; distinct URLs avoid stale CDN range caches."""
    separator='&' if '?' in url else '?'
    request_url=url+separator+'range='+spec
    for attempt in range(3):
        try:
            with urlopen(Request(request_url,headers={'Range':'bytes='+spec,'Cache-Control':'no-cache'}),timeout=45,context=TLS) as response:
                if response.status!=206:raise ValueError('Server did not honor range; refusing whole-archive download')
                match=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',response.headers.get('Content-Range',''))
                if not match:raise ValueError('Invalid Content-Range')
                start,end,total=map(int,match.groups())
                if end-start+1>maximum or (expected_start is not None and start!=expected_start):
                    raise ValueError('Range response does not match request')
                data=response.read(maximum+1)
                if len(data)!=end-start+1:raise ValueError('Incomplete ranged ZIP member')
                return data,start,total
        except (HTTPError,URLError,TimeoutError,ValueError):
            if attempt==2:raise
            time.sleep(1+attempt)


class RemoteZip(io.RawIOBase):
    def __init__(self, url):
        self.url, self.position, self.transferred = url, 0, 0
        self.buffer,self.buffer_start,self.size=ranged(url,'-65536',65536)
        if self.buffer_start+len(self.buffer)!=self.size:raise ValueError('Archive tail range mismatch')
        self.transferred += len(self.buffer)

    def seekable(self):return True
    def readable(self):return True
    def tell(self):return self.position
    def seek(self, offset, whence=0):
        self.position = offset if whence == 0 else self.position + offset if whence == 1 else self.size + offset
        if not 0 <= self.position <= self.size:raise ValueError('Invalid archive seek')
        return self.position
    def read(self, size=-1):
        size = self.size-self.position if size < 0 else min(size, self.size-self.position)
        if not size:return b''
        if size > 64*1024*1024:raise ValueError('ZIP member request exceeds 64 MiB transfer bound')
        if size > 2*1024*1024:
            ranges=[(start,min(start+2*1024*1024,self.position+size)) for start in range(self.position,self.position+size,2*1024*1024)]
            def chunk(bounds):
                start,end=bounds
                data,offset,total=ranged(self.url,f'{start}-{end-1}',end-start,start)
                if total!=self.size or len(data)!=end-start:raise ValueError('Archive size or range changed')
                return data
            with ThreadPoolExecutor(max_workers=4) as pool:
                parts=list(pool.map(chunk,ranges))
            self.position+=size
            self.transferred+=sum(map(len,parts))
            return b''.join(parts)
        start, end = self.position, self.position+size
        if not (self.buffer_start <= start and end <= self.buffer_start+len(self.buffer)):
            request_end = min(self.size, max(end, start+65536))
            self.buffer,self.buffer_start,total=ranged(self.url,f'{start}-{request_end-1}',request_end-start,start)
            if total!=self.size or len(self.buffer)!=request_end-start:raise ValueError('Archive size or range changed')
            self.transferred += len(self.buffer)
        result = self.buffer[start-self.buffer_start:end-self.buffer_start]
        self.position = end
        return result


def select(info):
    path = info.filename.lower()
    if '/gather/' not in '/'+path or '/logs/' not in path or '/attacker' in path or '/labels/' in path:
        return False
    # DNS, Linux authentication/audit, and firewall observations. Preserve entire files.
    return not info.is_dir() and (path.endswith('/dnsmasq.log') or path.endswith('/audit.log') or path.endswith('/auth.log') or ('firewall' in path and re.search(r'/(?:syslog|kern.log)(?:\.\d+)?$',path)) or path.endswith(('/intranet_server/logs/suricata/eve.json', '/inet-firewall/logs/suricata/eve.json')))


def timestamp(raw, year):
    audit = re.search(r'audit\((\d+(?:\.\d+)?):', raw)
    if audit:return float(audit[1])
    match = re.match(r'(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)', raw)
    if match:
        return datetime.strptime(f'{year} {match[1]}', '%Y %b %d %H:%M:%S').replace(tzinfo=timezone.utc).timestamp()
    match = re.match(r'(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)', raw)
    if match:
        value=datetime.fromisoformat(match[1].replace('Z','+00:00'))
        return value.replace(tzinfo=timezone.utc).timestamp() if value.tzinfo is None else value.timestamp()
    return None


def fetch(name, root, year=2022, inventory_only=False):
    url=f'{RECORD}/files/{name}_no-pcaps.zip?download=1'
    remote=RemoteZip(url)
    with zipfile.ZipFile(remote) as archive:
        selected=[entry for entry in archive.infolist() if select(entry)]
        inventory=[{'file': e.filename,'compressed':e.compress_size,'uncompressed':e.file_size,'crc32':f'{e.CRC:08x}'} for e in selected]
        if inventory_only:
            candidates=[{'file': e.filename,'compressed':e.compress_size,'uncompressed':e.file_size}
                        for e in archive.infolist() if '/logs/' in e.filename and ('firewall' in e.filename or 'suricata' in e.filename) and not e.is_dir() and ('kernel' in e.filename or 'syslog' in e.filename or 'eve' in e.filename)]
            print(json.dumps({'scenario':name,'members':inventory,'network_candidates':candidates,'transfer':remote.transferred},indent=2),flush=True)
            return
        raw_root=root/'raw'/name;raw_root.mkdir(parents=True,exist_ok=True)
        events=[];skipped=0
        for entry in selected:
            if entry.compress_size>60*1024*1024 or entry.file_size>1024*1024*1024:
                raise ValueError('Selected log exceeds retrieval bound: '+entry.filename)
            relative=Path(entry.filename)
            if relative.is_absolute() or '..' in relative.parts:raise ValueError('Invalid ZIP member path')
            target=raw_root/relative;target.parent.mkdir(parents=True,exist_ok=True)
            contents=target.read_bytes() if target.exists() and target.stat().st_size == entry.file_size else None
            if contents is None or binascii.crc32(contents) != entry.CRC:
                contents=archive.read(entry)  # zipfile validates member CRC.
                target.write_bytes(contents)
            host=entry.filename.split('/gather/')[-1].split('/')[0]
            if host==entry.filename.split('/')[0] and '/gather/' not in entry.filename:
                host=entry.filename.split('gather/',1)[1].split('/')[0]
            host=host.replace('_','-')
            for line,raw in enumerate(io.StringIO(contents.decode('utf-8',errors='replace')),1):
                raw=raw.rstrip('\r\n')
                if '/suricata/' in entry.filename:
                    obj=json.loads(raw)
                    # Keep actual flows, DNS and sensor alerts; HTTP requests already exist in AIT-ADS.
                    if obj.get('event_type') not in ('flow','dns','alert'):continue
                    obj.update(host=host,host_basis='source file host',origin_file=str(target.relative_to(root)),origin_line=line,origin_hash=hashlib.sha256(raw.encode()).hexdigest())
                    events.append(obj)
                    continue
                stamp=timestamp(raw,year)
                if stamp is None:skipped+=1;continue
                event={'timestamp':stamp,'host':host,'host_basis':'source file host','raw':raw,
                       'event_type':'dns' if 'dnsmasq' in entry.filename else 'audit' if 'audit.log' in entry.filename else 'auth' if 'auth.log' in entry.filename else 'connection',
                       'origin_file':str(target.relative_to(root)),'origin_line':line,'origin_hash':hashlib.sha256(raw.encode()).hexdigest()}
                for key,dest in (('SRC','src_ip'),('DST','dest_ip'),('SPT','src_port'),('DPT','dest_port'),('PROTO','proto')):
                    match=re.search(r'\b'+key+r'=(\S+)',raw)
                    if match:event[dest]=match[1]
                events.append(event)
            print(name,entry.filename,len(contents),'bytes',flush=True)
            del contents
        # Normalization sorts timestamps structurally in the replay cache.
        output=root/(name+'.jsonl')
        temporary=output.with_suffix('.building.jsonl')
        with temporary.open('w') as handle:
            for event in events:handle.write(json.dumps(event,separators=(',',':'))+'\n')
        temporary.replace(output)
        manifest={'source':RECORD,'url':url,'year_assumption':year,'scenario':name,'members':inventory,
                  'records':len(events),'unparsed_lines':skipped,'bytes_transferred':remote.transferred,
                  'integrity':'ZIP member CRC verified; full archive MD5 not verified because only selected ranges were downloaded.',
                  'scope':'No labels, attacker logs or attack-time filtering used. Source host names retain file-derived identity.'}
        (root/(name+'.manifest.json')).write_text(json.dumps(manifest,indent=2)+'\n')
        return manifest


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--scenarios',nargs='+',choices=SCENARIOS,default=['russellmitchell'])
    parser.add_argument('--inventory-only',action='store_true');parser.add_argument('--output',type=Path,default=Path(__file__).parent/'telemetry-inputs')
    args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    for name in args.scenarios:
        try:
            result=fetch(name,args.output,inventory_only=args.inventory_only)
            if result:print(json.dumps(result),flush=True)
        except Exception as exc:
            print(json.dumps({'scenario':name,'error':str(exc)}),flush=True)
            raise


if __name__=='__main__':main()
