"""Structural ingestion only. No attack labels, classifications, or future-state inference."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus, urlsplit, parse_qs

SCENARIOS = ('russellmitchell', 'fox', 'harrison', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson')
VERSION = 8

# Structural coverage, not a promise of complete collection.
CAPABILITIES = {'connection': 1, 'dns': 2, 'process': 4, 'auth': 8, 'service': 16, 'web': 32}


def safe_text(value):
    """Remove embedded command payloads and likely credentials from displayed evidence."""
    text = str(value)
    text = re.sub(r'(?i)([?&](?:wp_meta|cmd|command|exec|password|passwd|pwd|token|secret|key)=)[^\s&\"]+', r'\1[redacted]', text)
    text = re.sub(r'(?i)((?:password|passwd|pwd|token|secret)\s*[=:]\s*)[^\s,;\"\']+', r'\1[redacted]', text)
    text = re.sub(r'(?i)(mysql\b[^\n]*?\s-p)[^\s]+', r'\1[redacted]', text)
    text = re.sub(r'\b(proctitle=)[\da-fA-F]+', r'\1[redacted]', text)
    if 'type=EXECVE' in text:
        text = re.sub(r'\b(a\d+=)(?:"[^"]*"|\S+)', r'\1[redacted]', text)
    return text[:2200]


def valid_ip(value):
    value = str(value or '')
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if value.count(':') == 1:
            try:
                ipaddress.ip_address(value.split(':')[0])
                return value.split(':')[0]
            except ValueError:
                pass
    return ''


def command_features(commands):
    """Recognize command intent without execution or returning command contents."""
    commands = commands[:12000]
    callback = re.search(r'/dev/tcp/([\w.:-]+)/([\d]+)', commands)
    endpoint = callback.group(1) + ':' + callback.group(2) if callback else ''
    callback_pattern = bool(callback or re.search(
        r'(?is)(?:\b(?:nc|ncat|netcat)\b[^\n]{0,250}\s-(?:e|c)\s+\S*(?:sh|bash)|'
        r'\bsocat\b[^\n]{0,250}(?:exec:|system:)[^\n]{0,250}(?:tcp|openssl)|'
        r'\bsocat\b[^\n]{0,250}(?:tcp|openssl)[^\n]{0,250}(?:exec:|system:)|'
        r'socket[^\n]{0,800}\.connect\s*\([^\n]{0,800}(?:dup2|subprocess)|'
        r'\.connect\s*\([^\n]{0,800}dup2)', commands))
    cracking = bool(re.search(r'(?i)(?:^|[\s/;|])(?:john|hashcat|hydra|medusa|ncrack|wphashcrack\.sh)(?:\s|$)', commands))
    return {'callback': endpoint, 'callback_pattern': callback_pattern, 'cracking': cracking,
            'shell_command': bool(re.search(r'(?i)\b(?:bash|sh|mysql|chmod|curl|wget|whoami|cat|john|hashcat)\b', commands))}


def payload_features(raw):
    """Inspect bounded command parameters as data. Never evaluate or execute them."""
    features = {'encoded_command': False, 'callback': '', 'callback_pattern': False, 'cracking': False, 'shell_command': False}
    match = re.search(r'(?:[?&])(wp_meta|cmd|command|exec)=([^\s\"&]+)', raw)
    if not match:
        return features
    encoded = unquote_plus(match.group(2))[:16384]
    if match.group(1) != 'wp_meta':
        features.update(command_features(encoded))
        features['command_parameter'] = True
        return features
    try:
        decoded = base64.b64decode(encoded + '=' * (-len(encoded) % 4), validate=True).decode('utf-8', errors='replace')
        if len(decoded) > 12000:
            return features
        content = json.loads(decoded)
        if isinstance(content, list) and all(isinstance(item, str) for item in content):
            commands = ' '.join(content)
        elif isinstance(content, dict):
            commands = json.dumps(content)
        else:
            commands = decoded
        features['encoded_command'] = True
        features.update(command_features(commands))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        pass
    return features


def process_features(e):
    """Bounded audit command decoding occurs only when the record is ingested."""
    commands = e.get('_command', '') + ' ' + e.get('process', {}).get('exe', '')
    raw = e.get('_process_payload', '')
    match = re.search(r'\bproctitle=([\da-fA-F]{2,16384})\b', raw)
    if match:
        try:
            commands += ' ' + bytes.fromhex(match[1]).decode('utf-8', errors='replace').replace('\x00', ' ')
        except ValueError:
            pass
    elif 'type=EXECVE' in raw:
        arguments = []
        for match in re.finditer(r'\ba\d+=(?:"([^\"]*)"|([^\s]+))', raw):
            value = match[1] if match[1] is not None else match[2]
            if re.fullmatch(r'(?:[\da-fA-F]{2}){2,8192}', value):
                try:value = bytes.fromhex(value).decode('utf-8', errors='replace')
                except ValueError:pass
            arguments.append(value)
        commands += ' ' + ' '.join(arguments)
    return command_features(commands)


def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def structural_fields(data, raw, url):
    """Extract fields before redaction; opaque process commands are inspected online."""
    flow = data.get('flow') if isinstance(data.get('flow'), dict) else {}
    dst_port = number(data.get('dest_port') or data.get('dstport'))
    if not dst_port:
        m = re.search(r':(\d+)$', str(data.get('dstip', '')))
        dst_port = number(m[1]) if m else 0
    dns = data.get('dns') if isinstance(data.get('dns'), dict) else {}
    queries = dns.get('queries') or ([dns] if dns.get('rrname') else [])
    query_rows = [{'name': str(q.get('rrname') or q.get('name') or '').rstrip('.').lower()[:1024],
                   'type': str(q.get('rrtype') or q.get('type') or '').upper()}
                  for q in queries[:32] if isinstance(q, dict)]
    m = re.search(r'query\[([^\]]+)\]\s+(\S+)', raw)
    if m:
        query_rows.append({'name': m[2].rstrip('.').lower()[:1024], 'type': m[1].upper()})
    process = data.get('process') if isinstance(data.get('process'), dict) else {}
    audit = {}
    for match in re.finditer(r'\b(pid|ppid|uid|euid|auid|exe|unit|acct|res)=(?:"([^\"]*)"|([^\s\']+))', raw):
        audit[match[1]] = match[2] if match[2] is not None else match[3]
    audit_type = re.search(r'\btype=([A-Z_]+)', raw)
    command = str(process.get('command_line') or data.get('command') or '')[:16384]
    process_info = {'pid': str(process.get('pid') or audit.get('pid', '')),
                    'ppid': str(process.get('ppid') or audit.get('ppid', '')),
                    'exe': str(process.get('exe') or audit.get('exe', '')),
                    'uid': str(process.get('uid') if process.get('uid') is not None else audit.get('uid', '')),
                    'euid': str(process.get('euid') if process.get('euid') is not None else audit.get('euid', '')),
                    'type': audit_type[1] if audit_type else '', 'result': audit.get('res', '')}
    auth_failed = bool(re.search(r'(?i)(?:failed password|authentication failure|authentication failed|login failed|invalid user|USER_AUTH[^\n]*res=failed)', raw))
    auth_present = auth_failed or bool(re.search(r'(?i)(?:dovecot.*login|sshd.*(?:accepted|authentication)|sudo|successful su|type=USER_(?:AUTH|LOGIN|ACCT))', raw))
    user = str(data.get('dstuser') or audit.get('acct', ''))
    if not user:
        match = re.search(r'(?i)(?:user[=<]|for (?:invalid user )?)([\w.@-]+)', raw)
        user = match[1] if match else ''
    caps = 0
    if (dst_port or data.get('proto') or flow) and (data.get('src_ip') or data.get('srcip')) and (data.get('dest_ip') or data.get('dstip')):
        caps |= CAPABILITIES['connection']
    if query_rows:
        caps |= CAPABILITIES['dns']
    if process or process_info['type'] in ('SYSCALL', 'EXECVE', 'PROCTITLE') or command:
        caps |= CAPABILITIES['process']
    if auth_present:
        caps |= CAPABILITIES['auth']
    if process_info['type'] in ('SERVICE_STOP', 'SERVICE_START') or re.search(r'(?i)\b(?:stopped|stopping|started)\s+', raw):
        caps |= CAPABILITIES['service']
    if url:
        caps |= CAPABILITIES['web']
    return {'capabilities': caps, 'src_port': number(data.get('src_port') or data.get('srcport')),
            'dst_port': dst_port, 'protocol': str(data.get('proto') or data.get('protocol') or '').upper(),
            'flow_id': str(data.get('flow_id') or ''), 'flow_state': str(flow.get('state') or data.get('conn_state') or ''),
            'bytes_out': number(flow.get('bytes_toserver')), 'bytes_in': number(flow.get('bytes_toclient')),
            'dns_queries': query_rows, 'dns_rcode': str(dns.get('rcode') or ''),
            'process': process_info, 'auth_failed': auth_failed, 'user': user,
            'service_unit': audit.get('unit', ''), '_command': command,
            '_process_payload': raw[:16384] if audit_type and audit_type[1] in ('PROCTITLE', 'EXECVE') else ''}


def normalize(obj, filename, line):
    aminer = 'LogData' in obj
    data = obj.get('data') or {}
    if not isinstance(data, dict):
        data = {}
    pre = obj.get('predecoder') or {}
    rule = obj.get('rule') or {}
    component = obj.get('AnalysisComponent') or {}
    log = obj.get('LogData') or {}
    if aminer:
        stamps = log.get('Timestamps') or log.get('DetectionTimestamp')
        stamp = float(stamps[0])
        raw = '\n'.join(str(x) for x in log.get('RawLogData', []))
        locations = log.get('LogResources') or []
        location = str(locations[0]) if locations else ''
        detector = str(component.get('AnalysisComponentType', 'AMiner'))
        description = str(component.get('Message', component.get('AnalysisComponentName', detector)))
        training = bool(component.get('TrainingMode'))
        level = 0
    else:
        stamp = datetime.fromisoformat(obj['@timestamp'].replace('Z', '+00:00')).timestamp()
        raw = str(obj.get('full_log') or '')
        location = str(obj.get('location', ''))
        alert = data.get('alert') or {}
        detector = 'Wazuh ' + str(rule.get('id', 'unknown'))
        description = str(alert.get('signature') or rule.get('description', 'Wazuh alert'))
        training = False
        level = int(rule.get('level') or 0)
        if not raw:  # Suricata EVE exports often lack full_log entirely.
            raw = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    host = str(pre.get('hostname') or '')
    host_basis = 'record hostname' if host else ''
    if not host:
        m = re.match(r'\w{3}\s+\d+\s+[\d:]+\s+([\w.-]+)\s+', raw)
        if m:
            host, host_basis = m.group(1), 'syslog hostname'
        else:
            resources = location.lower()
            if 'intranet' in resources:
                host, host_basis = 'intranet-server', 'inferred from log path'
            elif 'cloud' in resources:
                host, host_basis = 'cloud-share', 'inferred from log path'
    source_ip = valid_ip(data.get('src_ip') or data.get('srcip'))
    destination_ip = valid_ip(data.get('dest_ip') or data.get('dstip'))
    if not source_ip:
        m = re.match(r'([\d.]+)\s+\S+\s+\S+\s+\[', raw)
        if not m:
            m = re.search(r'(?i)(?:from|rhost=)\s*([\d.]+)', raw)
        source_ip = valid_ip(m.group(1)) if m else ''
    http = data.get('http') or {}
    url = str(http.get('url') or '')
    if not url:
        m = re.search(r'\"(?:GET|POST|HEAD|PUT|OPTIONS|DELETE)\s+(\S+)\s+HTTP/', raw)
        url = m.group(1) if m else ''
    status = http.get('status')
    if not status:
        m = re.search(r'HTTP/[\d.]+\"\s+(\d{3})', raw)
        status = int(m.group(1)) if m else 0
    path = urlsplit(url).path[:400] if url else ''
    payload = re.search(r'(?:[?&])(wp_meta|cmd|command|exec)=([^\s\"&]+)', raw + ' ' + url)
    fields = structural_fields(data, raw, url)
    # The sensor address is kept separate from observed endpoints.
    sensor = str((obj.get('agent') or {}).get('ip') or (obj.get('AMiner') or {}).get('ID') or '')
    evidence_key = hashlib.sha1((str(stamp) + host + raw).encode()).hexdigest()[:20]
    return {
        'id': filename.rsplit('_', 1)[0] + ':' + ('a' if aminer else 'w') + ':' + str(line),
        'scenario': filename.rsplit('_', 1)[0],
        'timestamp': stamp,
        'time': datetime.fromtimestamp(stamp, timezone.utc).isoformat().replace('+00:00', 'Z'),
        'source': 'AMiner' if aminer else 'Wazuh', 'file': filename, 'line': line,
        'host': host or destination_ip or 'unresolved host',
        'host_basis': host_basis or ('observed destination IP' if destination_ip else 'unresolved'),
        'src': source_ip, 'dst': destination_ip, 'sensor': sensor,
        'detector': detector, 'description': safe_text(description), 'training': training,
        'level': level, 'raw': safe_text(raw), 'location': location,
        'path': path, 'status': int(status or 0),
        '_payload': '?' + payload.group(1) + '=' + payload.group(2)[:16384] if payload else '',
        'evidence_hash': hashlib.sha256(raw.encode()).hexdigest(),
        'rule_id': str(rule.get('id') or ''),
        'evidence_key': evidence_key,
        **fields,
    }


def normalize_external(obj, scenario, filename, line):
    """Native EVE or documented JSONL contract, preserving external line references."""
    stamp = obj.get('timestamp')
    if isinstance(stamp, (int, float)):
        stamp = datetime.fromtimestamp(stamp, timezone.utc).isoformat()
    if not isinstance(stamp, str):
        raise ValueError('External telemetry requires an explicit timestamp')
    native = {'@timestamp': stamp, 'data': obj, 'full_log': str(obj.get('raw') or ''),
              'predecoder': {'hostname': str(obj.get('host') or '')},
              'rule': {'id': 'external', 'level': 0, 'description': str(obj.get('event_type') or 'raw telemetry')}}
    event = normalize(native, scenario + '_wazuh.json', line)
    event.update(id=f'{scenario}:n:{line}', source='Telemetry', file=filename,
                 detector='External ' + str(obj.get('event_type') or 'telemetry'), training=bool(obj.get('training')))
    event['origin_file'] = str(obj.get('origin_file') or filename)
    event['origin_line'] = number(obj.get('origin_line')) or line
    event['origin_hash'] = str(obj.get('origin_hash') or '')
    if obj.get('host_basis'):
        event['host_basis'] = str(obj['host_basis'])
    return event
