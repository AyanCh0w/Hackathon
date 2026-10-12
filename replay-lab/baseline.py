"""Frozen pre-improvement classifier, for paired regression comparisons only."""
import re
from telemetry import payload_features as current_features

def payload_features(raw):
    # Preserve the original wp_meta JSON/base64 and IPv4 /dev/tcp behavior.
    import base64, json
    from urllib.parse import unquote_plus
    from telemetry import valid_ip
    out = {"encoded_command": False, "callback": "", "shell_command": False}
    m = re.search(r'(?:[?&])wp_meta=([^\s\"&]+)', raw)
    if not m: return out
    try:
        encoded=unquote_plus(m[1])[:16384]
        decoded=base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True).decode("utf-8", errors="replace")
        if len(decoded)>12000: return out
        content=json.loads(decoded)
        commands=" ".join(content) if isinstance(content,list) and all(isinstance(x,str) for x in content) else json.dumps(content) if isinstance(content,dict) else decoded
        out["encoded_command"]=True
        out["shell_command"]=bool(re.search(r"(?i)\b(?:bash|sh|mysql|chmod|curl|wget|whoami|cat)\b", commands))
        callback=re.search(r"/dev/tcp/([\d.]+)/([\d]+)",commands)
        if callback and valid_ip(callback[1]):out["callback"]=callback[1]+":"+callback[2]
    except (ValueError,UnicodeError,json.JSONDecodeError):pass
    return out

def classify(e):
    if not e.get('_payload') and e['path'] and e['status'] in (400, 401, 403, 404):
        return 'web', 'low', 'Unsuccessful / scanner-like HTTP request; escalation requires repeated distinct evidence.'
    if e['source'] == 'Wazuh' and e['description'] in ('ClamAV database update', 'Dovecot Authentication Success.') and e['level'] < 10:
        return 'background', 'low', 'Routine sensor event; no attack attribution.'
    text = (e['raw'] + ' ' + e['description']).lower()
    path, features = e['path'].lower(), payload_features(e.get('_payload', ''))
    if features['callback']:
        return 'callback', 'high', 'Encoded request contains /dev/tcp callback endpoint. Request observed; execution unproven.'
    if features['encoded_command'] and features['shell_command'] and path.endswith('.php'):
        return 'execution', 'high', 'PHP request carries an encoded command list. Content inspected as data; never executed.'
    if ('successful su for' in text and 'by www-data' in text) or re.search(r'su(?:\[\d+\])?:\s+\(to\s+\S+\)\s+www-data', text):
        return 'privilege', 'high', 'Observed successful identity transition involving the web-service account.'
    if re.search(r'sudo.*(?:user=root|session opened for user root)', text) or ('exe="/bin/su"' in text and 'uid=33' in text and 'res=success' in text):
        return 'privilege', 'medium', 'Successful privileged transition is present in authentication / audit evidence.'
    if 'service_stop' in text or re.search(r'(?:stopped|stopping)\s+(?:apache|nginx|ssh|dns|bind|cron|clam|dovecot)', text):
        return 'service', 'medium', 'Explicit service stop / stopping record. Operational intent is unknown.'
    if 'query[txt]' in text:
        domain = re.search(r'query\[txt\]\s+(\S+)', text)
        if domain and (len(domain.group(1)) >= 80 or max(map(len, domain.group(1).split('.'))) >= 45):
            return 'dns', 'low', 'Long TXT-query name. Length is an anomaly signal, not proof of exfiltration.'
    if any(token in text for token in ('nmap', 'portscan', 'port scan', 'did not receive identification string', 'masscan')):
        return 'recon', 'medium', 'Scan signature or incomplete SSH identification exchange observed.'
    if path and (e['status'] in (400, 401, 403, 404) or any(token in text for token in ('wpscan', 'dirbuster', 'sql injection', 'directory traversal'))):
        return 'web', 'low', 'Unsuccessful / scanner-like HTTP request; escalation requires repeated distinct evidence.'
    if any(token in text for token in ('sql injection', 'directory traversal', 'web application attack', 'web attack', 'shellcode', 'exploit kit')):
        return 'web', 'medium', 'Existing sensor signature flags potentially hostile application traffic.'
    if e['training']:
        return 'background', 'low', 'AMiner training-mode observation; retained separately from operational evidence.'
    if e['source'] == 'AMiner':
        return 'anomaly', 'low', 'AMiner detector reported a deviation; no attack interpretation inferred.'
    if e['level'] >= 10:
        return 'anomaly', 'medium', 'High-level sensor alert without a more specific supported rule.'
    return 'background', 'low', 'Routine or insufficiently specific alert; no attack attribution.'

