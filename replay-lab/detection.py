"""Versioned hypotheses and bounded causal behavioral detectors. No labels or models."""
from collections import Counter, OrderedDict, deque
import math
import re

RULES_VERSION = '2026-10-12.6'
# Thresholds are engineering starting points, not calibrated deployment operating points.
RULES = {
    'scan.signature': {'family': 'recon', 'condition': 'explicit scan signature', 'counterexample': 'approved vulnerability scanner'},
    'ssh.identification': {'family': 'recon', 'condition': 'incomplete SSH identification exchange', 'counterexample': 'client disconnect or health check'},
    'scan.ssh_identification': {'family': 'recon', 'condition': '>=10 distinct incomplete SSH identification exchanges in 5m from one observed source/host', 'counterexample': 'misconfigured client or repeated health checks'},
    'scan.fanout': {'family': 'recon', 'condition': '>=20 distinct destination ports OR >=12 destination hosts in 60s, >=20 distinct connections', 'counterexample': 'monitoring, service discovery, approved scanning'},
    'scan.slow': {'family': 'recon', 'condition': '>=40 distinct destination ports OR >=25 destination hosts in 15m, >=40 distinct connections', 'counterexample': 'batch monitoring or approved scanning'},
    'scan.rejected_ports': {'family': 'recon', 'condition': '>=10 distinct TCP destination ports on one destination in 60s with explicit REJECT/DROP SYN records or REJ flow outcomes', 'counterexample': 'approved service checks, authorized scan, or broken firewall policy'},
    'dns.lexical': {'family': 'dns', 'condition': 'name >=80 chars or label >=45 chars; all query types', 'counterexample': 'DKIM, anti-abuse and CDN names'},
    'dns.sequence': {'family': 'dns', 'condition': '>=12 distinct names per client/suffix in 5m AND mean label entropy >=3.5 AND mean longest label >=25', 'counterexample': 'telemetry SDK or anti-abuse DNS'},
    'dns.slow': {'family': 'dns', 'condition': '>=30 distinct names per client/suffix in 1h AND mean label entropy >=3.5 AND mean longest label >=25', 'counterexample': 'legitimate device telemetry'},
    'auth.failures': {'family': 'cracking', 'condition': '>=10 distinct authentication failures in 5m from one observed source/host', 'counterexample': 'misconfigured client or forgotten password'},
    'auth.spray': {'family': 'cracking', 'condition': '>=20 distinct failures targeting >=10 accounts in 15m from one source/host', 'counterexample': 'broken account migration'},
    'cracking.tool': {'family': 'cracking', 'condition': 'john/hashcat/hydra/medusa/ncrack or wphashcrack.sh wrapper in inspected command/process', 'counterexample': 'authorized password audit'},
    'callback.command': {'family': 'callback', 'condition': 'callback construct in command parameter or process command', 'counterexample': 'authorized diagnostic shell'},
    'web.command': {'family': 'execution', 'condition': 'PHP request with recognized shell command parameter', 'counterexample': 'administrative endpoint; execution unproven'},
    'web.probing': {'family': 'web', 'condition': 'unsuccessful HTTP request or sensor web signature', 'counterexample': 'broken links or legitimate client errors'},
    'privilege.transition': {'family': 'privilege', 'condition': 'observed successful web-account su or sudo/root transition', 'counterexample': 'authorized administration'},
    'service.stop': {'family': 'service', 'condition': 'explicit service stop record', 'counterexample': 'scheduled maintenance or restart'},
    'sensor.anomaly': {'family': 'anomaly', 'condition': 'generic detector anomaly', 'counterexample': 'benign novelty; no technique attribution'},
    'routine': {'family': 'background', 'condition': 'no supported technique-specific rule', 'counterexample': 'unobserved attack'},
}
for rule in RULES.values():
    rule['version'] = RULES_VERSION
    rule['status'] = 'experimental; thresholds uncalibrated'
    rule['provenance'] = 'Transparent local rules; adaptation rather than reproduction of research results.'
    rule['research'] = ['https://arxiv.org/abs/2610.03999']


def entropy(value):
    if not value:
        return 0.0
    size = len(value)
    return -sum((count / size) * math.log2(count / size) for count in Counter(value).values())


class Window:
    """Bounded distinct-event window. Repeated exports cannot inflate counters."""
    def __init__(self, seconds, limit=4096):
        self.seconds, self.limit = seconds, limit
        self.rows = deque()
        self.seen = set()
        self.counts = [Counter(), Counter()]
        self.totals = [0.0, 0.0]

    def track(self, value, delta):
        for index, item in enumerate(value if isinstance(value, tuple) else (value,)):
            self.counts[index][item] += delta
            if self.counts[index][item] == 0:
                del self.counts[index][item]
            if isinstance(item, (int, float)):
                self.totals[index] += item * delta

    def add(self, stamp, key, value):
        while self.rows and self.rows[0][0] < stamp - self.seconds:
            _, previous, previous_value = self.rows.popleft()
            self.seen.discard(previous)
            self.track(previous_value, -1)
        if key not in self.seen:
            if len(self.rows) >= self.limit:
                _, previous, previous_value = self.rows.popleft()
                self.seen.discard(previous)
                self.track(previous_value, -1)
            self.rows.append((stamp, key, value))
            self.seen.add(key)
            self.track(value, 1)
        return self.rows


class BehavioralDetectors:
    def __init__(self, max_entities=4096):
        self.windows = OrderedDict()
        self.max_entities = max_entities

    def window(self, key, seconds):
        key = (*key, seconds)
        window = self.windows.pop(key, None)
        if window is None:
            window = Window(seconds)
        self.windows[key] = window
        if len(self.windows) > self.max_entities:
            self.windows.popitem(last=False)
        return window

    def observe(self, e):
        if e['training']:
            return None
        stamp, scenario, actor = e['timestamp'], e['scenario'], e['src']
        if actor and e['host'] != 'unresolved host' and 'did not receive identification string' in (e['raw'] + ' ' + e['description']).lower():
            window = self.window(('ssh-identification', scenario, actor, e['host']), 300)
            rows = window.add(stamp, e['evidence_key'], '')
            if len(rows) >= 10:
                return 'recon', 'medium', f'{len(rows)} distinct incomplete SSH identification exchanges within 5 minutes; misconfigured clients or health checks remain possible.', 'scan.ssh_identification'
        rejected = e.get('flow_state') == 'REJ' or bool(re.search(r'\b(?:REJECT|DROP)\b.*\bPROTO=TCP\b.*\bSYN\b', e['raw']))
        if actor and e.get('dst') and e.get('dst_port') and e.get('protocol') == 'TCP' and rejected:
            window = self.window(('rejected', scenario, actor, e['dst']), 60)
            window.add(stamp, e.get('flow_id') or e['evidence_key'], e['dst_port'])
            if len(window.counts[0]) >= 10:
                return 'recon', 'medium', f'Explicit TCP failures on {len(window.counts[0])} distinct ports to {e["dst"]} within 60s; approved checks or firewall policy errors remain possible.', 'scan.rejected_ports'
        if actor and e.get('dst') and e.get('capabilities', 0) & 1:
            # Flow identity is preferred over detector-specific event IDs.
            key = e.get('flow_id') or e['evidence_key']
            for seconds, ports, hosts, count, rule in ((60, 20, 12, 20, 'scan.fanout'), (900, 40, 25, 40, 'scan.slow')):
                window = self.window(('flow', scenario, actor), seconds)
                rows = window.add(stamp, key, (e['dst'], e['dst_port']))
                observed_ports=len(window.counts[1])-int(0 in window.counts[1])
                if len(rows) >= count and (observed_ports >= ports or len(window.counts[0]) >= hosts):
                    return 'recon', 'medium', f'{len(rows)} distinct observed connections across {observed_ports} ports / {len(window.counts[0])} destinations within {seconds}s; approved scanning remains possible.', rule
        if actor and e.get('auth_failed') and e['host'] != 'unresolved host':
            for seconds, count, users, rule in ((900, 20, 10, 'auth.spray'), (300, 10, 1, 'auth.failures')):
                window = self.window(('auth', scenario, actor, e['host']), seconds)
                rows = window.add(stamp, e['evidence_key'], e.get('user', ''))
                if len(rows) >= count and len(window.counts[0]) - int('' in window.counts[0]) >= users:
                    return 'cracking', 'medium', f'{len(rows)} distinct authentication failures within {seconds}s; intent and compromise unconfirmed.', rule
        for query in e.get('dns_queries', []):
            name = query['name']
            labels = name.split('.')
            longest = max(labels, key=len, default='')
            # Two-label suffix is an explicit heuristic, not Public Suffix List resolution.
            suffix = '.'.join(labels[-2:])
            if actor and name:
                for seconds, count, rule in ((300, 12, 'dns.sequence'), (3600, 30, 'dns.slow')):
                    window = self.window(('dns', scenario, actor, suffix), seconds)
                    rows = window.add(stamp, name, (len(longest), entropy(longest)))
                    if len(rows) >= count and window.totals[0] / len(rows) >= 25 and window.totals[1] / len(rows) >= 3.5:
                        return 'dns', 'medium', f'{len(rows)} distinct DNS names within {seconds}s for suffix {suffix}; mean label length {window.totals[0]/len(rows):.1f}, entropy {window.totals[1]/len(rows):.2f}. Exfiltration unproven; suffix uses a two-label heuristic.', rule
        return None
