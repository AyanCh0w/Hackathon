"""Causal, deterministic online correlation over observed alert exports only."""
from __future__ import annotations

import copy
import hashlib
import re
import time
from collections import Counter, deque
from telemetry import payload_features, process_features
from investigation import public_record
from detection import BehavioralDetectors, RULES, RULES_VERSION, entropy

FAMILIES = {
    'background': ('Routine / background', 0),
    'anomaly': ('Detector anomaly', 1),
    'recon': ('Reconnaissance signal', 2),
    'web': ('Web probing', 3),
    'execution': ('Command-bearing web request', 4),
    'callback': ('Shell callback request', 5),
    'privilege': ('Privilege transition', 6),
    'service': ('Service state change', 7),
    'dns': ('DNS anomaly', 8),
    'cracking': ('Credential attack signal', 9),
}

PRIORITIES = ('high', 'investigate', 'context', 'routine')


def importance(group):
    """Review urgency from evidence seen so far, independent of labels and volume."""
    family, confidence = group['family'], group['confidence']
    if group['count'] == group['training']:
        tier, reason = 'routine', 'Training-only observations; no operational evidence in this episode.'
    elif family in ('callback', 'execution') or (family == 'privilege' and confidence == 'high'):
        tier, reason = 'high', 'Command / callback content or a web-account identity transition merits prompt review; success remains unconfirmed.'
    elif (family in ('service', 'privilege') and group.get('corroborated_signal')) or (family in ('cracking', 'recon', 'web', 'dns') and confidence in ('medium', 'high') and group.get('corroborated_signal')):
        tier, reason = 'investigate', 'A supported attack pattern or an operational change linked to a supported attack signal merits investigation.'
    elif family in ('service', 'privilege'):
        tier, reason = 'context', 'An operational change alone is consistent with administration or maintenance; a supported attack signal is required.'
    elif family == 'background':
        tier, reason = 'routine', 'Routine sensor activity without a supported attack signal.'
    else:
        tier, reason = 'context', 'An anomaly or standalone attack signal provides context; corroboration by a different supported behavior is needed for investigation.'
    base = {'high': 90, 'investigate': 60, 'context': 30, 'routine': 0}[tier]
    weight = {'callback': 9, 'execution': 8, 'privilege': 7, 'cracking': 6, 'recon': 5, 'web': 4, 'service': 3, 'dns': 2, 'anomaly': 1, 'background': 0}[family]
    related = len(group.get('related_families', ()))
    if related and tier != 'routine':
        reason += ' Also linked to another rule family by observed entity / time matches; causality is unproven.'
    # Detector repeat volume deliberately contributes nothing to review urgency.
    score = base + (weight if tier != 'routine' else 0) + min(related, 3) * (2 if tier != 'routine' else 0)
    return tier, score, reason


def classify_detail(e):
    if not e.get('_payload') and e['path'] and e['status'] in (400, 401, 403, 404):
        return 'web', 'low', 'Unsuccessful / scanner-like HTTP request; escalation requires repeated distinct evidence.', 'web.probing'
    if e['source'] == 'Wazuh' and e['description'] in ('ClamAV database update', 'Dovecot Authentication Success.') and e['level'] < 10:
        return 'background', 'low', 'Routine sensor event; no attack attribution.', 'routine'
    text = (e['raw'] + ' ' + e['description']).lower()
    path, features = e['path'].lower(), payload_features(e.get('_payload', ''))
    process_commands = process_features(e)
    if features['callback_pattern'] or process_commands['callback_pattern']:
        return 'callback', 'high', 'Observed command contains a shell callback construct; network connection and execution require corroboration.', 'callback.command'
    if features['cracking'] or process_commands['cracking']:
        return 'cracking', 'medium', 'Credential-tool command observed. Password-audit authorization and successful cracking are unknown.', 'cracking.tool'
    if (features['encoded_command'] or features.get('command_parameter')) and features['shell_command'] and path.endswith('.php'):
        return 'execution', 'high', 'PHP request carries a recognized command parameter. Execution remains unproven.', 'web.command'
    if ('successful su for' in text and 'by www-data' in text) or re.search(r'su(?:\[\d+\])?:\s+\(to\s+\S+\)\s+www-data', text):
        return 'privilege', 'high', 'Observed successful identity transition involving the web-service account.', 'privilege.transition'
    if re.search(r'sudo.*(?:user=root|session opened for user root)', text) or ('exe="/bin/su"' in text and 'uid=33' in text and 'res=success' in text):
        return 'privilege', 'medium', 'Successful privileged transition is present in authentication / audit evidence.', 'privilege.transition'
    if 'service_stop' in text or re.search(r'(?:stopped|stopping)\s+(?:apache|nginx|ssh|dns|bind|cron|clam|dovecot)', text):
        return 'service', 'medium', 'Explicit service stop / stopping record. Operational intent is unknown.', 'service.stop'
    for query in e.get('dns_queries', []):
        domain = query['name']
        labels = domain.split('.')[:-2]
        if any((len(label) >= 24 and entropy(label) >= 3.5 and label.isalnum() and any(c.isdigit() for c in label)) or (len(label) >= 32 and re.fullmatch(r'[0-9a-f]+', label)) for label in labels):
            return 'dns', 'low', 'Encoded-looking DNS subdomain label; CDN identifiers and telemetry remain possible.', 'dns.encoded'
        if len(domain) >= 80 or max(map(len, domain.split('.')), default=0) >= 45:
            return 'dns', 'low', 'Long DNS query name. Length is an anomaly signal, not proof of exfiltration.', 'dns.lexical'
    if any(token in text for token in ('nmap', 'portscan', 'port scan', 'masscan')):
        return 'recon', 'medium', 'Explicit scan signature observed; authorization remains unknown.', 'scan.signature'
    if 'did not receive identification string' in text:
        return 'recon', 'low', 'Isolated incomplete SSH identification exchange; a client disconnect or health check is possible.', 'ssh.identification'
    if path and (e['status'] in (400, 401, 403, 404) or any(token in text for token in ('wpscan', 'dirbuster', 'sql injection', 'directory traversal'))):
        return 'web', 'low', 'Unsuccessful / scanner-like HTTP request; escalation requires repeated distinct evidence.', 'web.probing'
    if any(token in text for token in ('sql injection', 'directory traversal', 'web application attack', 'web attack', 'shellcode', 'exploit kit')):
        return 'web', 'medium', 'Existing sensor signature flags potentially hostile application traffic.', 'web.probing'
    if e['training']:
        return 'background', 'low', 'AMiner training-mode observation; retained separately from operational evidence.', 'routine'
    if e['source'] == 'AMiner':
        return 'anomaly', 'low', 'AMiner detector reported a deviation; no attack interpretation inferred.', 'sensor.anomaly'
    if e['level'] >= 10:
        return 'anomaly', 'medium', 'High-level sensor alert without a more specific supported rule.', 'sensor.anomaly'
    return 'background', 'low', 'Routine or insufficiently specific alert; no attack attribution.', 'routine'


def classify(e):
    return classify_detail(e)[:3]


class OnlineEngine:
    def __init__(self):
        self.processed = 0
        self.training = 0
        self.sources = Counter()
        self.categories = Counter()
        self.groups = {}
        self.focus_groups = set()
        self.recent_groups = deque(maxlen=500)
        self.group_lookup = {}
        self.edges = {}
        from incident_workflow import EntityLinks
        self.entity_links = EntityLinks()
        self.suppressions = None
        self.host_groups = {}
        self.recent = deque(maxlen=220)
        self.history = deque(maxlen=240)
        self.signal_history = deque(maxlen=240)
        self.dataset_history = {}
        self.dataset_signal_history = {}
        self.timeline = []  # Frozen classification outcomes used only by end-of-run verification.
        self.stages = {name: {'count': 0, 'ms': 0, 'last': None} for name in ('normalize', 'classify', 'group', 'connect')}
        self.history_seq = 0
        self.priority_counts = Counter()
        self.dataset_priority_counts = {}
        self.priority_representatives = {}
        self.behavior = BehavioralDetectors()
        self.priority_observer = None
        self.current_event = None

    def rank_group(self, group):
        tier, score, reason = importance(group)
        previous = group.get('priority')
        counts = self.dataset_priority_counts.setdefault(group['scenario'], Counter())
        if previous != tier:
            if self.priority_observer and tier in ('high', 'investigate'):
                self.priority_observer(group, self.current_event)
            if previous:
                self.priority_counts[previous] -= 1
                counts[previous] -= 1
            self.priority_counts[tier] += 1
            counts[tier] += 1
            self.priority_representatives.setdefault((group['scenario'], tier), deque(maxlen=12)).append(group['id'])
        group.update(priority=tier, priority_score=score, priority_reason=reason)

    def audit(self, stage, e, detail, group=None):
        self.history_seq += 1
        entry = {'id': self.history_seq, 'stage': stage, 'time': e['time'],
                             'event': e['id'], 'detail': detail, 'group': group,
                             'processed': self.processed, 'wall': time.time(),
                             'scenario': e['scenario'],
                             'replay_elapsed': round(e.get('_replay_elapsed', 0), 3)}
        self.history.append(entry)
        self.dataset_history.setdefault(e['scenario'], deque(maxlen=80)).append(entry)
        if group and self.groups[group]['family'] not in ('background', 'anomaly'):
            self.signal_history.append(entry)
            self.dataset_signal_history.setdefault(e['scenario'], deque(maxlen=120)).append(entry)

    def ingest(self, e):
        self.current_event = e
        self.processed += 1
        self.sources[e['source']] += 1
        self.training += int(e['training'])
        start = time.perf_counter()
        family, confidence, reason, rule_id = classify_detail(e)
        behavior = self.behavior.observe(e)
        if behavior and family in ('background', 'anomaly', 'dns', 'recon'):
            family, confidence, reason, rule_id = behavior
        if e['training'] and family != 'background':
            confidence = 'low'
            reason += ' Training mode: candidate only.'
        self.stages['classify']['ms'] += (time.perf_counter() - start) * 1000
        self.stages['classify']['count'] += 1
        self.stages['classify']['last'] = e['time']
        self.categories[family] += 1
        start = time.perf_counter()
        actor = e['src'] or 'unknown actor'
        host_identity = e['host'] if e['host'] != 'unresolved host' else 'unresolved:' + e['sensor'] + ':' + e['location']
        host_identity = e['scenario'] + ':' + host_identity
        key = (e['scenario'], family, actor, host_identity)
        previous = self.group_lookup.get(key)
        # Close an episode after 30 minutes of event-time inactivity.
        new = previous is None or e['timestamp'] - self.groups[previous]['last_ts'] > 1800
        if new:
            gid = 'g' + str(len(self.groups) + 1)
            group = {
                'id': gid, 'scenario': e['scenario'], 'family': family, 'title': FAMILIES[family][0], 'actor': actor,
                'host': e['host'], 'host_basis': e['host_basis'], 'count': 0, 'unique': 0,
                'first': e['time'], 'last': e['time'], 'first_ts': e['timestamp'],
                'last_ts': e['timestamp'], 'confidence': confidence, 'reason': reason,
                'training': 0, 'detectors': Counter(), 'evidence': [], 'keys': set(),
                'paths': set(), 'rate_elevated': False, 'operational_unique': 0,
                'related_families': set(), 'connections': 0, 'corroborated_signal': False,
                'rules': Counter(), 'operational_keys': set(), 'web_window': deque(maxlen=4096),
                'context_counts': {key: Counter() for key in ('src', 'dst', 'user', 'sensor', 'location', 'source', 'description')},
            }
            self.groups[gid] = group
            self.recent_groups.append(gid)
            if family not in ('background', 'anomaly'):
                self.focus_groups.add(gid)
            self.group_lookup[key] = gid
            self.host_groups.setdefault(host_identity, []).append(gid)
        else:
            gid = previous
            group = self.groups[gid]
        if not e['training']:
            group['latest_operational_alert'] = e['id']
        previous_confidence = group['confidence']
        first_operational = not e['training'] and group['count'] == group['training']
        group['count'] += 1
        group['last'], group['last_ts'] = e['time'], e['timestamp']
        group['training'] += int(e['training'])
        group['detectors'][e['detector']] += 1
        group['rules'][rule_id] += 1
        for key, counts in group['context_counts'].items():
            value = e.get(key) or (e.get('origin_file') if key == 'location' else '')
            if value:
                counts[value] += 1
        if first_operational or (not e['training'] and {'low': 0, 'medium': 1, 'high': 2}[confidence] > {'low': 0, 'medium': 1, 'high': 2}[group['confidence']]):
            group['confidence'], group['reason'] = confidence, reason
        unique = e['evidence_key'] not in group['keys']
        if unique:
            group['keys'].add(e['evidence_key'])
            group['unique'] += 1
            if e['path']:
                group['paths'].add(e['path'])
        if unique or first_operational:
            example = public_record(e)
            example.update({'rule': rule_id, 'capabilities': e.get('capabilities', 0)})
            example.update({key:e[key] for key in ('origin_file','origin_line','origin_hash') if key in e})
            if len(group['evidence']) < 7:
                group['evidence'].append(example)
            elif first_operational or family in ('execution', 'callback', 'privilege', 'service', 'dns', 'cracking'):
                group['evidence'][-1] = example
        operational_new = not e['training'] and e['evidence_key'] not in group['operational_keys']
        if operational_new:
            group['operational_keys'].add(e['evidence_key'])
            group['operational_unique'] += 1
            if family == 'web' and not group['rate_elevated']:
                group['web_window'].append((e['timestamp'], e['path']))
        while group['web_window'] and group['web_window'][0][0] < e['timestamp'] - 180:
            group['web_window'].popleft()
        elevated = family == 'web' and not group['rate_elevated'] and len(group['web_window']) >= 25 and len({row[1] for row in group['web_window'] if row[1]}) >= 12
        if elevated:
            group['web_window'].clear()
            group['rate_elevated'] = True
            group['confidence'] = 'medium'
            group['reason'] = 'At least 25 distinct requests across 12 paths within 3 minutes; burst probing candidate.'
        if new or elevated or first_operational or previous_confidence != group['confidence']:
            old_priority = group.get('priority')
            self.rank_group(group)
            if old_priority and old_priority != group['priority']:
                self.audit('group', e, f"Review priority changed from {old_priority} to {group['priority']}: {group['priority_reason']}", gid)
        self.stages['group']['count'] += 1
        self.stages['group']['ms'] += (time.perf_counter() - start) * 1000
        self.stages['group']['last'] = e['time']
        if new and family != 'background':
            self.audit('classify', e, reason, gid)
            self.audit('group', e, f"Opened {group['title']} episode on {e['host']} from {actor}.", gid)
        if elevated:
            self.audit('classify', e, group['reason'], gid)
        start = time.perf_counter()
        # An edge is a time-bounded evidence relationship, never asserted causality.
        if family not in ('background', 'anomaly') and e['host'] != 'unresolved host' and not e['training'] and (new or group['operational_unique'] == 1 or elevated):
            for other_id in self.host_groups[host_identity][-100:]:
                other = self.groups[other_id]
                if other_id == gid or other['family'] in ('background', 'anomaly') or other['operational_unique'] == 0:
                    continue
                gap = e['timestamp'] - other['last_ts']
                if not 0 <= gap <= 900 or other['first_ts'] > e['timestamp']:
                    continue
                same_actor = actor != 'unknown actor' and actor == other['actor']
                if not same_actor and family not in ('privilege', 'service'):
                    continue
                edge_key = tuple(sorted((gid, other_id), key=lambda x: int(x[1:])))
                if edge_key not in self.edges:
                    basis = 'same observed source and host within 15 min' if same_actor else 'same host within 15 min; actor continuity unproven'
                    self.edges[edge_key] = {'id': '|'.join(edge_key), 'from': other_id, 'to': gid, 'basis': basis,
                                            'time': e['time'], 'confidence': 'medium' if same_actor else 'low',
                                            'relationship': 'inferred', 'evidence_ids': [other['latest_operational_alert'], e['id']],
                                            'confirmed_evidence': [{'field': 'host', 'value': e['host'],
                                                'evidence_ids': [other['latest_operational_alert'], e['id']]}]}
                    for current, related_group in ((group, other), (other, group)):
                        current['connections'] += 1
                        if current['family'] != related_group['family'] and (related_group['family'] in ('execution', 'callback') or
                                (same_actor and related_group['family'] in ('recon', 'web', 'dns', 'cracking')
                                 and related_group['confidence'] in ('medium', 'high'))):
                            current['corroborated_signal'] = True
                        if current['family'] != related_group['family']:
                            current['related_families'].add(related_group['family'])
                        self.rank_group(current)
                    self.audit('connect', e, f"Connected {other['title']} → {group['title']}: {basis}.", gid)
        # A previously contextual neighbor can become supported as its window fills.
        if elevated or previous_confidence != group['confidence']:
            for edge in self.edges.values():
                if gid not in (edge['from'], edge['to']):
                    continue
                other = self.groups[edge['to'] if edge['from'] == gid else edge['from']]
                if (other['family'] != group['family'] and group['operational_unique'] and group['confidence'] in ('medium', 'high') and
                        group['family'] in ('recon', 'web', 'dns', 'cracking', 'execution', 'callback') and
                        (edge['confidence'] == 'medium' or group['family'] in ('execution', 'callback')) and
                        0 <= e['timestamp'] - other['last_ts'] <= 900):
                    other['corroborated_signal'] = True
                    self.rank_group(other)
        self.entity_links.observe(self, e, group)
        self.stages['connect']['count'] += 1
        self.stages['connect']['ms'] += (time.perf_counter() - start) * 1000
        self.stages['connect']['last'] = e['time']
        logrow = {k: e[k] for k in ('id', 'scenario', 'timestamp', 'time', 'source', 'host', 'src', 'description', 'raw', 'file', 'line', 'training')}
        logrow.update({k: e.get(k, '') for k in ('dst', 'sensor', 'location', 'host_basis', 'evidence_hash')})
        if self.behavior.last_metrics:
            logrow['behavior_metrics'] = dict(self.behavior.last_metrics)
        logrow.update({'family': family, 'confidence': confidence, 'reason': reason, 'group': gid})
        self.recent.append(logrow)
        self.timeline.append((e['timestamp'], family, gid, e['training'], e['scenario'], e.get('capabilities', 0), rule_id, e['id']))
        return logrow

    def public_group(self, group):
        out = {k: v for k, v in group.items() if k not in ('keys', 'operational_keys', 'web_window', 'paths', 'detectors', 'rules', 'evidence', 'related_families', 'context_counts')}
        if self.suppressions:
            out['suppression'] = self.suppressions.status(group, self.groups.values())
            if out['suppression'].get('reopened') and group['priority'] not in ('high', 'investigate'):
                out['detection_priority'] = group['priority']
                out['priority'] = 'investigate'
                out['priority_score'] = 200
                out['priority_reason'] = out['suppression']['reason']
        out['context'] = {key: {'values': [{'value': value, 'records': count} for value, count in counts.most_common(12)],
                               'total_values': len(counts)} for key, counts in group['context_counts'].items()}
        duration = max(0, group['last_ts'] - group['first_ts'])
        out['frequency'] = {'duration_seconds': duration, 'repeated_records': group['count'] - group['unique'],
                            'records_per_minute': group['count'] * 60 / duration if duration else None,
                            'distinct_per_minute': group['unique'] * 60 / duration if duration else None}
        out['related_families'] = sorted(group['related_families'])
        out['paths'] = len(group['paths'])
        out['detectors'] = dict(group['detectors'])
        out['evidence'] = group['evidence']
        out['rules'] = {key: {'records': count, **RULES[key]} for key, count in group['rules'].items()}
        return out

    def candidates(self):
        result = []
        adjacency = {}
        for edge in self.edges.values():
            adjacency.setdefault(edge['from'], set()).add(edge['to'])
            adjacency.setdefault(edge['to'], set()).add(edge['from'])
        visited = set()
        for gid in adjacency:
            if gid in visited:
                continue
            pending, ids = [gid], []
            while pending:
                current = pending.pop()
                if current in visited:
                    continue
                visited.add(current)
                ids.append(current)
                pending.extend(adjacency.get(current, []))
            families = set(self.groups[x]['family'] for x in ids)
            if len(families) >= 2:
                result.append({'id': min(ids, key=lambda x: int(x[1:])), 'groups': ids,
                               'scenario': self.groups[ids[0]]['scenario'], 'host': self.groups[ids[0]]['host'], 'families': sorted(families, key=lambda f: FAMILIES[f][1]),
                               'priority': 'high' if families & {'callback', 'execution', 'privilege', 'cracking'} else 'medium',
                               'status': 'candidate; execution / intent not confirmed'})
        return result

    def review_queue(self):
        """One review item per connected set of actionable episodes."""
        actionable = {gid for gid, g in self.groups.items() if g['priority'] in ('high', 'investigate')}
        adjacency = {gid: set() for gid in actionable}
        for edge in self.edges.values():
            a, b = edge['from'], edge['to']
            if a in actionable and b in actionable and (edge['confidence'] == 'medium' or
                    self.groups[a]['family'] in ('execution', 'callback') or
                    self.groups[b]['family'] in ('execution', 'callback')):
                adjacency[a].add(b)
                adjacency[b].add(a)
        visited, result = set(), []
        for gid in sorted(actionable, key=lambda x: int(x[1:])):
            if gid in visited:
                continue
            pending, ids = [gid], []
            while pending:
                current = pending.pop()
                if current in visited:
                    continue
                visited.add(current)
                ids.append(current)
                pending.extend(adjacency[current] - visited)
            representative = min(ids, key=lambda x: (-self.groups[x]['priority_score'], -self.groups[x]['last_ts'], int(x[1:])))
            result.append({'id': gid, 'representative': representative, 'groups': sorted(ids, key=lambda x: int(x[1:])),
                           'scenario': self.groups[gid]['scenario'], 'priority': self.groups[representative]['priority']})
        return result

    def snapshot(self, include_logs=True):
        queue = self.review_queue()
        pool = self.focus_groups | set(self.recent_groups)
        pool.update(item['representative'] for item in queue)
        for ids in self.priority_representatives.values():
            pool.update(ids)
        groups = sorted((self.groups[gid] for gid in pool), key=lambda g: (
            -g['priority_score'], -g['last_ts'], int(g['id'][1:])))
        visible_by_id = {g['id']: g for g in groups[:100]}
        # One pass keeps every dataset and tier represented without rescanning the pool.
        scenario_shown, tier_shown = Counter(), Counter()
        for group in groups:
            scenario, key = group['scenario'], (group['scenario'], group['priority'])
            if scenario_shown[scenario] < 20 or tier_shown[key] < 4:
                visible_by_id[group['id']] = group
            scenario_shown[scenario] += 1
            tier_shown[key] += 1
        for item in queue:
            visible_by_id[item['representative']] = self.groups[item['representative']]
        # Preserve endpoints of actual relationships in the map's available pool.
        for edge in self.edges.values():
            for gid in (edge['from'], edge['to']):
                visible_by_id[gid] = self.groups[gid]
        visible = sorted(visible_by_id.values(), key=lambda g: (-g['priority_score'], -g['last_ts'], int(g['id'][1:])))
        all_history = {entry['id']: entry for entry in self.history}
        all_signals = {entry['id']: entry for entry in self.signal_history}
        for entries in self.dataset_history.values():
            all_history.update({entry['id']: entry for entry in entries})
        for entries in self.dataset_signal_history.values():
            all_signals.update({entry['id']: entry for entry in entries})
        return {'processed': self.processed, 'sources': dict(self.sources), 'categories': dict(self.categories),
                'training': self.training, 'group_count': len(self.groups), 'edge_count': len(self.edges),
                'review_queue': queue, 'review_queue_counts': dict(Counter(item['priority'] for item in queue)),
                'priority_counts': dict(self.priority_counts),
                'dataset_priority_counts': {name: dict(counts) for name, counts in self.dataset_priority_counts.items()},
                'groups': [self.public_group(g) for g in visible], 'edges': list(self.edges.values()),
                'candidates': self.candidates(), 'history': sorted(all_history.values(), key=lambda x: x['id']),
                'signal_history': sorted(all_signals.values(), key=lambda x: x['id']),
                'rules_version': RULES_VERSION,
                'stages': copy.deepcopy(self.stages), 'logs': list(self.recent) if include_logs else []}
