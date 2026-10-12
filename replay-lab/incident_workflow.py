"""Evidence-scoped incident views and durable analyst suppression decisions."""
import json
import time
import uuid
import threading
from pathlib import Path


def incident(engine, gid):
    if gid not in engine.groups:
        raise ValueError('Group not found')
    ids = {gid}
    changed = True
    while changed:
        changed = False
        for edge in engine.edges.values():
            if ids.intersection((edge['from'], edge['to'])):
                before = len(ids)
                ids.update((edge['from'], edge['to']))
                changed |= len(ids) != before
    groups = [engine.public_group(engine.groups[i]) for i in ids]
    timeline = sorted([{'group': g['id'], 'first': g['first'], 'last': g['last'],
                        'technique': g['family'], 'host': g['host'], 'actor': g['actor'],
                        'evidence_ids': [e['id'] for e in g['evidence']],
                        'priority': g['priority'], 'reason': g['priority_reason']} for g in groups],
                      key=lambda x: (x['first'], x['group']))
    return {'groups': groups, 'timeline': timeline,
            'edges': [e for e in engine.edges.values() if e['from'] in ids and e['to'] in ids],
            'scope': 'Connected observed episodes; collection may be incomplete. Links do not prove attack success or causality.'}


class Suppressions:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.rules = json.loads(self.path.read_text()) if self.path.exists() else []

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(self.rules, indent=2))
        temporary.replace(self.path)

    def approve(self, group, analyst, reason, expires):
        now = time.time()
        if not isinstance(analyst, str) or not analyst.strip() or not isinstance(reason, str) or not reason.strip():
            raise ValueError('Analyst name and supporting benign evidence are required')
        if not now < expires <= now + 30 * 86400:
            raise ValueError('Expiry must be in the future and within 30 days')
        if group['actor'] == 'unknown actor' or group['host'] == 'unresolved host' or not group['operational_unique']:
            raise ValueError('Suppression requires an observed actor, host and operational evidence')
        rule = {'id': uuid.uuid4().hex, 'scenario': group['scenario'], 'host': group['host'],
                'actor': group['actor'], 'family': group['family'], 'techniques': sorted(group['rules']),
                'related_families': sorted(group['related_families']),
                'destinations': sorted(group['context_counts']['dst']),
                'evidence_ids': [e['id'] for e in group['evidence']], 'expires': expires, 'active': True,
                'audit': [{'action': 'approved', 'at': now, 'analyst': analyst.strip(), 'reason': reason.strip()}]}
        with self.lock:
            self.rules.append(rule)
            self.save()
        return rule

    def revoke(self, rid, analyst):
        if not isinstance(analyst, str) or not analyst.strip():
            raise ValueError('Analyst name required')
        with self.lock:
            rule = next((r for r in self.rules if r['id'] == rid), None)
            if rule is None:
                raise ValueError('Suppression not found')
            rule['active'] = False
            rule['audit'].append({'action': 'unsuppressed', 'at': time.time(), 'analyst': analyst})
            self.save()
            return rule

    def status(self, group, peers):
        with self.lock:
            for rule in reversed(self.rules):
                if not all(group[k] == rule[k] for k in ('scenario', 'host', 'actor', 'family')):
                    continue
                if not rule['active']:
                    if any(a['action'] == 'reopened' for a in rule['audit']):
                        return {'suppressed': False, 'reopened': True, 'rule': rule['id'], 'reason': 'New evidence requires analyst review'}
                    continue
                if rule['expires'] <= time.time():
                    return {'suppressed': False, 'rule': rule['id'], 'reason': 'Suppression expired'}
                threats = [p for p in peers if p['scenario'] == group['scenario'] and
                           p['operational_unique'] and p['family'] not in ('background', 'anomaly') and
                           abs(group['last_ts'] - p['last_ts']) <= 900 and
                           (p['host'] == group['host'] or (p['actor'] == group['actor'] and p['actor'] != 'unknown actor') or p['actor'] in rule['destinations']) and
                           (p['family'] not in {rule['family'], *rule['related_families']} or
                            (p['host'] != group['host'] and (p['actor'] == group['actor'] or p['actor'] in rule['destinations'])))]
                changed = (set(group['rules']) - set(rule['techniques']) or
                           set(group['related_families']) - set(rule['related_families']) or
                           set(group['context_counts']['dst']) - set(rule['destinations']) or threats)
                if changed:
                    if not any(a['action'] == 'reopened' for a in rule['audit']):
                        rule['audit'].append({'action': 'reopened', 'at': time.time(),
                                              'reason': 'New technique, destination, lateral movement or corroborating evidence',
                                              'evidence_ids': [e['id'] for p in [group, *threats] for e in p['evidence']]})
                        rule['active'] = False
                        self.save()
                    return {'suppressed': False, 'rule': rule['id'], 'reopened': True,
                            'reason': 'New evidence overrides benign suppression; analyst review required'}
                return {'suppressed': True, 'rule': rule['id'], 'reason': 'Analyst approved; active until expiry'}
        return {'suppressed': False}

class EntityLinks:
    """Bounded prefix-only entity joins; observed equality never asserts causality."""
    def __init__(self):
        self.index = {}

    def observe(self, engine, event, group):
        if event['training'] or group['family'] in ('background', 'anomaly'):
            return
        entities = [('ip', event.get(k)) for k in ('src', 'dst')]
        entities += [('account', event.get('user'))]
        for kind, value in set(entities):
            if not value:
                continue
            key = (event['scenario'], kind, value)
            previous = self.index.setdefault(key, {})
            for other_id, witness in list(previous.items()):
                if event['timestamp'] - witness['timestamp'] > 900:
                    previous.pop(other_id)
                    continue
                if other_id == group['id']:
                    continue
                other = engine.groups[other_id]
                # An IP crossing hosts can suggest lateral movement. A shared service
                # account alone needs a matching host to avoid joining entire fleets.
                if kind == 'account' and (other['host'] != group['host'] or group['host'] == 'unresolved host'):
                    continue
                edge_key = tuple(sorted((group['id'], other_id), key=lambda x: int(x[1:])))
                if edge_key in engine.edges:
                    continue
                engine.edges[edge_key] = {'id': '|'.join(edge_key), 'from': other_id, 'to': group['id'],
                    'basis': f'shared observed {kind} {value} within 15 min', 'confidence': 'low',
                    'relationship': 'inferred', 'time': event['time'],
                    'evidence_ids': [witness['id'], event['id']],
                    'confirmed_evidence': [{'field': kind, 'value': value, 'evidence_ids': [witness['id'], event['id']]}]}
                for member, neighbor in ((group, other), (other, group)):
                    member['connections'] += 1
                    member['related_families'].add(neighbor['family'])
                    engine.rank_group(member)
            previous[group['id']] = {'id': event['id'], 'timestamp': event['timestamp']}
            if len(previous) > 100:
                previous.pop(next(iter(previous)))
