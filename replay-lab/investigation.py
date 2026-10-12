"""Read-only, evidence-bound review. Deterministic protocol; no simulated LLM."""
from telemetry import CAPABILITIES
from sqlite3 import Error as DatabaseError

QUESTIONS = {
    'execution': ('process', 'connection'), 'callback': ('process', 'connection'),
    'cracking': ('process', 'auth'), 'privilege': ('process', 'auth'),
    'service': ('service', 'process'), 'dns': ('dns',), 'recon': ('connection', 'auth'),
    'web': ('web',), 'anomaly': ('process',), 'background': (),
}
GAPS = {
    'execution': 'Process execution linked to the request and authoritative endpoint ownership.',
    'callback': 'Process-to-socket linkage and confirmation of the callback connection.',
    'cracking': 'Authorized password-audit context and evidence of cracking/authentication outcome.',
    'privilege': 'Initiating process ancestry and approved administrator/change context.',
    'service': 'Initiating identity/process, service lifecycle and approved maintenance context.',
    'dns': 'Complete client DNS traffic, responses and domain purpose; query anomalies alone do not prove exfiltration.',
    'recon': 'Complete connection outcomes and authoritative approved-scanner inventory.',
    'web': 'Endpoint ownership, request intent and member-level review of mixed HTTP activity.',
    'anomaly': 'Technique-specific evidence explaining the detector deviation.',
    'background': 'Complete collection and affirmative benign context before closing an investigation.',
}


def public_record(e):
    keys = ('id', 'scenario', 'time', 'source', 'file', 'line', 'raw', 'detector', 'training',
            'src', 'dst', 'src_port', 'dst_port', 'protocol', 'flow_state', 'bytes_out', 'bytes_in', 'dns_queries', 'auth_failed', 'user', 'sensor', 'host', 'host_basis', 'location', 'description', 'evidence_hash', 'capabilities', 'process', 'service_unit', 'origin_file', 'origin_line', 'origin_hash')
    return {key: e[key] for key in keys if key in e}


def review(group, retrieve=None, budget=3):
    if not 0 <= budget <= 3:
        raise ValueError('Review budget must be between zero and three queries')
    ledger = []
    def append(kind, **fields):
        entry = {'entry': len(ledger) + 1, 'kind': kind, **fields}
        ledger.append(entry)
        return entry['entry']
    evidence = list(group['evidence'])
    append('evidence', records=evidence, note='Representative observed members; repeated detector outputs remain counted.')
    coverage = set()
    calls = 0
    for field in QUESTIONS[group['family']]:
        if calls >= budget or retrieve is None:
            break
        calls += 1
        try:
            result = retrieve(field)
            records = [public_record(e) for e in result['records']]
            append('retrieval', capability=field, outcome='records' if records else 'empty',
                   records=records, truncated=result.get('truncated', False), query=result.get('query', {}))
            evidence.extend(records)
            if any(not e['training'] and e.get('capabilities', 0) & CAPABILITIES[field] for e in records):
                coverage.add(field)
        except (ValueError, OSError, DatabaseError) as exc:
            append('retrieval', capability=field, outcome='failed', error=str(exc))
    operational = [e for e in group['evidence'] if not e['training']]
    thesis = append('thesis', claim=group['title'] + ' observed in exported evidence.',
                    evidence_ids=[e['id'] for e in operational], scope='Observed content/event; intent and success remain unresolved.')
    # Independent evidence-only checks, without inheriting a private reasoning narrative.
    seen = {e['id']: e for e in evidence}
    bound = all(ref in seen and seen[ref].get('evidence_hash') and seen[ref].get('file') and seen[ref].get('line') for ref in ledger[thesis - 1]['evidence_ids'])
    append('challenge', thesis=thesis, evidence_binding='valid' if bound else 'incomplete',
           missing=GAPS[group['family']],
           benign_explanations=sorted({rule['counterexample'] for rule in group.get('rules', {}).values() if 'counterexample' in rule}),
           note='Nearby records establish context only. Empty retrieval and missing fields cannot justify benign dismissal.')
    if not operational:
        verdict = 'training_only' if group['training'] else 'insufficient_telemetry'
    elif not bound:
        verdict = 'insufficient_telemetry'
    elif group['family'] in ('background', 'anomaly'):
        verdict = 'needs_review'
    else:
        verdict = 'investigate'
    append('verdict', decision=verdict, supports=[thesis], missing=GAPS[group['family']],
           corroborated_execution=False, explanation='A specific operational signal merits investigation.' if verdict == 'investigate' else 'Available evidence is insufficient for an attack or benign verdict.')
    return {'group': group['id'], 'scenario': group['scenario'], 'decision': verdict, 'ledger': ledger,
            'queries': calls, 'budget': budget, 'available_context': sorted(coverage),
            'missing': GAPS[group['family']], 'mode': 'deterministic evidence review',
            'note': 'This deterministic review is read-only and bounded to the ingested prefix. It does not establish causal execution proof or authoritative maintenance context.'}
