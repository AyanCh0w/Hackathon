"""Observe an existing real combined run without affecting replay or opening labels."""
import argparse
import json
import time
from pathlib import Path
from urllib.request import urlopen

parser=argparse.ArgumentParser();parser.add_argument('id');parser.add_argument('--port',type=int,default=8787)
args=parser.parse_args();last_print=0;deadline=time.monotonic()+600
while True:
    with urlopen(f'http://127.0.0.1:{args.port}/api/run?id={args.id}',timeout=30) as response:
        run=json.loads(response.read())
    if time.monotonic()-last_print>=5:
        print(f"{run['status']} · {run['processed']:,}/{run['total']:,} · {run['actual_elapsed']:.2f} active seconds",flush=True);last_print=time.monotonic()
    if run['status']=='complete':break
    assert run['status'] not in ('error','cancelled'),run.get('error')
    assert time.monotonic()<deadline,'Completion deadline exceeded'
    time.sleep(.6)
assert run['processed']==run['total']==sum(run['dataset_totals'].values())
assert all(run['dataset_counts'][name]==run['dataset_totals'][name] for name in run['scenarios'])
assert all(stage['count']==run['total'] for stage in run['stages'].values())
assert sum(run['priority_counts'].values())==run['group_count']
assert sum(sum(counts.values()) for counts in run['dataset_priority_counts'].values())==run['group_count']
assert [g['priority_score'] for g in run['groups']]==sorted((g['priority_score'] for g in run['groups']),reverse=True)
visible={group['id'] for group in run['groups']}
assert all(edge['from'] in visible and edge['to'] in visible for edge in run['edges'])
report={k:run[k] for k in ('id','status','total','processed','dataset_counts','categories','group_count','edge_count','duration','actual_elapsed')}
report['priority_counts']=run['priority_counts']
report['priority_checks']='all episode totals conserved; shortlist ranked; real edge endpoints preserved'
report['candidates']=len(run['candidates']);report['labels']='not read';report['checks']='passed'
(Path(__file__).parent/'all-dataset-run-results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2),flush=True)
