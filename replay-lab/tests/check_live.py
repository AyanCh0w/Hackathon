"""Integration checks against a running local server; also prepares all eight datasets."""
import argparse
import json
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

parser=argparse.ArgumentParser()
parser.add_argument('--port',type=int,default=8787)
args=parser.parse_args()
base=f'http://127.0.0.1:{args.port}'

def request(path,body=None,expected=200):
    req=Request(base+path,data=json.dumps(body).encode() if body else None,headers={'Content-Type':'application/json'})
    try:
        with urlopen(req,timeout=60) as response:
            status=response.status;result=json.loads(response.read())
    except HTTPError as error:
        status=error.code;result=json.loads(error.read())
    assert status==expected,(path,status,result)
    return result

catalog=request('/api/catalog');names=catalog['scenarios']
rules=request('/api/rules')
assert 'cracking.tool' in rules['rules']
request('/api/prepare',{'scenarios':names})
last_print=0
while True:
    catalog=request('/api/catalog')['catalog']
    failures=[m for m in catalog.values() if m['status']=='error']
    assert not failures,failures
    if all(catalog.get(name,{}).get('status')=='ready' for name in names):break
    if time.monotonic()-last_print>5:
        print('Preparing:',sum(m.get('loaded',0) for m in catalog.values()),'records;',sum(m['status']=='ready' for m in catalog.values()),'/ 8 ready',flush=True)
        last_print=time.monotonic()
    time.sleep(.8)

run=request('/api/start',{'scenarios':['russellmitchell','shaw'],'duration':3,'pacing':'events'})
key=run['id']
request('/api/verify',{'id':key},409)
request('/labels.csv',expected=404)
request('/%2e%2e/labels.csv',expected=404)
time.sleep(.2)
paused=request('/api/action',{'id':key,'action':'pause'})
count=paused['processed'];time.sleep(.1)
assert request('/api/run?id='+key)['processed']==count
request('/api/action',{'id':key,'action':'step'});time.sleep(.1)
assert request('/api/run?id='+key)['processed']==count+1
request('/api/action',{'id':key,'action':'resume'})
deadline=time.monotonic()+180
while True:
    snapshot=request('/api/run?id='+key)
    if snapshot['status']=='complete':break
    assert snapshot['status']!='error',snapshot.get('error')
    assert time.monotonic()<deadline,'Replay completion deadline'
    time.sleep(.2)
assert snapshot['processed']==catalog['russellmitchell']['total']+catalog['shaw']['total']
assert snapshot['processed']==sum(snapshot['dataset_counts'].values())
assert all(stage['count']==snapshot['processed'] for stage in snapshot['stages'].values())
groups={group['id']:group for group in snapshot['groups']}
for edge in snapshot['edges']:
    left=request('/api/group?id='+key+'&group='+edge['from'])['group']
    right=request('/api/group?id='+key+'&group='+edge['to'])['group']
    assert left['scenario']==right['scenario']
group=next(g for g in snapshot['groups'] if g['family'] in ('callback','cracking','execution'))
members=request('/api/group-members?id='+key+'&group='+group['id'])
assert members['members'] and len(members['members'])<=50
record=request('/api/evidence?id='+key+'&record='+members['members'][0]['id'])['record']
assert record['id']==members['members'][0]['id']
assert not any(k.startswith('_') for k in record)
investigation=request('/api/investigate?id='+key+'&group='+group['id'])
assert investigation['queries']<=3
assert investigation['decision']!='benign'
assert request('/api/run?id='+key)['groups']==snapshot['groups']
verified=request('/api/verify',{'id':key})
after=request('/api/run?id='+key)
for field in ('processed','dataset_counts','categories','groups','edges','candidates','history','signal_history','stages','logs'):
    assert after[field]==snapshot[field],field+' changed during verification'
assert set(row['scenario'] for row in verified['rows'])=={'russellmitchell','shaw'}
report={'checks':'passed','datasets':{name:{'records':catalog[name]['total'],'skipped':catalog[name]['errors']} for name in names},
        'all_records':sum(catalog[name]['total'] for name in names),'mixed_replay_records':snapshot['processed'],
        'pre_completion_verification':409,'static_label_access':404,'pause_and_single_step':'passed',
        'cross_dataset_edges':'none','frozen_verification':'unchanged','verification_windows':len(verified['rows']),
        'rules_version':rules['version'],'bounded_review':'passed','exact_member_lookup':'passed'}
(Path(__file__).parent/'live-check-results.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2),flush=True)
