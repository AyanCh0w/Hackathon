'use strict';
const assert=require('node:assert/strict'), fs=require('node:fs'), vm=require('node:vm');
class Element {
  constructor(tag,cls,text){this.tag=tag;this.className=cls||'';this.textContent=text||'';this.children=[];this.attributes={};}
  append(...children){this.children.push(...children);}
  replaceChildren(...children){this.children=children;}
  setAttribute(key,value){this.attributes[key]=value;}
}
const calls=[];
let fail=false;
const sandbox={el:(...args)=>new Element(...args),names:{recon:'Recon'},priorities:{context:'Context'},dateTime:x=>x,
  toast:message=>{throw Error(message);},evidenceNode:r=>new Element('pre','',r.id),
  api:async(path,body)=>{assert.equal(body,undefined,'Timeline may only read evidence');calls.push(path);if(fail)throw Error('Incident unavailable');
    if(path.startsWith('/api/evidence'))return {record:{id:'alert-1'}};
    return {scope:'Observed episodes; causality unproven',timeline:[{group:'g1',first:'start',last:'end',technique:'recon',host:'host',actor:'192.0.2.1',priority:'context',reason:'Observed scan',evidence_ids:['alert-1']}],edges:[{from:'g1',to:'g2',relationship:'inferred',basis:'shared IP',evidence_ids:['alert-1'],confirmed_evidence:[{field:'ip',value:'192.0.2.1',evidence_ids:['alert-1']}]}]};}};
vm.createContext(sandbox);
const source=fs.readFileSync(require('node:path').join(__dirname,'../static/app.js'),'utf8');
vm.runInContext(source.slice(source.indexOf('function incidentControls(')),sandbox);
function nodes(root){return [root,...root.children.flatMap(nodes)];}
(async()=>{
  const section=sandbox.incidentControls({id:'g1'},'real-run'), all=nodes(section);
  assert.ok(all.some(node=>node.textContent==='For demo only'));
  const show=all.find(node=>node.textContent==='View timeline');assert.notEqual(show.disabled,true);
  for(const control of all.filter(node=>['input','textarea','fieldset'].includes(node.tag)||['Approve suppression','Unsuppress'].includes(node.textContent))){assert.equal(control.disabled,true);assert.equal(control.onclick,undefined);}
  await show.onclick();assert.equal(calls[0],'/api/incident?id=real-run&group=g1');assert.equal(show.textContent,'Hide timeline');
  assert.ok(JSON.stringify(section).includes('inferred relationship'));assert.ok(JSON.stringify(section).includes('Confirmed matching field:'));
  await nodes(section).find(node=>node.tag==='button'&&node.textContent==='alert-1').onclick();assert.ok(calls[1].startsWith('/api/evidence'));
  await show.onclick();assert.equal(show.textContent,'View timeline');await show.onclick();assert.equal(calls.length,2,'Reopening uses the same observed snapshot');
  fail=true;const retrySection=sandbox.incidentControls({id:'g2'},'run');const retry=nodes(retrySection).find(node=>node.textContent==='View timeline');await retry.onclick();assert.equal(retry.textContent,'Retry timeline');assert.equal(retry.disabled,false);
  const fallbackCalls=[];
  const episode=(id,first)=>({id,first,last:first,family:'recon',host:'host',actor:'192.0.2.1',priority:'context',reason:'Observed scan',evidence:[{id:'alert-'+id}]});
  sandbox.api=async(path)=>{
    fallbackCalls.push(path);
    if(path.startsWith('/api/incident')){const error=Error('Not found');error.status=404;throw error;}
    if(path.startsWith('/api/run'))return {groups:[episode('g1','2022-01-02')],edges:[{from:'g1',to:'g2',basis:'same host'},{from:'g3',to:'g4',basis:'unrelated'}]};
    if(path.startsWith('/api/group'))return {group:episode('g2','2022-01-01')};
    throw Error('Unexpected endpoint');
  };
  const observed=await sandbox.loadIncidentTimeline({id:'g1'},'existing-run');
  assert.deepEqual(Array.from(observed.timeline,row=>row.group),['g2','g1']);
  assert.equal(observed.edges.length,1);assert.equal(observed.edges[0].relationship,'inferred');
  assert.equal(observed.timeline[0].evidence_ids[0],'alert-g2');
  assert.ok(fallbackCalls.some(path=>path==='/api/group?id=existing-run&group=g2'));
  sandbox.api=async()=>{const error=Error('Run not found');error.status=400;throw error;};
  await assert.rejects(()=>sandbox.loadIncidentTimeline({id:'g1'},'expired-run'),/Run not found/);
  console.log('Incident controls passed: real timeline, clickable alert evidence, certainty labels, show/hide, retry, inert suppression, and older-server fallback.');
})().catch(error=>{console.error(error);process.exitCode=1;});
