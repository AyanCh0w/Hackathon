'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
class Element {
  constructor(tag, cls, text) { this.tag=tag;this.className=cls;this.textContent=text||'';this.children=[];this.attributes={}; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children=children; }
  setAttribute(name,value) { this.attributes[name]=value; }
  after(child) { this.afterNode=child; }
}
const source=fs.readFileSync(require('node:path').join(__dirname,'../static/app.js'),'utf8');
let resolveRequest;
const requests=[];
const response={analysis:{summary:'<script>bad()</script>',assessment:'investigate',confidence:'low',confidence_reason:'Unconfirmed',
  findings:[{observation:'Observed request',meaning:'Check execution',evidence_ids:['record-1']}],
  next_steps:[{priority:'now',action:'Review auth',why:'Verify identity',expected_result:'Approved change',evidence_ids:['record-1']}],
  possible_explanations:['Maintenance'],missing_evidence:['Process ancestry'],escalation_criteria:'Unauthorized access'},
  model:'test-model',snapshot:{cutoff:'2022-01-24T04:00:00Z'},coverage:{included_members:2,total_members:150,member_traces_sampled:true,connected_nodes_included:1,connected_nodes_total:1,decision_entries_included:5,retrieval_queries:2}};
const sandbox={el:(...args)=>new Element(...args),fmt:String,dateTime:x=>x,evidenceNode:r=>new Element('pre','',r.id),toast:message=>{throw Error(message);},
  api:(path,body)=>{requests.push({path,body});return new Promise(resolve=>{resolveRequest=resolve;});}};
vm.createContext(sandbox);
vm.runInContext(source.slice(source.indexOf('function nodeAnalysis('),source.indexOf('async function inspectGroup(')),sandbox);
(async()=>{
  const section=sandbox.nodeAnalysis({id:'g1'},'frozen-run');
  const button=section.children[2],result=section.children[3];
  const pending=button.onclick();
  assert.equal(button.disabled,true);
  assert.equal(result.attributes['aria-busy'],'true');
  assert.equal(requests[0].path,'/api/analyze-node');
  assert.equal(requests[0].body.id,'frozen-run');
  resolveRequest(response);await pending;
  assert.equal(button.disabled,false);
  assert.equal(result.attributes['aria-busy'],'false');
  assert.ok(result.children.some(child=>child.textContent==='<script>bad()</script>'),'Model output rendered as text');
  const finding=result.children.find(child=>child.className==='ai-finding');
  const ref=finding.children[2].children[0];
  const citation=ref.onclick();resolveRequest({record:{id:'record-1'}});await citation;
  assert.ok(requests.at(-1).path.includes('id=frozen-run&record=record-1'),'Citation uses original run');
  sandbox.api=async()=>{throw Error('Set OPENAI_API_KEY');};
  await button.onclick();
  assert.equal(button.disabled,false);
  assert.equal(button.textContent,'Retry AI analysis');
  assert.equal(result.children[0].textContent,'Set OPENAI_API_KEY');
  console.log('AI inspector passed: loading, safe text, citations, frozen run, errors and retry.');
})().catch(error=>{console.error(error);process.exitCode=1;});
