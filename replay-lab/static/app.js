'use strict';
const $ = id => document.getElementById(id);
const state = {meta:null, run:null, stream:null, catalog:null, graphAll:true, signalLedger:false, lastRender:0, rate:0, lastCount:0, lastTick:0, preparing:false};
const names = {background:'Routine', anomaly:'Anomaly', recon:'Recon', web:'Web probing', execution:'Web commands', callback:'Callback request', privilege:'Privilege', service:'Service change', dns:'DNS anomaly', cracking:'Credential attack'};
const priorities = {high:'High priority', investigate:'Investigate', context:'Context', routine:'Routine / training'};
const importanceOrder = (a,b) => b.priority_score-a.priority_score || b.last_ts-a.last_ts || Number(a.id.slice(1))-Number(b.id.slice(1));
const evidenceGraph = new EvidenceGraph($('graph'), {inspect:inspectGroup, tooltip:$('graph-tooltip'), container:$('graph-container')});
const horizontalMap = new HorizontalEvidenceMap($('horizontal-world'), inspectGroup, renderGraph);
let originalMap = false;
const fmt = value => Number(value || 0).toLocaleString('en-US');
const compact = value => Number(value||0).toLocaleString('en-US',{notation:'compact',maximumFractionDigits:1}).toLowerCase();
const clock = value => `${String(Math.floor(value / 60)).padStart(2,'0')}:${String(Math.floor(value % 60)).padStart(2,'0')}`;
const shortTime = value => value ? value.slice(11,19) : '—';
const dateTime = value => value ? value.replace('T',' ').replace(/\.\d+(Z|\+00:00)$/, '').replace('Z','').replace('+00:00','') : '—';
const shortDate = value => value ? new Date(value).toLocaleString('en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZone:'UTC',hour12:false}) : '—';
const selected = () => [...document.querySelectorAll('#dataset-options input:checked')].map(input=>input.value);
const inView = row => $('dataset-view').value==='all'||row.scenario===$('dataset-view').value;
function el(tag, cls, text) { const node = document.createElement(tag); if(cls) node.className=cls; if(text!==undefined) node.textContent=text; return node; }
async function api(path, body) { const response = await fetch(path, body ? {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)} : {}); const result=await response.json(); if(!response.ok)throw Error(result.error || `HTTP ${response.status}`); return result; }
function toast(message) { $('toast').textContent=message; $('toast').hidden=false; clearTimeout(toast.timer); toast.timer=setTimeout(()=>$('toast').hidden=true,6000); }
function showEmpty(target,title,copy,symbol='↳') { const empty=el('div','empty');empty.append(el('span','empty-symbol',symbol),el('strong','',title),el('p','',copy));target.replaceChildren(empty); }

async function prepareSelected() {
  const selections=selected(),generation=(state.prepGeneration||0)+1;state.prepGeneration=generation;
  $('dataset-summary').replaceChildren(document.createTextNode(selections.length===8?'All 8 selected':`${selections.length} of 8 selected`),el('span','','⌄'));
  state.preparing=true;state.meta=null;state.run=null;
  const view=$('dataset-view');view.replaceChildren(el('option','','All selected datasets'));view.firstChild.value='all';
  for(const name of selections){const option=el('option','',name[0].toUpperCase()+name.slice(1));option.value=name;view.append(option);}
  $('play').disabled=true;$('play-label').textContent='Preparing…';$('preparation').textContent='Reading and sorting the two alert files. No inference or label access during preparation.';
  if(!selections.length){state.preparing=false;$('play-label').textContent='Select datasets';$('preparation').textContent='Choose at least one dataset to prepare the replay.';$('total').textContent='/ —';return;}
  try {
    await api('/api/prepare',{scenarios:selections});
    let catalog;
    do {
      catalog=await api('/api/catalog');
      if(state.prepGeneration!==generation)return;
      state.catalog=catalog;
      const datasets=selections.map(name=>catalog.catalog[name]);
      const failure=datasets.find(meta=>meta?.status==='error');if(failure)throw Error(failure.error);
      if(datasets.every(meta=>meta?.status==='ready')){
        const start=Math.min(...datasets.map(m=>m.start_ts)),end=Math.max(...datasets.map(m=>m.end_ts));
        state.meta={total:datasets.reduce((n,m)=>n+m.total,0),errors:datasets.reduce((n,m)=>n+m.errors,0),sources:{wazuh:datasets.reduce((n,m)=>n+m.sources.wazuh,0),aminer:datasets.reduce((n,m)=>n+m.sources.aminer,0),telemetry:datasets.reduce((n,m)=>n+(m.sources.telemetry||0),0)},start:new Date(start*1000).toISOString(),end:new Date(end*1000).toISOString(),datasets:selections};break;
      }
      const ready=datasets.filter(m=>m?.status==='ready').length,loaded=datasets.reduce((n,m)=>n+(m?.loaded||0),0);
      $('preparation').textContent=`Preparing ${selections.length} datasets · ${ready} ready · ${fmt(loaded)} records read · labels sealed`;
      await new Promise(resolve=>setTimeout(resolve,750));
    }while(true);
    state.preparing=false;
    renderReady();
  }catch(error){state.preparing=false;toast(error.message);$('preparation').textContent='Preparation failed. Select the scenario again to retry.';}
}
const fpStorageKey = 'trace-false-positive-reviews-v1';
const fpStatuses = ['Suspected', 'Confirmed false positive', 'Valid detection', 'Inconclusive'];
let fpCases = [];
try {
  const saved = JSON.parse(localStorage.getItem(fpStorageKey) || '[]');
  if(Array.isArray(saved)) fpCases = saved.filter(row => row && typeof row.key==='string' && fpStatuses.includes(row.status));
} catch {}
function saveFalsePositives(next) {
  try { localStorage.setItem(fpStorageKey, JSON.stringify(next)); }
  catch { toast('Could not save reviews in this browser. Export existing reviews before leaving.'); return false; }
  fpCases=next;renderFalsePositives();return true;
}
function falsePositiveAction(group,runId) {
  const button=el('button','secondary','Flag possible false positive');
  const key=JSON.stringify([runId,group.id]);
  if(fpCases.some(row=>row.key===key)) button.textContent='Open false positive review';
  button.onclick=()=>{
    if(!fpCases.some(row=>row.key===key)) {
      const row={key,runId,groupId:group.id,scenario:group.scenario,title:group.title,host:group.host,first:group.first,last:group.last,evidenceIds:(group.evidence||[]).map(record=>record.id),status:'Suspected',notes:'',updated:new Date().toISOString()};
      if(!saveFalsePositives([...fpCases,row])) return;
    }
    $('detail-dialog').close();$('false-positive-panel').open=true;
    $('false-positive-panel').scrollIntoView({behavior:'auto',block:'start'});
  };
  return button;
}
function renderFalsePositives() {
  const counts=fpStatuses.map(status=>`${fpCases.filter(row=>row.status===status).length} ${status.toLowerCase()}`);
  $('fp-summary').textContent=counts.join(' · ');
  const target=$('fp-cases');
  if(!fpCases.length){showEmpty(target,'No flagged groups','Open an evidence group and choose “Flag possible false positive”.');return;}
  const fragment=document.createDocumentFragment();
  for(const row of [...fpCases].reverse()) {
    const card=el('section','fp-case');
    card.append(el('h3','',`${row.scenario} / ${row.groupId} · ${row.title}`),el('p','detail-subtitle',`Run ${row.runId} · ${row.host} · ${dateTime(row.first)} – ${dateTime(row.last)} UTC`));
    const refs=el('details');refs.append(el('summary','','Evidence references'),el('p','',row.evidenceIds?.join(', ')||'No sampled records'));card.append(refs);
    const statusLabel=el('label','','Review outcome'),select=el('select');
    for(const value of fpStatuses){const option=el('option','',value);option.value=value;select.append(option);}select.value=row.status;statusLabel.append(select);
    const notesLabel=el('label','','Supporting evidence and follow-up'),notes=el('textarea');notes.value=row.notes;notes.rows=3;notes.maxLength=10000;notes.placeholder='Explain the benign behavior, evidence checked, and next steps.';notesLabel.append(notes);
    const save=el('button','secondary','Save review');
    save.onclick=()=>{
      if(select.value==='Confirmed false positive'&&!notes.value.trim()){toast('Add supporting evidence before confirming a false positive.');notes.focus();return;}
      if(saveFalsePositives(fpCases.map(item=>item.key===row.key?{...item,status:select.value,notes:notes.value.trim(),updated:new Date().toISOString()}:item)))toast('Review saved.');
    };
    card.append(statusLabel,notesLabel,save,el('p','detail-subtitle',`Last saved ${dateTime(row.updated)} UTC`));fragment.append(card);
  }
  target.replaceChildren(fragment);
}
$('fp-export').onclick=()=>{
  const url=URL.createObjectURL(new Blob([JSON.stringify({version:1,unit:'evidence group per replay run',reviews:fpCases},null,2)],{type:'application/json'}));
  const link=el('a');link.href=url;link.download='false-positive-reviews.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
function renderReady() {
  const meta=state.meta;if(!meta)return;
  $('play').disabled=false;$('play-label').textContent='Start replay';$('play-icon').textContent='▶';
  $('preparation').textContent=`${meta.datasets.length} datasets · ${fmt(meta.total)} real records ready · ${fmt(meta.sources.wazuh)} Wazuh + ${fmt(meta.sources.aminer)} AMiner + ${fmt(meta.sources.telemetry)} raw telemetry · ${meta.errors} skipped records`;
  $('total').textContent=`/ ${fmt(meta.total)}`;$('range-start').textContent=shortDate(meta.start);$('range-end').textContent=shortDate(meta.end);
  $('event-time').textContent=dateTime(meta.start);$('wall-duration').textContent=` / ${clock(Number($('duration').value))}`;
  $('pacing-copy').textContent=$('pacing').value==='events'?'Chronological order · quiet gaps compressed · no future evidence':'Original timeline scaled evenly · chronological order · no future evidence';
}
function setControls(run) {
  const status=run?.status;const active=status==='running'||status==='paused';
  for(const id of ['duration','pacing','select-all','select-none'])$(id).disabled=active;
  for(const input of document.querySelectorAll('#dataset-options input'))input.disabled=active;
  $('step').disabled=status!=='paused';$('verify').disabled=status!=='complete';
  if(status==='running'){$('play-icon').textContent='Ⅱ';$('play-label').textContent='Pause replay';}
  else if(status==='paused'){$('play-icon').textContent='▶';$('play-label').textContent='Resume replay';}
  else {$('play-icon').textContent='▶';$('play-label').textContent=status==='complete'?'Replay again':'Start replay';}
  $('play').disabled=state.preparing||!state.meta||status==='error';
}
async function start() {
  if(!state.meta)return;
  try {
    $('play').disabled=true;
    if(state.stream)state.stream.close();
    $('datasets').open=false;
    const result=await api('/api/start',{scenarios:selected(),duration:Number($('duration').value),pacing:$('pacing').value});
    history.replaceState(null,'','/');
    evidenceGraph.reset();horizontalMap.reset();state.lastRender=0;
    $('verification').hidden=true;$('verify').textContent='Verify at end ↗';$('isolation-title').textContent='Labels sealed';$('isolation-copy').textContent='Analysis uses the selected telemetry; labels stay sealed.';
    state.lastCount=0;state.lastTick=performance.now();
    state.stream=new EventSource(`/api/stream?id=${result.id}`);
    $('run-strip').style.scrollMarginTop=(document.querySelector('.controls').getBoundingClientRect().height+24)+'px';
    $('run-strip')?.scrollIntoView({behavior:'instant',block:'nearest'});
    state.stream.addEventListener('snapshot',event=>{
      const run=JSON.parse(event.data);state.run=run;
      const now=performance.now();state.rate=run.status==='running'?Math.max(0,(run.processed-state.lastCount)/((now-state.lastTick)/1000)):0;
      state.lastTick=now;state.lastCount=run.processed;
      render(run);
      if(['complete','cancelled','error'].includes(run.status)){state.stream.close();if(run.status==='complete')history.replaceState(null,'','/?run='+encodeURIComponent(run.id));if(run.error)toast(run.error);}
    });
    state.stream.onerror=async()=>{
      if(state.run&&!['complete','cancelled'].includes(state.run.status)){
        try{const latest=await api(`/api/run?id=${result.id}`);state.run=latest;render(latest);if(latest.status==='complete')state.stream.close();}
        catch(error){toast('Connection interrupted: '+error.message);}
      }
    };
  }catch(error){toast(error.message);setControls(state.run);}
}
async function action(action) {
  try{const run=await api('/api/action',{id:state.run.id,action});state.run=run;render(run);}
  catch(error){toast(error.message);}
}
async function reset() {
  history.replaceState(null,'','/');
  if(state.stream)state.stream.close();
  if(state.run&&['running','paused'].includes(state.run.status))await action('cancel');
  state.run=null;state.lastCount=0;state.lastRender=0;
  for(const id of ['duration','pacing','select-all','select-none'])$(id).disabled=false;
  for(const input of document.querySelectorAll('#dataset-options input'))input.disabled=false;
  $('status').className='status';$('status').replaceChildren(el('i'),document.createTextNode(' READY'));
  $('progress').style.width='0%';$('processed').replaceChildren(document.createTextNode('0 '),el('small','','/ '+fmt(state.meta?.total)));
  $('processed').lastChild.id='total';
  for(const id of ['group-count','edge-count','candidate-count'])$(id).textContent='0';
  $('wall-time').textContent='00:00';$('feed-rate').textContent='0 / sec';
  $('candidate-note').textContent='Connected signals across rule families';
  for(const node of document.querySelectorAll('.stage')){node.classList.remove('active');node.querySelector('.stage-count').textContent='0 evaluated';node.querySelector('.stage-time').textContent='0 ms';}
  showEmpty($('feed'),'No records yet','Start a replay to view incoming records.','≋');
  showEmpty($('ledger'),'No decisions yet','Classification and grouping decisions appear during replay.');
  evidenceGraph.reset();horizontalMap.reset();$('graph-empty').hidden=false;$('graph-visible').textContent='0 groups shown';
  $('priority-summary').replaceChildren(el('span','','Groups are categorized as evidence arrives.'));
  $('groups').replaceChildren(el('div','empty horizontal','No evidence groups yet'));
  $('finding').replaceChildren(el('span','finding-icon','↳'),el('div','','Waiting for a connected candidate'));
  $('verification').hidden=true;$('isolation-title').textContent='Labels sealed';$('isolation-copy').textContent='Analysis uses the selected telemetry; labels stay sealed.';
  $('verify').textContent='Verify at end ↗';setControls(null);renderReady();
}
function render(run) {
  setControls(run);
  $('status').dataset.runId=run.id;
  $('status').className='status '+run.status;$('status').replaceChildren(el('i'),document.createTextNode(' '+run.status.toUpperCase()));
  $('event-time').textContent=dateTime(run.virtual);$('wall-time').textContent=clock(run.actual_elapsed??run.elapsed);$('wall-duration').textContent=` / ${clock(run.duration)}`;
  $('progress').style.width=(run.elapsed/run.duration*100)+'%';
  $('processed').firstChild.textContent=fmt(run.processed)+' ';$('total').textContent='/ '+fmt(run.total);
  $('source-counts').textContent=`${fmt(run.sources.Wazuh)} Wazuh · ${fmt(run.sources.AMiner)} AMiner · ${fmt(run.sources.Telemetry)} raw telemetry`;
  $('group-count').textContent=fmt(run.group_count);$('edge-count').textContent=fmt(run.edge_count);$('candidate-count').textContent=fmt(run.candidates.length);
  $('training-note').textContent=`${fmt(run.training)} training-mode records kept separate from operational evidence.`;
  $('dataset-progress').textContent=run.scenarios.map(name=>`${name}: ${Math.round((run.dataset_counts[name]||0)/run.dataset_totals[name]*100)}%`).join(' · ');
  $('feed-rate').textContent=fmt(Math.round(state.rate))+' / sec';
  if(run.status==='complete'){$('preparation').textContent=`Replay complete · ${fmt(run.processed)} / ${fmt(run.total)} records analyzed · findings frozen · verification is now available`;}
  for(const [name,data] of Object.entries(run.stages)){
    const node=document.querySelector(`[data-stage="${name}"]`);node.classList.toggle('active',run.status==='running'&&run.processed>0);
    const verbs={normalize:'decoded',classify:'evaluated',group:'assigned',connect:'checked'};
    node.querySelector('.stage-count').textContent=fmt(data.count)+' '+verbs[name];
    node.querySelector('.stage-time').textContent=(data.ms<1000?data.ms.toFixed(0)+' ms':(data.ms/1000).toFixed(1)+' s');
    node.title=`${name}: cumulative measured CPU time ${data.ms.toFixed(2)} ms; last record ${data.last||'none'}`;
  }
  renderFeed();renderLedger();
  if(performance.now()-state.lastRender>450||run.status!=='running'){
    state.lastRender=performance.now();renderGraph();renderGroups();
  }
  const candidates=run.candidates.filter(inView).sort((a,b)=>(b.priority==='high')-(a.priority==='high') || b.families.includes('privilege')-a.families.includes('privilege'));
  if(candidates.length){
    const candidate=candidates[0];const div=el('div');div.append(el('strong','',`${candidate.scenario} / ${candidate.host} · ${candidate.families.map(f=>names[f]).join(' + ')}`),el('p','',`${candidate.groups.length} connected groups · ${candidate.status}`));
    $('finding').replaceChildren(el('span','finding-icon','↳'),div);$('candidate-note').textContent='Candidates need review; success is unproven';
  }
}
function renderFeed() {
  if(!state.run)return;
  const query=$('search').value.toLowerCase(),source=$('source-filter').value;
  const rows=state.run.logs.filter(row=>inView(row)&&(source==='all'||row.source===source)&&(!query||`${row.scenario} ${row.host} ${row.src} ${row.description} ${row.raw}`.toLowerCase().includes(query))).reverse().slice(0,45);
  if(!rows.length){$('feed-caption').textContent=`0 matching · latest ${state.run.logs.length} received`;showEmpty($('feed'),'No matching records in the live buffer.','Inspect group evidence, change the filter, or keep the stream running.','≋');return;}
  const fragment=document.createDocumentFragment();
  for(const row of rows){
    const node=el('div','log-row');node.tabIndex=0;node.setAttribute('role','button');node.setAttribute('aria-label',`${row.source} ${names[row.family]} ${row.host} ${shortTime(row.time)}; inspect evidence`);
    const meta=el('div','log-meta');meta.append(el('time','',shortTime(row.time)),el('span','source-tag '+(row.source==='AMiner'?'aminer':''),row.source),el('span','log-category '+row.family,names[row.family]));
    node.append(meta,el('div','log-title',`${row.scenario} / ${row.host}${row.src?' ← '+row.src:''}`),el('div','log-desc',(row.training?'TRAINING · ':'')+row.description));
    node.addEventListener('click',()=>inspectRecord(row));node.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();inspectRecord(row);}});fragment.append(node);
  }
  $('feed').replaceChildren(fragment);$('feed-caption').textContent=`${rows.length} shown · latest ${state.run.logs.length} received`;
}
function renderLedger() {
  if(!state.run)return;
  const history=state.signalLedger?state.run.signal_history:state.run.history;
  if(!history?.length){showEmpty($('ledger'),'No signal decisions yet.','Switch to All decisions to see detector anomalies. Live stage totals cover every record.');return;}
  const fragment=document.createDocumentFragment();
  for(const item of [...history].filter(inView).reverse().slice(0,45)){
    const node=el('div','ledger-item '+item.stage),mark=el('span','ledger-mark',item.stage==='connect'?'↔':item.stage==='group'?'+':'✓'),content=el('div');
    const meta=el('div','ledger-meta');meta.append(el('strong','',item.stage.toUpperCase()),el('span','',`${shortTime(item.time)} · +${clock(item.replay_elapsed)}`));
    content.append(meta,el('div','ledger-dataset',item.scenario),el('p','',item.detail));
    if(item.group){const button=el('button','',`${item.group} · inspect decision ↗`);button.onclick=()=>inspectGroup(item.group,item);content.append(button);}
    node.append(mark,content);fragment.append(node);
  }
  $('ledger').replaceChildren(fragment);
}
function graphGroups() {
  const connected=new Set(state.run.edges.flatMap(edge=>[edge.from,edge.to]));
  const pool=(state.run?.groups||[]).filter(g=>inView(g)&&(connected.has(g.id)||state.graphAll||g.priority!=='routine')).sort(importanceOrder);
  const available=new Map(pool.map(g=>[g.id,g])), chosen=new Map(),limit=80;
  // Every relationship endpoint is mandatory; the cap applies only to isolated context.
  for(const id of connected)if(available.has(id))chosen.set(id,available.get(id));
  const add=group=>{if(group&&chosen.size<limit)chosen.set(group.id,group);};
  // Give each selected dataset an important starting point, then preserve real edge pairs.
  for(const dataset of new Set(pool.map(g=>g.scenario))){
    for(const group of pool.filter(g=>g.scenario===dataset&&g.priority==='high').slice(0,2))add(group);
    add(pool.find(g=>g.scenario===dataset&&g.priority==='investigate'));
  }
  const edges=state.run.edges.filter(e=>available.has(e.from)&&available.has(e.to)).sort((a,b)=>
    Math.max(available.get(b.from).priority_score,available.get(b.to).priority_score)-Math.max(available.get(a.from).priority_score,available.get(a.to).priority_score));
  for(const edge of edges){
    const needed=Number(!chosen.has(edge.from))+Number(!chosen.has(edge.to));
    if(chosen.size+needed<=limit){add(available.get(edge.from));add(available.get(edge.to));}
  }
  const represented=new Set([...chosen.values()].map(g=>g.scenario+':'+g.family+':'+g.priority));
  for(const group of pool){
    const key=group.scenario+':'+group.family+':'+group.priority;
    if(!represented.has(key)){add(group);represented.add(key);}
  }
  for(const group of pool)if(group.priority==='high')add(group);
  return [...chosen.values()].sort(importanceOrder);
}
function renderGraph() {
  if(!state.run)return;
  const groups=graphGroups(),shown=originalMap?evidenceGraph.update(groups,state.run.edges):horizontalMap.update(groups,state.run.edges);
  $('graph-empty').hidden=shown.nodes>0;
  const totals=$('dataset-view').value==='all'?state.run.priority_counts:state.run.dataset_priority_counts[$('dataset-view').value]||{};
  const total=Object.values(totals).reduce((a,b)=>a+b,0);
  const viewIds=new Set(state.run.groups.filter(inView).map(group=>group.id));
  const connections=state.run.edges.filter(edge=>viewIds.has(edge.from)&&viewIds.has(edge.to)).length;
  $('graph-visible').textContent=`${shown.nodes} / ${fmt(total)} groups · ${shown.links} / ${connections} connections in this view`;
}
function renderGroups() {
  if(!state.run)return;
  const groups=state.run.groups.filter(g=>inView(g)&&($('show-routine').checked||g.priority!=='routine')).sort(importanceOrder);
  const totals=$('dataset-view').value==='all'?state.run.priority_counts:state.run.dataset_priority_counts[$('dataset-view').value]||{};
  const summary=document.createDocumentFragment();
  for(const [tier,label] of Object.entries(priorities)){
    const item=el('span','priority-total '+tier);item.append(el('i'),el('strong','',fmt(totals[tier])),document.createTextNode(' '+label));summary.append(item);
  }
  $('priority-summary').replaceChildren(summary);
  if(!groups.length){$('groups').replaceChildren(el('div','empty horizontal','No matching evidence groups yet.'));return;}
  const openSections=new Map([...$('groups').querySelectorAll('.priority-section')].map(node=>[node.dataset.priority,node.open]));
  const fragment=document.createDocumentFragment();
  for(const [tier,label] of Object.entries(priorities)){
    const candidates=groups.filter(g=>g.priority===tier);if(!candidates.length)continue;
    const section=el('details','priority-section '+tier);section.dataset.priority=tier;section.open=openSections.get(tier)??(tier==='high'||tier==='investigate');
    const heading=el('summary','priority-heading');heading.append(el('span','',label),el('small','',`${Math.min(8,candidates.length)} representative / ${fmt(totals[tier])} total`));section.append(heading);
    const list=el('div','priority-list');
    for(const group of candidates.slice(0,8)){
      const node=el('button','group-card priority-'+tier);node.dataset.group=group.id;node.dataset.priority=tier;
      const top=el('div','group-top');top.append(el('span','',group.id.toUpperCase()+' · '+shortTime(group.last)),el('span','confidence '+group.confidence,group.confidence+' confidence'));
      node.append(top,el('p','group-scenario',group.scenario),el('h3','',group.title),el('p','group-host',`${group.host} ← ${group.actor}`));
      const reason=el('p','priority-reason',group.priority_reason);reason.title=group.priority_reason;node.append(reason);
      const bottom=el('div','group-bottom'),count=el('strong','',fmt(group.count)+' ');count.append(el('span','','records'));
      bottom.append(count,el('span','',fmt(group.unique)+' distinct'+(group.training?' · '+fmt(group.training)+' training':'')));node.append(bottom);
      node.onclick=()=>inspectGroup(group.id);list.append(node);
    }
    section.append(list);fragment.append(section);
  }
  $('groups').replaceChildren(fragment);
}
function disclosure(title,...children){const node=el('details','inspector-disclosure');node.append(el('summary','',title),...children);return node;}
function pair(label,value){const node=el('div');node.append(el('label','',label),el('strong','',value));return node;}
function evidenceNode(record){
  const node=el('div','evidence-item');node.append(el('div','evidence-ref',`${record.file}:${record.line} · ${record.source} · ${record.id}`),el('p','',dateTime(record.time)+(record.training?' · TRAINING MODE':'')));
  if(record.sensor)node.append(el('p','',`Sensor ${record.sensor} · observed source ${record.src||'unresolved'} · destination ${record.dst||'unresolved'}`));
  if(record.evidence_hash)node.append(el('p','evidence-hash',`Evidence SHA-256 ${record.evidence_hash}`));
  if(record.origin_file)node.append(el('p','evidence-hash',`Original log ${record.origin_file}:${record.origin_line}${record.origin_hash?' · SHA-256 '+record.origin_hash:''}`));
  if(record.src||record.dst)node.append(el('p','',`${record.protocol||'Observed endpoints'} · ${record.src||'unknown'}${record.src_port?':'+record.src_port:''} → ${record.dst||'unknown'}${record.dst_port?':'+record.dst_port:''}${record.flow_state?' · '+record.flow_state:''}`));
  if(record.dns_queries?.length){const queries=el('details');queries.append(el('summary','','DNS query fields'),el('pre','',JSON.stringify(record.dns_queries,null,2)));node.append(queries);}
  if(record.process?.exe)node.append(el('p','',`Process ${record.process.exe}${record.process.pid?' · PID '+record.process.pid:''}`));
  if(record.auth_failed)node.append(el('p','','Authentication failure'+(record.user?' · '+record.user:'')));
  node.append(disclosure('Raw record',el('pre','',record.raw)));return node;
}
function openDetail(content){$('detail-content').replaceChildren(content);if(!$('detail-dialog').open)$('detail-dialog').showModal();}
const nextChecks = {
  execution:'Check web access/error logs and process ancestry on the affected host around this window. Confirm whether the request spawned a process; inspect the PHP file and response.',
  callback:'Check process ancestry and outbound firewall or flow logs around this window. Verify whether a shell ran and a connection reached the callback endpoint in the evidence.',
  privilege:'Review authentication, sudo and audit logs for the initiating account, target identity and resulting processes. Verify whether the change was authorized.',
  service:'Check service manager and audit logs for who stopped the service, the reason and current service health. Compare with approved maintenance.',
  cracking:'Inspect the process, account, input files and authorization for the password audit. Check authentication logs for subsequent use of affected credentials.',
  recon:'Review network flows and destination ports for the observed source and host. Establish scan scope and check whether the scanner was authorized.',
  web:'Review requested paths, HTTP responses and access logs for this source. Check successful responses and any follow-on process or authentication activity.',
  dns:'Retrieve DNS queries and responses plus resolver and network logs. Check query volume, domain patterns and the initiating process.',
  anomaly:'Compare the detector finding with baseline activity and retrieve the underlying host or network logs before escalating.',
  background:'Confirm expected activity and training status. Use these records as context when reviewing related signals.'
};
function contextText(group,key){
  const summary=group.context?.[key];
  if(!summary)return 'Summary unavailable from this server';
  if(!summary.values.length)return group.context_sample?'Not found in retrieved evidence samples':'Not recorded in episode telemetry';
  return summary.values.map(row=>`${row.value} (${fmt(row.records)} ${group.context_sample?'samples':'records'})`).join(' · ')+(summary.total_values>summary.values.length?` · showing top ${summary.values.length} of ${fmt(summary.total_values)}`:'');
}
function inspectionFrequency(group){
  const duration=Math.max(0,(Date.parse(group.last)-Date.parse(group.first))/1000);
  return group.frequency||{duration_seconds:duration,repeated_records:group.count-group.unique,
    records_per_minute:duration>0?group.count*60/duration:null,distinct_per_minute:duration>0?group.unique*60/duration:null};
}
function sampleContext(records){
  return Object.fromEntries(['src','dst','sensor','location','source','description'].map(key=>{
    const counts=new Map();
    for(const record of records){const value=record[key]||(key==='location'?(record.origin_file||(record.file?'Alert export: '+record.file:'')):key==='description'?record.detector:'');if(value)counts.set(value,(counts.get(value)||0)+1);}
    return [key,{values:[...counts].map(([value,records])=>({value,records})),total_values:counts.size}];
  }));
}
function analystSummary(group){
  const content=el('section','analyst-summary'),grid=el('div','detail-grid');
  const frequency=inspectionFrequency(group),duration=frequency.duration_seconds;
  grid.append(pair('WHAT HAPPENED',group.reason),pair('WHERE · DATASET / HOST',`${group.scenario} / ${group.host} · ${group.host_basis}`),
    pair('FIRST OBSERVED · UTC',group.first),pair('LAST OBSERVED · UTC',group.last),
    pair('SOURCE IPs',contextText(group,'src')),pair('DESTINATION IPs',contextText(group,'dst')),
    pair('COLLECTION SENSOR',contextText(group,'sensor')),pair('LOG LOCATION',contextText(group,'location')),
    pair('FREQUENCY · OBSERVED EPISODE',`${fmt(group.count)} records · ${fmt(group.unique)} distinct · ${fmt(frequency.repeated_records)} repeats · ${fmt(group.training)} training · ${fmt(group.operational_unique)} operational distinct`),
    pair('AVERAGE RATE · FIRST TO LAST EVENT',duration>0?`${frequency.records_per_minute.toFixed(2)} records/min · ${frequency.distinct_per_minute.toFixed(2)} distinct/min over ${duration.toFixed(1)} seconds`:'Rate unavailable: observations share one timestamp'),
    pair('REPORTED EVENTS / DETECTORS',contextText(group,'description')),pair('OBSERVATION SOURCES',contextText(group,'source')));
  content.append(disclosure('Episode details · timing, endpoints, and frequency',grid),el('p','detail-subtitle',group.context_sample?'Endpoint and log details come from retrieved evidence samples because this running server predates episode summaries. Frequency uses the full episode counts and timestamps. Restart the server and replay for complete field counts.':'Counts cover all received episode members, including training. Repeats are detector records sharing the same evidence key; rates describe this episode, not a baseline. Sensor addresses identify collection infrastructure.'));
  content.append(el('h3','','Suggested next checks'),el('p','',group.count===group.training?'This episode is training-only. Validate against operational telemetry before escalation.':nextChecks[group.family]||nextChecks.anomaly));
  return content;
}
function inspectRecord(row){
  const content=el('div');content.append(el('h2','',`${names[row.family]} · ${row.scenario} / ${row.host}`),el('div','rule-note',row.reason));
  const grid=el('div','detail-grid');grid.append(pair('WHAT HAPPENED',row.description),pair('WHERE',`${row.scenario} / ${row.host} · ${row.host_basis||'unresolved'}`),pair('WHEN · UTC',dateTime(row.time)),pair('SOURCE → DESTINATION IP',`${row.src||'Not observed'} → ${row.dst||'Not observed'}`),pair('CLASSIFICATION',row.family+' / '+row.confidence),pair('ASSIGNED GROUP',row.group));
  const button=el('button','secondary','Inspect episode frequency and next checks');button.onclick=()=>inspectGroup(row.group);
  content.append(grid,button,evidenceNode(row));openDetail(content);
}
function nodeAnalysis(group,runId){
  const section=el('section','ai-analysis'),button=el('button','','Analyze node with AI');
  const result=el('div','ai-analysis-result');result.setAttribute('role','status');result.setAttribute('aria-live','polite');
  section.append(el('h3','','Understand this node'),el('p','detail-subtitle','Get an evidence-backed assessment and prioritized next steps. Sends redacted node details, sampled member traces, connections, and investigation results to OpenAI.'),button,result);
  button.onclick=async()=>{
    button.disabled=true;button.textContent='Analyzing node…';result.setAttribute('aria-busy','true');
    result.replaceChildren(el('p','','Gathering evidence and analyzing what to check next. This can take up to a minute.'));
    try{
      const response=await api('/api/analyze-node',{id:runId,group:group.id});
      const report=response.analysis,coverage=response.coverage;
      result.replaceChildren(el('h3','',report.assessment.replaceAll('_',' ')),el('p','ai-summary',report.summary),
        el('p','',`Confidence: ${report.confidence} — ${report.confidence_reason}`));
      result.append(el('p','detail-subtitle',`${response.model} · Snapshot through ${dateTime(response.snapshot.cutoff)} UTC · ${fmt(coverage.included_members)} / ${fmt(coverage.total_members)} member traces${coverage.member_traces_sampled?' (sampled)':''} · ${coverage.connected_nodes_included} / ${coverage.connected_nodes_total} connected nodes · ${coverage.decision_entries_included} retained decisions · ${coverage.retrieval_queries} investigation queries. Recommendations require analyst review.`));
      const citations=(parent,ids)=>{
        if(!ids.length)return;
        const refs=el('div','ai-citations');
        for(const id of ids){
          const ref=el('button','member-reference',id);ref.onclick=async()=>{
            ref.disabled=true;
            try{const response=await api(`/api/evidence?id=${encodeURIComponent(runId)}&record=${encodeURIComponent(id)}`);refs.after(evidenceNode(response.record));}
            catch(error){toast(error.message);ref.disabled=false;}
          };refs.append(ref);
        }parent.append(refs);
      };
      result.append(el('h3','','What the evidence shows'));
      for(const finding of report.findings){const item=el('div','ai-finding');item.append(el('strong','',finding.observation),el('p','',finding.meaning));citations(item,finding.evidence_ids);result.append(item);}
      result.append(el('h3','','What to do next'));
      const steps=el('ol','ai-next-steps');
      for(const step of report.next_steps){const item=el('li');item.append(el('strong','',`${step.priority.toUpperCase()} · ${step.action}`),el('p','',step.why),el('p','',`Look for: ${step.expected_result}`));citations(item,step.evidence_ids);steps.append(item);}result.append(steps);
      for(const [title,items] of [['Possible explanations',report.possible_explanations],['Evidence still needed',report.missing_evidence]]){
        const list=el('ul');for(const item of items)list.append(el('li','',item));result.append(el('h3','',title),list);
      }
      result.append(el('h3','','When to escalate'),el('p','',report.escalation_criteria));
      button.textContent='Analyze latest node snapshot';
    }catch(error){result.replaceChildren(el('p','gap',error.message));button.textContent='Retry AI analysis';}
    finally{button.disabled=false;result.setAttribute('aria-busy','false');}
  };
  return section;
}
async function inspectGroup(id,decision=null){
  let group=state.run?.groups.find(g=>g.id===id);
  if(!group){
    try{const result=await api(`/api/group?id=${state.run.id}&group=${encodeURIComponent(id)}`);group=result.group;}
    catch(error){toast(error.message);return;}
  }
  if(!group.context){
    try{
      const result=await api(`/api/group?id=${state.run.id}&group=${encodeURIComponent(id)}`);group=result.group;
      if(!group.context){
        const results=await Promise.allSettled(group.evidence.map(record=>api(`/api/evidence?id=${state.run.id}&record=${encodeURIComponent(record.id)}`)));
        const records=results.map((result,index)=>result.status==='fulfilled'?result.value.record:group.evidence[index]);
        group={...group,context:sampleContext(records),context_sample:true};
      }
    }catch(error){toast(`Episode summary retrieval: ${error.message}`);}
  }
  const content=el('div');content.append(el('h2','',group.title),el('div','rule-note',group.reason));
  if(decision){
    const section=el('section','decision-context');section.append(el('h3','','Decision at event time'),el('p','',`${decision.stage.toUpperCase()} · ${dateTime(decision.time)} UTC · event ${decision.event}`),el('p','',decision.detail));
    const button=el('button','secondary','Show triggering event');button.onclick=async()=>{button.disabled=true;try{const result=await api(`/api/evidence?id=${state.run.id}&record=${encodeURIComponent(decision.event)}`);section.append(evidenceNode(result.record));}catch(error){toast(error.message);button.disabled=false;}};
    section.append(button,el('p','detail-subtitle','The episode summary below includes all observations received by selection time.'));content.append(section);
  }
  content.append(el('div','priority-detail priority-'+group.priority,`${priorities[group.priority]} · ${group.priority_reason}`));
  content.append(falsePositiveAction(group,state.run.id));
  content.append(nodeAnalysis(group,state.run.id));
  content.append(analystSummary(group),el('p','detail-subtitle','Snapshot at selection. Credentials and embedded command payloads are redacted.'));
  const edges=state.run.edges.filter(edge=>edge.from===id||edge.to===id);
  if(edges.length){
    content.append(el('h3','',`${edges.length} connections · all shown in the map`));
    for(const edge of edges){const other=edge.from===id?edge.to:edge.from;const button=el('button','member-reference',`${edge.from} → ${edge.to}: ${edge.basis}`);button.onclick=()=>inspectGroup(other);content.append(button);}
  }
  content.append(disclosure(`Supporting records (${group.evidence.length})`,...group.evidence.map(evidenceNode)));
  const rules=el('details','rule-details');rules.append(el('summary','','Rule conditions and counterexamples'));
  for(const [key,rule] of Object.entries(group.rules||{}))rules.append(el('p','',`${key} · ${rule.version}\n${rule.condition}\nBenign explanation: ${rule.counterexample}`));
  content.append(rules);
  const actions=el('div','review-actions'),reviewButton=el('button','secondary','Investigate evidence'),membersButton=el('button','secondary','Browse every member');
  const reviewTarget=el('div','review-result'),membersTarget=el('div','member-list');
  const runId=state.run.id;
  reviewButton.onclick=async()=>{
    reviewButton.disabled=true;reviewButton.textContent='Retrieving evidence…';
    try{
      const result=await api(`/api/investigate?id=${runId}&group=${encodeURIComponent(id)}`);
      reviewTarget.replaceChildren(el('h3','',result.decision.replaceAll('_',' ')),el('p','',result.missing),el('p','detail-subtitle',`${result.mode} · ${result.queries} / ${result.budget} queries · ${result.note}`));
      for(const entry of result.ledger){
        const section=el('details','review-entry');section.append(el('summary','',`${entry.entry}. ${entry.kind}${entry.outcome?' · '+entry.outcome:''}`));
        section.append(el('p','',entry.claim||entry.explanation||entry.note||entry.error||entry.missing||''));
        for(const explanation of entry.benign_explanations||[])section.append(el('p','','Possible benign explanation: '+explanation));
        if(entry.query)section.append(el('pre','',JSON.stringify(entry.query,null,2)));
        if(entry.truncated)section.append(el('p','gap','More matches exist; retrieval reached its bound.'));
        for(const record of entry.records||[])section.append(evidenceNode(record));
        reviewTarget.append(section);
      }
      reviewButton.textContent='Review complete';
    }catch(error){toast(error.message);reviewButton.disabled=false;reviewButton.textContent='Retry investigation';}
  };
  let cursor=0;
  membersButton.onclick=async()=>{
    membersButton.disabled=true;
    try{
      const result=await api(`/api/group-members?id=${runId}&group=${encodeURIComponent(id)}&cursor=${cursor}`);
      for(const member of result.members){
        const button=el('button','member-reference',`${dateTime(member.time)} · ${member.id} · ${member.rule}${member.training?' · training':''}`);
        button.onclick=async()=>{try{const r=await api(`/api/evidence?id=${runId}&record=${encodeURIComponent(member.id)}`);button.after(evidenceNode(r.record));button.disabled=true;}catch(error){toast(error.message);}};
        membersTarget.append(button);
      }
      cursor=result.next_cursor;membersButton.textContent=cursor===null?'All members loaded':'Load next 50 members';membersButton.disabled=cursor===null;
    }catch(error){toast(error.message);membersButton.disabled=false;}
  };
  actions.append(reviewButton,membersButton);content.append(actions,reviewTarget,membersTarget);openDetail(content);
}
async function verify(scroll=true){
  if(state.run?.status!=='complete')return;
  $('verify').disabled=true;
  try{
    const result=await api('/api/verify',{id:state.run.id});state.run.verification=result;
    const total=result.rows.length, matched=result.summary?.specific_signal??0;
    const score=result.score??{percent:total?Math.round(1000*matched/total)/10:null,detected:matched,total,possible_misses:(result.summary?.unsupported_behavior??0)+(result.summary?.training_only??0),insufficient_telemetry:result.summary?.insufficient_telemetry??0,definition:'Percentage of labeled attack windows with an operational technique-specific signal. All labeled windows are included; this is detection coverage, not record-level accuracy.'};
    const overview=document.createDocumentFragment();
    const scoreCard=el('div','verification-score');
    scoreCard.append(el('span','eyebrow','VERIFICATION SCORE'),el('strong','score-value',score.percent===null?'N/A':`${score.percent}%`),el('span','', 'Attack-window detection coverage'));
    const meter=el('progress');meter.max=100;meter.value=score.percent??0;meter.setAttribute('aria-label','Attack-window detection coverage');meter.hidden=score.percent===null;scoreCard.append(meter);
    scoreCard.append(el('p','',score.total?`${fmt(score.detected)} of ${fmt(score.total)} labeled windows detected`:'No labeled windows to verify'));
    overview.append(scoreCard);
    for(const [count,label,copy,tone] of [[score.detected,'Detected','Operational technique-specific signals','good'],[score.possible_misses,'Possible misses','No specific signal, or training-only evidence','gap'],[score.insufficient_telemetry,'Insufficient telemetry','Detection could not be established','']]){
      const card=el('div','verification-stat');card.append(el('strong',tone,fmt(count)),el('span','',label),el('p','',copy));overview.append(card);
    }
    $('verification-overview').replaceChildren(overview);
    const detected=el('div');detected.append(el('strong','','Detected techniques'));
    const techniques=Object.entries(result.phases).filter(([,phase])=>phase.specific_signal>0);
    if(!techniques.length)detected.append(el('span','','No operational technique-specific signals'));
    for(const [name,phase] of techniques)detected.append(el('span','technique-chip',`${name.replaceAll('_',' ')} · ${fmt(phase.specific_signal)}/${fmt(phase.windows)} windows`));
    $('verification-detected').replaceChildren(detected);
    $('verification-note').textContent=score.definition+' Possible misses require review; false positives cannot be measured from time-window labels. '+result.isolation;
    const fragment=document.createDocumentFragment();
    for(const row of result.rows){
      const tr=el('tr');tr.append(el('td','',row.scenario+' / '+row.phase.replaceAll('_',' ')),el('td','',shortDate(row.start)+' → '+shortTime(row.end)),el('td','',fmt(row.records)));
      const signals=el('td');signals.append(el('strong',row.relevant?'good':'gap',fmt(row.relevant)+' specific'),el('div','',`${fmt(row.generic_anomalies)} generic anomalies · ${fmt(row.training_related)} training-related`),el('div','',Object.entries(row.categories).map(([name,count])=>`${names[name]} ${fmt(count)}`).join(' · ')));
      const interpretation=el('td');interpretation.append(el('span',row.relevant?'good':'gap',row.interpretation));
      const detail=el('details');detail.append(el('summary','','Evidence and telemetry'),el('p','',row.diagnosis),el('p','',`Observed operational excerpts: ${Object.entries(row.telemetry.operational).map(([key,count])=>`${key} ${fmt(count)}`).join(' · ')||'none with relevant fields'}`),el('p','',`Needed: ${row.telemetry.needed_any.join(' or ')}. Collection completeness unknown.`));
      for(const ref of row.references){const button=el('button','member-reference',ref.id+(ref.training?' · training':''));button.onclick=async()=>{try{const r=await api(`/api/evidence?id=${state.run.id}&record=${encodeURIComponent(ref.id)}`);const content=el('div');content.append(el('h2','',ref.rule),evidenceNode(r.record));openDetail(content);}catch(error){toast(error.message);}};detail.append(button);}
      const errors={specific_signal:'Possible false positive: overlap does not confirm attack attribution.',training_only:'Possible operational miss: related evidence was excluded as training.',unsupported_behavior:'Possible missed detection: relevant excerpts exist, but no specific rule fired.',insufficient_telemetry:'Unknown: relevant operational telemetry is missing.'};
      interpretation.append(detail);tr.append(signals,interpretation,el('td','verification-error',errors[row.evidence_status]));fragment.append(tr);
    }
    $('verification-rows').replaceChildren(fragment);$('verification').hidden=false;$('isolation-title').textContent='Labels read for verification';$('isolation-copy').textContent='The completed analysis remains frozen.';
    $('verify').textContent='Verification open ✓';if(scroll)$('verification').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'start'});
  }catch(error){toast(error.message);}
  finally{setControls(state.run);}
}
$('play').onclick=()=>state.run?.status==='running'?action('pause'):state.run?.status==='paused'?action('resume'):start();
$('step').onclick=()=>action('step');$('reset').onclick=reset;$('verify').onclick=()=>verify();
async function selectionChanged(){try{localStorage.setItem('trace-datasets',JSON.stringify(selected()));}catch{}await reset();prepareSelected();}
for(const input of document.querySelectorAll('#dataset-options input'))input.onchange=selectionChanged;
$('select-all').onclick=()=>{for(const input of document.querySelectorAll('#dataset-options input'))input.checked=true;selectionChanged();};
$('select-none').onclick=()=>{for(const input of document.querySelectorAll('#dataset-options input'))input.checked=false;selectionChanged();};
$('dataset-view').onchange=()=>{renderFeed();renderGraph();renderGroups();renderLedger();if(state.run)render(state.run);};
for(const id of ['duration','pacing'])$(id).onchange=renderReady;
for(const id of ['source-filter','search'])$(id).addEventListener(id==='search'?'input':'change',renderFeed);
$('show-routine').onchange=renderGroups;
$('graph-mode').onclick=()=>{state.graphAll=!state.graphAll;$('graph-mode').textContent=state.graphAll?'All groups ▾':'Signals ▾';renderGraph();};
function setGraphLayout(original) {
  originalMap=original;
  $('graph').toggleAttribute('hidden',!original);
  $('horizontal-map').hidden=original;
  $('graph-motion').hidden=!original;
  $('graph-fit').hidden=false;
  $('horizontal-controls').hidden=original;
  $('graph-layout').textContent=original?'Show horizontal map':'Show original map';
  $('graph-layout').setAttribute('aria-pressed',String(original));
  $('map-hint').textContent=original?'Drag to move · scroll to zoom':'Drag to move · scroll to zoom · expand connections';
  evidenceGraph.tooltip.hidden=true;
  if(!original)evidenceGraph.simulation.stop();
  renderGraph();
  if(original)evidenceGraph.resize();
  try{localStorage.setItem('trace-graph-layout',original?'original':'horizontal');}catch{}
}
$('graph-layout').onclick=()=>setGraphLayout(!originalMap);
try{setGraphLayout(localStorage.getItem('trace-graph-layout')==='original');}catch{setGraphLayout(false);}
$('graph-fit').onclick=()=>{if(originalMap){evidenceGraph.userCamera=false;evidenceGraph.fit();}else horizontalMap.fit();};
$('map-collapse').onclick=()=>{horizontalMap.expandAll(false);renderGraph();};
$('map-expand').onclick=()=>{horizontalMap.expandAll(true);renderGraph();};
$('map-zoom-out').onclick=()=>horizontalMap.zoomBy(1/1.2);
$('map-zoom-in').onclick=()=>horizontalMap.zoomBy(1.2);
$('graph-motion').onclick=()=>{evidenceGraph.freeze(!evidenceGraph.frozen);$('graph-motion').textContent=evidenceGraph.frozen?'Unfreeze':'Freeze';$('graph-motion').setAttribute('aria-pressed',String(evidenceGraph.frozen));};
$('ledger-mode').onclick=()=>{state.signalLedger=!state.signalLedger;$('ledger-mode').textContent=state.signalLedger?'Signals ▾':'All decisions ▾';renderLedger();};
$('method-btn').onclick=()=>$('method-dialog').showModal();
for(const button of document.querySelectorAll('.close-dialog'))button.onclick=()=>button.closest('dialog').close();
for(const dialog of document.querySelectorAll('dialog'))dialog.addEventListener('click',event=>{if(event.target===dialog){const r=dialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)dialog.close();}});
$('graph-mode').textContent='All groups ▾';
try{const saved=JSON.parse(localStorage.getItem('trace-datasets'));if(Array.isArray(saved)&&saved.length&&saved.every(name=>[...document.querySelectorAll('#dataset-options input')].some(input=>input.value===name))){for(const input of document.querySelectorAll('#dataset-options input'))input.checked=saved.includes(input.value);}}catch{}
async function initialize() {
  const id=new URLSearchParams(location.search).get('run');
  let completed=null;
  if(id){
    try{
      const run=await api('/api/run?id='+encodeURIComponent(id));
      if(run.status!=='complete')throw Error('This replay has not completed. Start a fresh replay to continue.');
      completed=run;
      for(const input of document.querySelectorAll('#dataset-options input'))input.checked=run.scenarios.includes(input.value);
      $('duration').value=String(run.duration);$('pacing').value=run.pacing;
    }catch(error){toast('Saved replay unavailable: '+error.message);history.replaceState(null,'','/');}
  }
  await prepareSelected();
  if(completed&&state.meta){
    state.run=completed;render(completed);
    if(completed.verification)await verify(false);
  }
}
// Remember disclosure choices without allowing stream updates to reopen panels.
for(const panel of document.querySelectorAll('[data-remember]')){
  const key='trace-panel-'+panel.id;
  try{const saved=localStorage.getItem(key);if(saved!==null)panel.open=saved==='open';}catch{}
  panel.addEventListener('toggle',()=>{try{localStorage.setItem(key,panel.open?'open':'closed');}catch{}});
}
// Pointer capture keeps resizing reliable when the divider moves under the cursor.
const workspace = document.querySelector('.workspace');
const workspaceDivider = $('workspace-divider');
let treeShare = 50;
function setWorkspaceSplit(percent) {
  treeShare = Math.max(20, Math.min(80, percent));
  workspace.style.setProperty('--tree-share', `${treeShare}fr`);
  workspace.style.setProperty('--records-share', `${100-treeShare}fr`);
  workspaceDivider.setAttribute('aria-valuenow', String(Math.round(treeShare)));
  workspaceDivider.setAttribute('aria-valuetext', `Tree ${Math.round(treeShare)}%, live records ${Math.round(100-treeShare)}%`);
}
setWorkspaceSplit(50);
let resizePointer = null;
workspaceDivider.addEventListener('pointerdown', event => {
  if(event.button !== 0 || !matchMedia('(min-width: 721px)').matches) return;
  event.preventDefault();
  resizePointer = event.pointerId;
  workspaceDivider.setPointerCapture(event.pointerId);
  workspaceDivider.focus();
  workspace.classList.add('resizing');
});
workspaceDivider.addEventListener('pointermove', event => {
  if(event.pointerId !== resizePointer) return;
  const bounds = workspace.getBoundingClientRect();
  const dividerWidth = workspaceDivider.getBoundingClientRect().width;
  setWorkspaceSplit((event.clientX-bounds.left-dividerWidth/2)/(bounds.width-dividerWidth)*100);
});
function finishWorkspaceResize(event) {
  if(event.pointerId !== resizePointer) return;
  resizePointer = null;
  workspace.classList.remove('resizing');
  if(workspaceDivider.hasPointerCapture(event.pointerId)) workspaceDivider.releasePointerCapture(event.pointerId);
}
for(const type of ['pointerup','pointercancel','lostpointercapture']) workspaceDivider.addEventListener(type, finishWorkspaceResize);
workspaceDivider.addEventListener('dblclick', () => setWorkspaceSplit(50));
workspaceDivider.addEventListener('keydown', event => {
  const step = event.shiftKey ? 10 : 2;
  const changes = {ArrowLeft: treeShare-step, ArrowRight: treeShare+step, Home: 20, End: 80, Enter: 50};
  if(Object.hasOwn(changes, event.key)) { event.preventDefault(); setWorkspaceSplit(changes[event.key]); }
});
renderFalsePositives();
initialize();

// Native details stays keyboard accessible; dismiss the menu like a standard popover.
document.addEventListener('pointerdown', event => {
  for(const id of ['datasets','replay-settings'])if (!$(id).contains(event.target)) $(id).open = false;
});
document.addEventListener('keydown', event => {
  if(event.key==='Escape')for(const id of ['datasets','replay-settings'])if($(id).open){$(id).open=false;$(id).querySelector('summary').focus();}
});
