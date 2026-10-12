'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../static/app.js'),'utf8');
const group=(id,priority,last_ts,scenario='a',priority_score=0)=>({id,priority,last_ts,scenario,priority_score});
const groups=[group('high','high',200),group('investigation','investigate',0),group('isolated','investigate',0),
  group('context1','context',100,'a',10),group('context2','context',200,'a',20),group('deep','context',300,'a',30),
  group('highNoise','routine',100),group('other','investigate',10,'b'),group('otherContext','context',20,'b',10)];
const edges=[{from:'high',to:'investigation'},{from:'context1',to:'investigation'},
  {from:'investigation',to:'context2'},{from:'context2',to:'deep'},{from:'high',to:'highNoise'},
  {from:'deep',to:'high'},{from:'context2',to:'investigation'},{from:'other',to:'otherContext'}];
const context={state:{run:{groups,edges,logs:[{scenario:'a',timestamp:10000}]}},inView:()=>true,
  importanceOrder:(a,b)=>b.priority_score-a.priority_score||b.last_ts-a.last_ts||a.id.localeCompare(b.id)};
vm.createContext(context);
vm.runInContext(source.slice(source.indexOf('function graphGroups()'),source.indexOf('function renderGraph()')),context);
const ids=()=>Array.from(context.graphGroups(),g=>g.id).sort();
assert.deepEqual(ids(),['context2','high','investigation','isolated','other','otherContext']);
// Replay age never hides investigations. High nodes do not pull entire chains in.
context.state.run.logs=[{scenario:'a',timestamp:20000}];
assert.deepEqual(ids(),['context2','high','investigation','isolated','other','otherContext']);
// Selection does not depend on edge orientation, ordering, duplicates or cycles.
context.state.run.edges=edges.slice().reverse().map(e=>({from:e.to,to:e.from}));
assert.deepEqual(ids(),['context2','high','investigation','isolated','other','otherContext']);
context.inView=g=>g.scenario==='b';
assert.deepEqual(ids(),['other','otherContext']);
context.inView=g=>g.scenario==='a';
context.state.run.edges=[];
assert.deepEqual(ids(),['high','investigation','isolated']);
context.state.run=null;
assert.deepEqual(ids(),[]);
console.log('Graph selection passed: all investigations, one ranked supporting node, no recursive or High context expansion, cycles and dataset filtering.');
