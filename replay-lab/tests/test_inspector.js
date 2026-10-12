'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../static/app.js'), 'utf8');
const sandbox = {state: {graphAll: false, run: {groups: [], edges: []}}, inView: g => g.scenario === 'selected', importanceOrder: () => 0};
vm.createContext(sandbox);
vm.runInContext(source.slice(source.indexOf('function graphGroups()'), source.indexOf('function renderGraph()')), sandbox);
vm.runInContext(source.slice(source.indexOf('function inspectionFrequency('), source.indexOf('function analystSummary(')), sandbox);
for (let index = 0; index < 120; index++) {
  sandbox.state.run.groups.push({id: 'g'+index, scenario:'selected', priority:index%2?'routine':'high'});
  if(index) sandbox.state.run.edges.push({from:'g'+(index-1), to:'g'+index});
}
sandbox.state.run.groups.push({id:'other',scenario:'other',priority:'high'});
const displayed = new Set(sandbox.graphGroups().map(group => group.id));
assert.equal(displayed.size, 120, 'All endpoints survive the former 80-node cap and routine filter');
for(const edge of sandbox.state.run.edges)assert.ok(displayed.has(edge.from)&&displayed.has(edge.to));
assert.ok(!displayed.has('other'), 'Dataset filter remains respected');
const frequency=sandbox.inspectionFrequency({count:4,unique:3,first:'2022-01-17T11:24:14Z',last:'2022-01-17T11:24:45Z'});
assert.equal(frequency.duration_seconds,31);
assert.equal(frequency.repeated_records,1);
assert.equal(frequency.records_per_minute,240/31);
assert.equal(sandbox.inspectionFrequency({count:1,unique:1,first:'2022-01-17T11:24:14Z',last:'2022-01-17T11:24:14Z'}).records_per_minute,null);
const context=sandbox.sampleContext([{src:'192.0.2.1',origin_file:'/var/log/access.log',source:'Wazuh'},{src:'192.0.2.1',location:'/var/log/access.log',source:'AMiner'}]);
assert.equal(context.src.values[0].records,2);
assert.equal(context.location.values[0].records,2);
assert.equal(context.dst.values.length,0);
console.log('Inspector regressions passed: complete connections, legacy frequency, evidence context.');
