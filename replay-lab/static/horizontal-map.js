'use strict';

// Breadth-first columns organize undirected relationships; they imply no chronology.
function horizontalLayout(groups, edges) {
  const nodes=new Map(groups.map(group=>[group.id,group]));
  const links=edges.filter(edge=>nodes.has(edge.from)&&nodes.has(edge.to));
  const neighbors=new Map(groups.map(group=>[group.id,new Set()]));
  for(const edge of links){neighbors.get(edge.from).add(edge.to);neighbors.get(edge.to).add(edge.from);}
  const seen=new Set(),positions=new Map(),clusters=[];let offset=40,maxColumn=0;
  for(const root of groups){
    if(seen.has(root.id))continue;
    const columns=[],queue=[{id:root.id,depth:0}];seen.add(root.id);
    for(let index=0;index<queue.length;index++){
      const item=queue[index];(columns[item.depth]??=[]).push(item.id);
      for(const id of neighbors.get(item.id))if(!seen.has(id)){seen.add(id);queue.push({id,depth:item.depth+1});}
    }
    clusters.push({root:root.id,members:queue.map(item=>item.id)});
    const rows=Math.max(...columns.map(column=>column.length));
    columns.forEach((column,depth)=>column.forEach((id,row)=>positions.set(id,{x:24+depth*300,y:offset+row*148})));
    maxColumn=Math.max(maxColumn,columns.length-1);offset+=rows*148+28;
  }
  return {positions,links,clusters,width:Math.max(560,24+maxColumn*300+296),height:Math.max(220,offset),columns:maxColumn+1};
}

class HorizontalEvidenceMap {
  constructor(world, inspect, changed=()=>{}){
    this.changed=changed;this.world=world;this.viewport=world.parentElement;this.inspect=inspect;this.signature='';
    this.collapsed=new Set();this.offsets=new Map();this.transform=d3.zoomIdentity;
    this.zoom=d3.zoom().scaleExtent([.2,3])
      .filter(event=>(event.type==='wheel'||!event.target.closest('.horizontal-node,.relationship-toggle'))&&!event.button)
      .on('zoom',event=>{this.transform=event.transform;this.world.style.transform=`translate(${event.transform.x}px,${event.transform.y}px) scale(${event.transform.k})`;document.getElementById('map-zoom-value').textContent=Math.round(event.transform.k*100)+'%';});
    d3.select(this.viewport).call(this.zoom).on('dblclick.zoom',null);
  }
  zoomBy(factor){d3.select(this.viewport).call(this.zoom.scaleBy,factor);}
  fit(){
    if(!this.layout)return;
    const positions=[...this.layout.positions.values()];
    if(!positions.length){d3.select(this.viewport).call(this.zoom.transform,d3.zoomIdentity);return;}
    const x0=Math.min(...positions.map(p=>p.x)),y0=Math.min(...positions.map(p=>p.y));
    const x1=Math.max(...positions.map(p=>p.x+280)),y1=Math.max(...positions.map(p=>p.y+130));
    const box=this.viewport.getBoundingClientRect(),scale=Math.max(.2,Math.min(1,(box.width-32)/(x1-x0),(box.height-32)/(y1-y0)));
    d3.select(this.viewport).call(this.zoom.transform,d3.zoomIdentity.translate(16-x0*scale,16-y0*scale).scale(scale));
  }
  expandAll(expand){
    this.collapsed=expand?new Set():new Set(horizontalLayout(this.groups||[],this.edges||[]).clusters.filter(c=>c.members.length>1).map(c=>c.root));
    this.signature='';this.update(this.groups||[],this.edges||[]);
  }
  reset(){this.world.replaceChildren();this.signature='';this.groups=[];this.edges=[];this.collapsed.clear();this.offsets.clear();d3.select(this.viewport).call(this.zoom.transform,d3.zoomIdentity);}
  paint(){
    for(const card of this.world.querySelectorAll('.horizontal-node,.relationship-toggle')){
      const position=this.layout.positions.get(card.dataset.horizontalGroup||card.dataset.cluster);
      card.style.left=position.x+'px';card.style.top=(position.y+(card.dataset.cluster?110:0))+'px';
    }
    for(const path of this.world.querySelectorAll('.horizontal-links path')){
      const a=this.layout.positions.get(path.dataset.from),b=this.layout.positions.get(path.dataset.to);
      const forward=a.x!==b.x,left=a.x<b.x?a:b,right=a.x<b.x?b:a;
      const x1=forward?left.x+248:a.x+248,y1=forward?left.y+52:a.y+52;
      const x2=forward?right.x:b.x+248,y2=forward?right.y+52:b.y+52;
      const bend=forward?(x1+x2)/2:x1+32;
      path.setAttribute('d',`M ${x1} ${y1} C ${bend} ${y1}, ${bend} ${y2}, ${x2} ${y2}`);
    }
  }
  update(groups,edges){
    this.groups=groups;this.edges=edges;
    if(this.dragging)return {nodes:this.layout.positions.size,links:this.layout.links.length};
    const full=horizontalLayout(groups,edges),hidden=new Set();
    for(const cluster of full.clusters)if(this.collapsed.has(cluster.root))for(const id of cluster.members)if(id!==cluster.root)hidden.add(id);
    const available=groups.filter(group=>!hidden.has(group.id));
    const layout=horizontalLayout(available,edges);
    for(const [id,position] of layout.positions){const offset=this.offsets.get(id);if(offset){position.x+=offset.x;position.y+=offset.y;}}
    const signature=JSON.stringify([groups,layout.links,[...this.collapsed]]);
    if(signature===this.signature)return {nodes:available.length,links:layout.links.length};
    this.signature=signature;this.layout=layout;
    const focused=document.activeElement?.dataset.horizontalGroup;
    const fragment=document.createDocumentFragment();
    const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
    svg.setAttribute('width',layout.width);svg.setAttribute('height',layout.height);svg.setAttribute('aria-hidden','true');svg.classList.add('horizontal-links');
    for(const edge of layout.links){
      const path=document.createElementNS(svg.namespaceURI,'path');
      path.setAttribute('class','graph-edge'+(edge.confidence==='low'?' weak':''));
      path.dataset.from=edge.from;path.dataset.to=edge.to;svg.append(path);
    }
    fragment.append(svg);
    for(let column=0;groups.length&&column<layout.columns;column++){
      const label=el('span','horizontal-column',column===0?'Evidence clusters':`Connection level ${column}`);
      label.style.left=(24+column*300)+'px';fragment.append(label);
    }
    for(const group of available){
      const position=layout.positions.get(group.id),card=el('button','horizontal-node priority-'+group.priority);
      card.dataset.horizontalGroup=group.id;card.style.left=position.x+'px';card.style.top=position.y+'px';
      card.setAttribute('aria-label',`${group.title}, ${priorities[group.priority]}, ${group.scenario}, ${group.host}, ${group.unique} distinct evidence records. Inspect evidence.`);
      card.title=`${group.title}\n${group.priority_reason}\n${group.actor} → ${group.host}\nConnections show shared evidence, not causality.`;
      const heading=el('div','horizontal-node-heading');heading.append(el('span','',priorities[group.priority]),el('span','mono',group.id.toUpperCase()));
      card.append(heading,el('strong','horizontal-title',group.title),el('span','horizontal-context',`${group.scenario} · ${group.host}`),el('span','horizontal-counts',`${fmt(group.unique)} distinct · ${fmt(group.count)} records · ${fmt(group.connections)} links`),el('span','horizontal-updated',`Latest ${group.last?.slice(5,10)||'—'} ${shortTime(group.last)} UTC`));
      card.onclick=event=>{if(!this.suppressClick)this.inspect(group.id);};
      card.onpointerdown=event=>{
        if(event.button!==0)return;
        event.stopPropagation();card.setPointerCapture(event.pointerId);
        this.dragging={id:group.id,startX:event.clientX,startY:event.clientY,x:position.x,y:position.y,offset:this.offsets.get(group.id)||{x:0,y:0},moved:false};
      };
      card.onpointermove=event=>{
        const drag=this.dragging;if(!drag||drag.id!==group.id)return;
        const dx=(event.clientX-drag.startX)/this.transform.k,dy=(event.clientY-drag.startY)/this.transform.k;
        if(Math.hypot(event.clientX-drag.startX,event.clientY-drag.startY)>4)drag.moved=true;
        if(!drag.moved)return;
        card.classList.add('dragging');position.x=drag.x+dx;position.y=drag.y+dy;
        this.offsets.set(group.id,{x:drag.offset.x+dx,y:drag.offset.y+dy});this.paint();
      };
      const finish=()=>{
        if(!this.dragging)return;
        this.suppressClick=this.dragging.moved;this.dragging=null;card.classList.remove('dragging');
        setTimeout(()=>{this.suppressClick=false;this.signature='';this.update(this.groups,this.edges);},0);
      };
      card.onpointerup=finish;card.onpointercancel=finish;
      card.onkeydown=event=>{
        const delta={ArrowLeft:[-12,0],ArrowRight:[12,0],ArrowUp:[0,-12],ArrowDown:[0,12]}[event.key];
        if(!delta)return;event.preventDefault();const offset=this.offsets.get(group.id)||{x:0,y:0};
        offset.x+=delta[0];offset.y+=delta[1];this.offsets.set(group.id,offset);position.x+=delta[0];position.y+=delta[1];this.paint();
      };
      const highlight=()=>{
        const neighbors=new Set([group.id]);
        for(const edge of layout.links)if(edge.from===group.id||edge.to===group.id){neighbors.add(edge.from);neighbors.add(edge.to);}
        this.world.querySelectorAll('.horizontal-node').forEach(node=>node.classList.toggle('dimmed',!neighbors.has(node.dataset.horizontalGroup)));
        svg.querySelectorAll('path').forEach(path=>{const active=path.dataset.from===group.id||path.dataset.to===group.id;path.classList.toggle('dimmed',!active);path.classList.toggle('highlighted',active);});
      };
      const clear=()=>this.world.querySelectorAll('.dimmed,.highlighted').forEach(node=>node.classList.remove('dimmed','highlighted'));
      card.onmouseenter=highlight;card.onfocus=highlight;card.onmouseleave=()=>{if(document.activeElement!==card)clear();};card.onblur=clear;
      fragment.append(card);
    }
    for(const cluster of full.clusters){
      if(cluster.members.length<2)continue;
      const toggle=el('button','relationship-toggle');toggle.dataset.cluster=cluster.root;
      const expanded=!this.collapsed.has(cluster.root);
      toggle.textContent=(expanded?'− Collapse':'＋ Expand')+` ${cluster.members.length-1} related`;
      toggle.setAttribute('aria-expanded',String(expanded));toggle.setAttribute('aria-label',`${expanded?'Collapse':'Expand'} relationships for ${cluster.root.toUpperCase()}`);
      toggle.onclick=()=>{expanded?this.collapsed.add(cluster.root):this.collapsed.delete(cluster.root);this.signature='';this.update(this.groups,this.edges);this.changed();this.world.querySelector(`[data-cluster="${cluster.root}"]`)?.focus({preventScroll:true});};
      fragment.append(toggle);
    }
    this.world.style.width=layout.width+'px';this.world.style.height=layout.height+'px';this.world.replaceChildren(fragment);this.paint();
    if(focused){const card=[...this.world.querySelectorAll('.horizontal-node')].find(node=>node.dataset.horizontalGroup===focused);card?.focus({preventScroll:true});}
    return {nodes:available.length,links:layout.links.length};
  }
}
