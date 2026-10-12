'use strict';

// D3 owns only layout and interaction. Every node and link comes from online evidence.
class EvidenceGraph {
  constructor(element, {inspect, tooltip, container}) {
    this.element = element;
    this.inspect = inspect;
    this.tooltip = tooltip;
    this.container = container;
    this.nodes = [];
    this.links = [];
    this.cache = new Map();
    this.signature = '';
    this.frozen = false;
    this.userCamera = false;
    this.media = matchMedia('(prefers-reduced-motion: reduce)');
    this.root = d3.select(element);
    this.world = this.root.append('g').attr('class', 'graph-world');
    this.linkLayer = this.world.append('g').attr('class', 'graph-links');
    this.nodeLayer = this.world.append('g').attr('class', 'graph-nodes');
    this.zoom = d3.zoom().scaleExtent([.25, 4])
      .filter(event => !event.target.closest('.graph-node') && (!event.ctrlKey || event.type === 'wheel') && !event.button)
      .on('zoom', event => {
        this.world.attr('transform', event.transform);
        this.zoomScale = event.transform.k;
        if (event.sourceEvent) this.userCamera = true;
        this.tooltip.hidden = true;
        this.paint();
      });
    this.root.call(this.zoom).on('dblclick.zoom', null);
    this.linkForce = d3.forceLink().id(d => d.id)
      .distance(d => d.confidence === 'low' ? 95 : 72)
      .strength(d => d.confidence === 'low' ? .12 : .34);
    this.simulation = d3.forceSimulation([])
      .force('link', this.linkForce)
      .force('charge', d3.forceManyBody().strength(-105).distanceMax(360))
      .force('collide', d3.forceCollide(d => d.radius + 13).strength(.8).iterations(2))
      .force('x', d3.forceX(d => this.center(d).x).strength(.045))
      .force('y', d3.forceY(d => this.center(d).y).strength(.065))
      .velocityDecay(.3).alphaDecay(.045)
      .on('tick', () => this.paint())
      .on('end', () => { if (!this.userCamera) this.fit(); })
      .stop();
    this.drag = d3.drag().container(() => this.world.node()).clickDistance(4)
      .on('start', (event, node) => {
        event.sourceEvent.stopPropagation();
        this.userCamera = true;
        node.fx = node.x; node.fy = node.y;
        this.tooltip.hidden = true;
        d3.select(event.sourceEvent.target.closest('.graph-node')).classed('dragging', true);
        if (this.animated && !event.active) this.simulation.alphaTarget(.16).restart();
      })
      .on('drag', (event, node) => {
        node.x = node.fx = event.x; node.y = node.fy = event.y;
        node.vx = node.vy = 0;
        this.paint(); // Lines track the exact endpoints, even with motion frozen.
      })
      .on('end', (event, node) => {
        node.fx = node.fy = null;
        this.nodeSelection.classed('dragging', false);
        if (!event.active) this.simulation.alphaTarget(0);
        if (this.animated) this.simulation.alpha(.36).restart();
        else if (!this.frozen) this.settle();
      });
    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(container);
    this.media.addEventListener('change', () => this.reheat());
    this.resize();
  }

  get animated() { return !this.frozen && !this.media.matches; }

  center(node) {
    const index = this.datasets?.indexOf(node.scenario) || 0;
    const total = this.datasets?.length || 1;
    const angle = index / total * Math.PI * 2 - Math.PI / 2;
    return {
      x: this.width / 2 + (total > 1 ? Math.cos(angle) * this.width * .24 : 0),
      y: this.height / 2 + (total > 1 ? Math.sin(angle) * this.height * .22 : 0),
    };
  }

  resize() {
    const box = this.element.getBoundingClientRect();
    this.width = Math.max(240, box.width);
    this.height = Math.max(190, box.height);
    this.root.attr('viewBox', `0 0 ${this.width} ${this.height}`);
    this.zoom.extent([[0, 0], [this.width, this.height]]);
    this.simulation.force('x').x(d => this.center(d).x);
    this.simulation.force('y').y(d => this.center(d).y).strength(Math.min(.22, .06 * this.width / this.height));
    this.reheat();
  }

  update(groups, edges) {
    this.datasets = [...new Set(groups.map(g => g.scenario))].sort();
    const ids = new Set(groups.map(g => g.id));
    const evidenceLinks = edges.filter(e => ids.has(e.from) && ids.has(e.to));
    const signature = groups.map(g => g.id).sort().join(',') + '/' + evidenceLinks.map(e => e.id).sort().join(',');
    const changed = signature !== this.signature;
    this.nodes = groups.map(group => {
      let node = this.cache.get(group.id);
      if (!node) {
        const center = this.center(group), index = Number(group.id.slice(1));
        const angle = index * 2.39996, radius = 18 + (index % 23) * 3;
        node = {id: group.id, x: center.x + Math.cos(angle) * radius, y: center.y + Math.sin(angle) * radius, vx: 0, vy: 0};
        // A new related group enters next to evidence already on screen.
        const edge = evidenceLinks.find(e => e.from === group.id || e.to === group.id);
        const neighbor = edge && this.cache.get(edge.from === group.id ? edge.to : edge.from);
        if (neighbor) { node.x = neighbor.x + Math.cos(angle) * 45; node.y = neighbor.y + Math.sin(angle) * 45; }
        this.cache.set(group.id, node);
      }
      Object.assign(node, group);
      // Distinct evidence, capped, affects size. Detector repeats do not inflate it.
      node.radius = 5 + Math.min(5, Math.log2(1 + group.unique) * .65) + (group.priority === 'high' ? 3 : 0);
      return node;
    });
    this.linkSelection = this.linkLayer.selectAll('line').data(evidenceLinks, d => d.id).join(
      enter => { const line = enter.append('line'); line.append('title'); return line; },
      update => update,
      exit => exit.remove()
    ).attr('class', d => 'graph-edge' + (d.confidence === 'low' ? ' weak' : ''))
      .attr('data-from', d => d.from).attr('data-to', d => d.to);
    this.linkSelection.select('title').text(d => (d.relationship || 'inferred') + ' relationship · ' + d.basis + ' · alerts ' + (d.evidence_ids || []).join(', ') + ' · ' + d.time);
    this.nodeSelection = this.nodeLayer.selectAll('.graph-node').data(this.nodes, d => d.id).join(
      enter => {
        const node = enter.append('g').attr('tabindex', 0).attr('role', 'button');
        node.append('circle').attr('class', 'node-hit').attr('r', 18);
        node.append('circle').attr('class', 'node-dot');
        node.append('text').attr('class', 'node-name').attr('text-anchor', 'middle');
        node.append('text').attr('class', 'node-subtitle').attr('text-anchor', 'middle');
        node.append('title');
        node.call(this.drag)
          .on('click', (event, d) => { if (!event.defaultPrevented) this.inspect(d.id); })
          .on('mouseenter', (event, d) => this.highlight(d, event))
          .on('mouseleave', () => this.clearHighlight())
          .on('focus', (event, d) => this.highlight(d, event))
          .on('blur', () => this.clearHighlight())
          .on('keydown', (event, d) => {
            if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); this.inspect(d.id); }
            const delta = {ArrowLeft: [-12, 0], ArrowRight: [12, 0], ArrowUp: [0, -12], ArrowDown: [0, 12]}[event.key];
            if (delta) {
              event.preventDefault(); this.simulation.stop();
              d.x += delta[0]; d.y += delta[1]; d.vx = d.vy = 0; this.paint();
            }
          });
        return node;
      },
      update => update,
      exit => exit.remove()
    ).attr('class', d => 'graph-node priority-' + d.priority)
      .attr('data-group', d => d.id).attr('data-priority', d => d.priority)
      .attr('aria-label', d => `${d.priority} priority: ${d.title}, ${d.scenario}, ${d.host}, ${d.unique} distinct evidence records. Enter to inspect; arrow keys to move.`);
    this.nodeSelection.select('.node-dot').attr('r', d => d.radius);
    this.nodeSelection.select('.node-name').attr('y', d => d.radius + 14)
      .text(d => d.label = this.nodes.length <= 28 || d.priority === 'high' ? `${names[d.family]} · ${d.id.toUpperCase()}` : d.id.toUpperCase());
    this.nodeSelection.select('.node-subtitle').attr('y', d => d.radius + 26)
      .text(d => d.sublabel = this.nodes.length <= 20 || d.priority === 'high' ? d.scenario : '');
    this.nodeSelection.select('title').text(d => `${d.title} · ${d.scenario}\n${d.actor} → ${d.host}\n${d.priority_reason}\n${d.unique} distinct / ${d.count} records`);
    this.simulation.force('collide').radius(d => d.radius + (this.nodes.length > 28 ? 12 : 24));
    if (changed) {
      this.signature = signature;
      this.linkForce.links([]);
      this.simulation.nodes(this.nodes);
      this.links = evidenceLinks.map(e => ({...e, source: e.from, target: e.to}));
      this.linkForce.links(this.links);
      this.simulation.force('x').x(d => this.center(d).x);
      this.simulation.force('y').y(d => this.center(d).y);
      this.clearHighlight();
      this.reheat();
    }
    this.paint();
    return {nodes: this.nodes.length, links: this.links.length};
  }

  paint() {
    if (!this.nodeSelection || !this.nodes.length) return;
    const scale = this.zoomScale || 1;
    this.nodeSelection.attr('transform', d => `translate(${d.x},${d.y})`);
    // Keep labels readable when Fit scales a larger network down.
    this.nodeSelection.select('.node-name').style('font-size', 9 / scale + 'px')
      .style('stroke-width', 2 / scale + 'px').attr('y', d => d.radius + 14 / scale);
    this.nodeSelection.select('.node-subtitle').style('font-size', 8 / scale + 'px')
      .style('stroke-width', 2 / scale + 'px').attr('y', d => d.radius + 26 / scale);
    const positions = new Map(this.nodes.map(d => [d.id, d]));
    this.linkSelection
      .attr('x1', d => positions.get(d.from).x).attr('y1', d => positions.get(d.from).y)
      .attr('x2', d => positions.get(d.to).x).attr('y2', d => positions.get(d.to).y);
    // Label collision handling does not change evidence or move the circles.
    // Most important labels get space first; the hovered / focused label always wins.
    const occupied = [];
    const ordered = [...this.nodes].sort((a, b) =>
      Number(b.id === this.activeId) - Number(a.id === this.activeId) || b.priority_score - a.priority_score);
    for (const node of ordered) {
      const width = (Math.max(node.label.length * 5.5, node.sublabel.length * 4.9) + 8) / scale;
      const area = {x0: node.x - width / 2, x1: node.x + width / 2,
        y0: node.y + node.radius + 5 / scale, y1: node.y + node.radius + (node.sublabel ? 30 : 18) / scale};
      node.labelVisible = !occupied.some(other => area.x0 < other.x1 && area.x1 > other.x0 && area.y0 < other.y1 && area.y1 > other.y0);
      if (node.labelVisible) occupied.push(area);
    }
    this.nodeSelection.selectAll('.node-name,.node-subtitle').style('visibility', d => d.labelVisible ? 'visible' : 'hidden');
  }

  highlight(node, event) {
    this.activeId = node.id;
    const neighbors = new Set([node.id]);
    for (const link of this.links) {
      if (link.from === node.id) neighbors.add(link.to);
      if (link.to === node.id) neighbors.add(link.from);
    }
    this.nodeSelection.classed('dimmed', d => !neighbors.has(d.id)).classed('highlighted', d => neighbors.has(d.id));
    this.linkSelection.classed('dimmed', d => d.from !== node.id && d.to !== node.id).classed('highlighted', d => d.from === node.id || d.to === node.id);
    this.tooltip.replaceChildren();
    const heading = document.createElement('strong'); heading.textContent = node.title;
    const detail = document.createElement('span'); detail.textContent = `${node.scenario} / ${node.host} · ${node.priority} priority · ${node.confidence} confidence`;
    const counts = document.createElement('span'); counts.textContent = `${node.unique.toLocaleString()} distinct · ${node.count.toLocaleString()} records · ${node.connections} connections`;
    this.tooltip.append(heading, detail, counts);
    this.tooltip.hidden = false;
    const box = this.container.getBoundingClientRect();
    this.tooltip.style.left = Math.max(8, Math.min(this.width - 268, (event.clientX || box.left + this.width / 2) - box.left + 14)) + 'px';
    this.tooltip.style.top = Math.max(8, Math.min(this.height - 88, (event.clientY || box.top + 20) - box.top - 92)) + 'px';
    this.paint();
  }

  clearHighlight() {
    this.activeId = null;
    this.nodeSelection?.classed('dimmed', false).classed('highlighted', false);
    this.linkSelection?.classed('dimmed', false).classed('highlighted', false);
    this.tooltip.hidden = true;
    this.paint();
  }

  reheat() {
    if (this.element.hasAttribute('hidden')) { this.simulation.stop(); return; }
    if (!this.nodes.length) return;
    if (this.animated) this.simulation.alpha(Math.max(.45, this.simulation.alpha())).restart();
    else if (!this.frozen) this.settle();
    else { this.simulation.stop(); this.paint(); if (!this.userCamera) this.fit(); }
  }

  settle() {
    this.simulation.stop().alpha(.7).alphaTarget(0).tick(140);
    this.paint();
    if (!this.userCamera) this.fit();
  }

  freeze(value) {
    this.frozen = value;
    if (value) this.simulation.stop();
    else this.reheat();
  }

  fit() {
    if (!this.nodes.length) { this.root.call(this.zoom.transform, d3.zoomIdentity); return; }
    const x0 = d3.min(this.nodes, d => d.x - 50), x1 = d3.max(this.nodes, d => d.x + 50);
    const y0 = d3.min(this.nodes, d => d.y - 26), y1 = d3.max(this.nodes, d => d.y + 40);
    const scale = Math.max(.25, Math.min(1.5, (this.width - 34) / (x1 - x0), (this.height - 42) / (y1 - y0)));
    this.root.call(this.zoom.transform, d3.zoomIdentity.translate(this.width / 2 - (x0 + x1) / 2 * scale, this.height / 2 - (y0 + y1) / 2 * scale).scale(scale));
  }

  reset() {
    this.simulation.stop().alphaTarget(0);
    this.linkForce.links([]); this.simulation.nodes([]);
    this.nodes = []; this.links = []; this.cache.clear(); this.signature = ''; this.userCamera = false;
    this.linkLayer.selectAll('*').remove(); this.nodeLayer.selectAll('*').remove();
    this.clearHighlight(); this.root.call(this.zoom.transform, d3.zoomIdentity);
  }
}
