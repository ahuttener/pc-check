/*!
 * PC Check speedometer | CyberSecInfo | MIT License
 * Draws an animated SVG gauge. Knows nothing about the speed test itself.
 * ES2017; styles go through SVG attributes so the page's strict CSP holds.
 */
(function () {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var TICKS = [0, 5, 10, 50, 100, 250, 500, 750, 1000];
  var CX = 150, CY = 150, R = 118;
  var START = 135, SWEEP = 270; // degrees, clockwise from the positive x axis
  var PHASES = ['ping', 'download', 'upload'];

  // Map Mbps onto 0..1: ticks are evenly spaced, linear in between, clamped.
  function fraction(mbps) {
    var m = Number(mbps);
    if (!(m > 0)) return 0;
    if (m >= TICKS[TICKS.length - 1]) return 1;
    for (var i = 0; i < TICKS.length - 1; i++) {
      if (m <= TICKS[i + 1]) return (i + (m - TICKS[i]) / (TICKS[i + 1] - TICKS[i])) / (TICKS.length - 1);
    }
    return 1;
  }

  function node(tag, attrs, parent) {
    var n = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
    if (parent) parent.appendChild(n);
    return n;
  }

  function point(angleDeg, radius) {
    var a = angleDeg * Math.PI / 180;
    return [CX + radius * Math.cos(a), CY + radius * Math.sin(a)];
  }

  function arcPath(radius) {
    var s = point(START, radius);
    var e = point(START + SWEEP, radius);
    return 'M ' + s[0].toFixed(2) + ' ' + s[1].toFixed(2) + ' A ' + radius + ' ' + radius + ' 0 1 1 ' + e[0].toFixed(2) + ' ' + e[1].toFixed(2);
  }

  function reducedMotion() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  }

  function create(container) {
    var svg = node('svg', { viewBox: '0 0 300 270', class: 'gauge-svg', role: 'img', 'aria-label': 'Speed gauge' });
    var defs = node('defs', {}, svg);
    var grad = node('linearGradient', { id: 'gauge-grad', x1: '0', y1: '1', x2: '1', y2: '0' }, defs);
    node('stop', { offset: '0', 'stop-color': '#06b6d4' }, grad);
    node('stop', { offset: '1', 'stop-color': '#22d3ee' }, grad);
    var glow = node('filter', { id: 'gauge-glow', x: '-20%', y: '-20%', width: '140%', height: '140%' }, defs);
    node('feGaussianBlur', { stdDeviation: '4', result: 'b' }, glow);
    var merge = node('feMerge', {}, glow);
    node('feMergeNode', { in: 'b' }, merge);
    node('feMergeNode', { in: 'SourceGraphic' }, merge);

    node('path', { d: arcPath(R), fill: 'none', stroke: '#1f2937', 'stroke-width': '16', 'stroke-linecap': 'round' }, svg);
    var value = node('path', { d: arcPath(R), fill: 'none', stroke: 'url(#gauge-grad)', 'stroke-width': '16', 'stroke-linecap': 'round', filter: 'url(#gauge-glow)' }, svg);

    TICKS.forEach(function (tick, i) {
      var ang = START + SWEEP * i / (TICKS.length - 1);
      var p = point(ang, R - 30);
      var label = node('text', { x: p[0].toFixed(1), y: (p[1] + 4).toFixed(1), 'text-anchor': 'middle', 'font-size': '11', fill: '#9ca3af', 'font-family': 'Roboto, system-ui, sans-serif' }, svg);
      label.textContent = String(tick);
    });

    var needle = node('g', { transform: 'rotate(' + START + ' ' + CX + ' ' + CY + ')' }, svg);
    node('line', { x1: String(CX), y1: String(CY), x2: String(CX + R - 26), y2: String(CY), stroke: '#e5e7eb', 'stroke-width': '3', 'stroke-linecap': 'round' }, needle);
    node('circle', { cx: String(CX), cy: String(CY), r: '7', fill: '#22d3ee' }, svg);

    var number = node('text', { x: String(CX), y: '218', 'text-anchor': 'middle', 'font-size': '38', 'font-weight': '900', fill: '#22d3ee', 'font-family': 'Orbitron, Roboto, sans-serif', 'data-role': 'gauge-value' }, svg);
    number.textContent = '0';
    var unit = node('text', { x: String(CX), y: '238', 'text-anchor': 'middle', 'font-size': '12', fill: '#9ca3af', 'letter-spacing': '2', 'font-family': 'Roboto, system-ui, sans-serif' }, svg);
    unit.textContent = 'MBPS';

    var strip = node('text', { x: String(CX), y: '262', 'text-anchor': 'middle', 'font-size': '11', 'letter-spacing': '1.5', 'font-family': 'Roboto, system-ui, sans-serif' }, svg);
    var spans = {};
    PHASES.forEach(function (p, i) {
      if (i) { var dot = node('tspan', { fill: '#374151' }, strip); dot.textContent = '  ·  '; }
      spans[p] = node('tspan', { fill: '#6b7280' }, strip);
      spans[p].textContent = p.toUpperCase();
    });

    container.insertBefore(svg, container.firstChild);
    // Measured after insertion: some engines return 0 for a detached path.
    var measured = value.getTotalLength ? value.getTotalLength() : 0;
    var length = measured > 0 ? measured : 2 * Math.PI * R * SWEEP / 360;
    value.setAttribute('stroke-dasharray', length.toFixed(2));
    value.setAttribute('stroke-dashoffset', length.toFixed(2));

    var shown = 0;
    var target = 0;
    var frame = null;

    function draw(mbps) {
      var f = fraction(mbps);
      value.setAttribute('stroke-dashoffset', (length * (1 - f)).toFixed(2));
      needle.setAttribute('transform', 'rotate(' + (START + SWEEP * f).toFixed(2) + ' ' + CX + ' ' + CY + ')');
      number.textContent = mbps >= 100 ? String(Math.round(mbps)) : String(Math.round(mbps * 10) / 10);
    }

    function animate() {
      shown += (target - shown) * 0.18;
      if (Math.abs(target - shown) < 0.05) shown = target;
      draw(shown);
      frame = shown === target ? null : window.requestAnimationFrame(animate);
    }

    return {
      set: function (mbps) {
        target = Math.max(0, Number(mbps) || 0);
        if (reducedMotion() || !window.requestAnimationFrame) { shown = target; draw(shown); return; }
        if (!frame) frame = window.requestAnimationFrame(animate);
      },
      phase: function (name) {
        PHASES.forEach(function (p) {
          spans[p].setAttribute('fill', p === name ? '#22d3ee' : '#6b7280');
          spans[p].setAttribute('font-weight', p === name ? '700' : '400');
        });
      },
      reset: function () {
        if (frame) { window.cancelAnimationFrame(frame); frame = null; }
        shown = 0; target = 0; draw(0);
        this.phase(null);
      }
    };
  }

  window.PCGauge = { create: create, fraction: fraction };
})();
