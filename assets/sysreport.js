/*!
 * PC Check system reports | CyberSecInfo | MIT License
 * Reads the reports Windows already writes, entirely in the browser. Pure functions only:
 * no DOM changes, no network. ES2017 on purpose, like the rest of the page.
 */
(function () {
  'use strict';

  var MSINFO_HEAD_CHARS = 2000000; // System Summary and Problem Devices come first in the export

  // ---------------------------------------------------------------------------
  // Text decoding: Windows writes these reports as UTF-16 LE with a BOM
  // ---------------------------------------------------------------------------
  function decode(buffer) {
    var bytes = new Uint8Array(buffer);
    if (bytes[0] === 0xFF && bytes[1] === 0xFE) return new TextDecoder('utf-16le').decode(bytes.subarray(2));
    if (bytes[0] === 0xFE && bytes[1] === 0xFF) return new TextDecoder('utf-16be').decode(bytes.subarray(2));
    if (bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) return new TextDecoder('utf-8').decode(bytes.subarray(3));
    return new TextDecoder('utf-8').decode(bytes);
  }

  function parseDate(s) {
    var d = new Date(String(s || '').trim());
    return isNaN(d.getTime()) ? null : d;
  }

  function childText(node, tag) {
    var c = node.getElementsByTagName(tag)[0];
    return c ? c.textContent.trim() : '';
  }

  // ---------------------------------------------------------------------------
  // Reliability Monitor: "Save reliability history" (XML, language-neutral tags)
  // ---------------------------------------------------------------------------
  function parseReliability(text) {
    if (!/<RelMonReport[\s>]/.test(String(text).slice(0, 2000))) return { error: 'not_reliability' };
    var doc = new DOMParser().parseFromString(String(text).replace(/^<\?xml[^>]*\?>/, ''), 'application/xml');
    if (doc.getElementsByTagName('parsererror').length) return { error: 'not_reliability' };
    var root = doc.documentElement;
    var generated = parseDate(root.getAttribute('TimeGenerated'));

    var points = Array.prototype.map.call(doc.getElementsByTagName('GraphDataPoint'), function (p) {
      return { time: parseDate(childText(p, 'Time')), value: parseFloat(childText(p, 'Value')) };
    }).filter(function (p) { return p.time && !isNaN(p.value); });
    points.sort(function (a, b) { return b.time - a.time; });

    var since = generated ? generated.getTime() - 30 * 86400000 : null;
    var recent = since === null ? points : points.filter(function (p) { return p.time.getTime() >= since; });

    var events = Array.prototype.map.call(doc.getElementsByTagName('Event'), function (e) {
      return { time: parseDate(childText(e, 'Time')), impact: childText(e, 'Impact'), source: childText(e, 'Source'), problem: childText(e, 'Problem') };
    }).filter(function (e) { return e.time; });

    return {
      generated: generated || (points[0] ? points[0].time : null),
      stabilityNow: points.length ? points[0].value : null,
      stabilityMin30d: recent.length ? Math.min.apply(null, recent.map(function (p) { return p.value; })) : null,
      events: events
    };
  }

  // ---------------------------------------------------------------------------
  // Battery: powercfg /batteryreport (HTML; labels are localised)
  // ---------------------------------------------------------------------------
  var BATTERY_LABELS = {
    design: ['DESIGN CAPACITY', 'CAPACIDADE PROJETADA', 'CAPACIDADE DE DESIGN', 'CAPACIDADE DO PROJETO'],
    full: ['FULL CHARGE CAPACITY', 'CAPACIDADE DE CARGA TOTAL', 'CAPACIDADE DE CARGA COMPLETA', 'CAPACIDADE TOTAL DE CARGA'],
    cycles: ['CYCLE COUNT', 'CONTAGEM DE CICLOS', 'CONTAGEM DE CICLO', 'NÚMERO DE CICLOS']
  };

  function digits(s) {
    var n = parseInt(String(s).replace(/[^\d]/g, ''), 10);
    return isNaN(n) ? null : n;
  }

  function parseBattery(text) {
    var head = String(text).slice(0, 4000);
    var looksLikeReport = /schemas\.microsoft\.com\/battery|<title>\s*Battery report/i.test(head) || /batteryreport|bat:/i.test(head);
    if (!looksLikeReport) return { error: 'not_battery' };
    var doc = new DOMParser().parseFromString(String(text), 'text/html');
    var values = {};
    Array.prototype.forEach.call(doc.querySelectorAll('.label'), function (label) {
      var key = label.textContent.trim().toUpperCase();
      var cell = label.closest('td');
      var next = cell && cell.nextElementSibling;
      if (next && !(key in values)) values[key] = next.textContent.trim();
    });
    function pick(names) {
      for (var i = 0; i < names.length; i++) if (values[names[i]] !== undefined) return values[names[i]];
      return undefined;
    }
    var design = pick(BATTERY_LABELS.design);
    var full = pick(BATTERY_LABELS.full);
    if (design === undefined || full === undefined) return Object.keys(values).length ? { unsupportedLanguage: true } : { error: 'not_battery' };
    var d = digits(design);
    var f = digits(full);
    var cycles = digits(pick(BATTERY_LABELS.cycles));
    return { designMWh: d, fullMWh: f, cycles: cycles, healthPct: d ? Math.round((f / d) * 1000) / 10 : null };
  }

  // ---------------------------------------------------------------------------
  // System information: msinfo32 -> File -> Export (UTF-16 text, localised labels)
  // ---------------------------------------------------------------------------
  var MSINFO = {
    summary: ['[System Summary]', '[Resumo do Sistema]'],
    problems: ['[Problem Devices]', '[Dispositivos com Problema]'],
    fields: {
      os: ['OS Name', 'Nome do SO', 'Nome do Sistema Operacional'],
      version: ['Version', 'Versão'],
      model: ['System Model', 'Modelo do sistema', 'Modelo do Sistema'],
      manufacturer: ['System Manufacturer', 'Fabricante do sistema', 'Fabricante do Sistema'],
      cpu: ['Processor', 'Processador'],
      ram: ['Installed Physical Memory (RAM)', 'Memória Física (RAM) Instalada', 'Memória física (RAM) instalada'],
      bios: ['BIOS Version/Date', 'Versão/Data do BIOS']
    }
  };

  function parseMsinfo(text) {
    var head = String(text).slice(0, MSINFO_HEAD_CHARS);
    var lines = head.split(/\r?\n/);
    var start = -1;
    for (var i = 0; i < lines.length && start < 0; i++) if (MSINFO.summary.indexOf(lines[i].trim()) !== -1) start = i;
    if (start < 0) {
      var looksLikeMsinfo = /^\s*\[[^\]]+\]\s*$/m.test(head.slice(0, 5000)) && /\t/.test(head.slice(0, 5000));
      return looksLikeMsinfo ? { unsupportedLanguage: true } : { error: 'not_msinfo' };
    }
    var map = {};
    for (var j = start + 1; j < lines.length; j++) {
      var line = lines[j];
      if (/^\s*\[/.test(line)) break;
      var tab = line.indexOf('\t');
      if (tab > 0) map[line.slice(0, tab).trim()] = line.slice(tab + 1).replace(/\t+$/, '').trim();
    }
    function field(name) {
      var names = MSINFO.fields[name];
      for (var k = 0; k < names.length; k++) if (map[names[k]] !== undefined) return map[names[k]];
      return null;
    }
    var ramText = field('ram');
    var ram = ramText ? parseFloat(ramText.replace(',', '.')) : null;

    var problems = [];
    var p = -1;
    for (var m = 0; m < lines.length && p < 0; m++) if (MSINFO.problems.indexOf(lines[m].trim()) !== -1) p = m;
    if (p >= 0) {
      for (var n = p + 1; n < lines.length; n++) {
        var row = lines[n];
        if (/^\s*\[/.test(row)) break;
        var name = row.split('\t')[0].trim();
        if (name && !/^(Device|Dispositivo)$/i.test(name)) problems.push(name);
      }
    }
    return {
      os: field('os'), version: field('version'), model: field('model'), manufacturer: field('manufacturer'),
      cpu: field('cpu'), ramGb: ram === null || isNaN(ram) ? null : ram, bios: field('bios'), problemDevices: problems
    };
  }

  window.PCSys = { decode: decode, parseReliability: parseReliability, parseBattery: parseBattery, parseMsinfo: parseMsinfo };
})();
