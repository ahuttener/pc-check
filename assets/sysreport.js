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
    // Computer and user names are kept only so the anonymiser can remove them everywhere else.
    var names = [];
    ['System Name', 'Nome do Sistema', 'Nome do sistema'].forEach(function (k) { if (map[k]) names.push(map[k]); });
    ['Username', 'User Name', 'Nome de Usuário', 'Nome do usuário'].forEach(function (k) {
      if (map[k]) map[k].split('\\').forEach(function (part) { if (part.trim()) names.push(part.trim()); });
    });
    return {
      os: field('os'), version: field('version'), model: field('model'), manufacturer: field('manufacturer'),
      cpu: field('cpu'), ramGb: ram === null || isNaN(ram) ? null : ram, bios: field('bios'), problemDevices: problems,
      names: names
    };
  }

  // ---------------------------------------------------------------------------
  // Anonymiser: nothing personal may reach the AI summary or the PDF
  // ---------------------------------------------------------------------------
  function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function anonymise(value, names) {
    var s = String(value === null || value === undefined ? '' : value);
    (names || []).filter(function (n) { return n && n.length >= 3; }).forEach(function (n) {
      s = s.replace(new RegExp(escapeRe(n), 'gi'), '[name]');
    });
    return s
      .replace(/([A-Za-z]:\\Users\\)[^\\\s]+/gi, '$1[user]')
      .replace(/(\/(?:home|Users)\/)[^\/\s]+/g, '$1[user]')
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
      .replace(/\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi, '[mac]')
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[id]')
      .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '[ip]')
      .replace(/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi, '[ip]')
      .replace(/\b(DESKTOP|LAPTOP|PC)-[A-Z0-9]{4,}\b/g, '[pc]')
      .replace(/\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{10,}\b/g, '[id]');
  }

  // ---------------------------------------------------------------------------
  // Rules: findings, score and facts
  // ---------------------------------------------------------------------------
  var DAY = 86400000;
  var KNOWN_HELPERS = [
    { re: /MiracastPowerManager/i, what: 'a wireless-display (Miracast) helper installed by the PC maker' },
    { re: /AcerRegistration/i, what: 'Acer’s product-registration helper' },
    { re: /jusched|Java Update Scheduler/i, what: 'Java’s update checker' }
  ];
  var CRASH_PROBLEMS = ['Stopped working', 'Stopped responding and was closed', 'Stopped responding'];
  var SHUTDOWN_PROBLEMS = ['Shut down unexpectedly', 'Windows was not properly shut down'];

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  function evaluateWindows(reports, now) {
    var r = reports || {};
    var at = now || new Date();
    var findings = [];
    var facts = [];
    var out = { score: 100, findings: findings, facts: facts, reportDate: null,
      shutdowns30d: null, hardwareErrors30d: null, topCrashApps: [], stabilityNow: null, batteryHealthPct: null,
      os: null, model: null, ramGb: null, names: (r.names || []).concat(r.msinfo && r.msinfo.names ? r.msinfo.names : []) };
    function add(id, severity, title, detail, fix) { findings.push({ id: id, severity: severity, title: title, detail: detail || '', fix: fix || '' }); }

    var rel = r.reliability && !r.reliability.error ? r.reliability : null;
    if (rel) {
      var gen = rel.generated || at;
      out.reportDate = gen;
      var since = gen.getTime() - 30 * DAY;
      var recent = rel.events.filter(function (e) { return e.time.getTime() >= since && e.time.getTime() <= gen.getTime() + DAY; });
      var count = function (problems) { return recent.filter(function (e) { return problems.indexOf(e.problem) !== -1; }).length; };

      var shutdowns = count(SHUTDOWN_PROBLEMS);
      out.shutdowns30d = shutdowns;
      if (shutdowns >= 1) {
        add('shutdowns', shutdowns >= 3 ? 'risk' : 'warn', 'Windows shut down unexpectedly ' + plural(shutdowns, 'time', 'times') + ' in 30 days',
          'Usually a blue screen, a power loss or a forced restart. This report does not include the blue-screen error code.',
          'Install pending Windows updates, then update the graphics, chipset and storage drivers from your PC maker’s support page. If it happens under heavy load, check that the fans and vents are clean.');
      }
      var hardware = count(['Hardware error']);
      out.hardwareErrors30d = hardware;
      if (hardware >= 1) {
        add('hardware', 'warn', 'Windows logged ' + plural(hardware, 'hardware error', 'hardware errors') + ' in 30 days',
          'Hardware errors are often caused by drivers or firmware, and sometimes by memory or storage.',
          'Update the BIOS and drivers from your PC maker. If the errors keep appearing, run Windows Memory Diagnostic (Win + R, mdsched) and check the disk’s health.');
      }

      var bySource = {};
      recent.forEach(function (e) { if (CRASH_PROBLEMS.indexOf(e.problem) !== -1) bySource[e.source] = (bySource[e.source] || 0) + 1; });
      var top = Object.keys(bySource).map(function (k) { return { name: k, count: bySource[k] }; })
        .sort(function (a, b) { return b.count - a.count; }).slice(0, 3);
      out.topCrashApps = top;
      if (top.length && top[0].count >= 10) {
        var notes = top.map(function (a) {
          var known = KNOWN_HELPERS.filter(function (h) { return h.re.test(a.name); })[0];
          return a.name + ' (' + plural(a.count, 'crash', 'crashes') + (known ? ', ' + known.what : '') + ')';
        });
        add('crashes', 'warn', 'Some programs keep crashing', 'Most crashes in the last 30 days: ' + notes.join('; ') + '.',
          'If these are background helpers you don’t use, uninstall the app they belong to (Settings > Apps) or turn them off in Task Manager > Startup apps. Otherwise update or reinstall them.');
      }

      out.stabilityNow = rel.stabilityNow;
      if (rel.stabilityNow !== null && rel.stabilityNow < 5) {
        add('stability', 'warn', 'Windows stability index is ' + rel.stabilityNow + ' out of 10',
          'Windows scores stability from 1 to 10 using the crashes and failures above.', 'Fixing the items above raises it again within days.');
      }
      var failedUpdates = count(['Failed Windows Update']);
      if (failedUpdates >= 3) {
        add('updates', 'warn', plural(failedUpdates, 'update failed', 'updates failed') + ' in 30 days', '',
          'Open Settings > Windows Update and retry. If one keeps failing, run Settings > System > Troubleshoot > Windows Update.');
      }
      if (at.getTime() - gen.getTime() > 30 * DAY) {
        add('old_report', 'info', 'This report is ' + Math.round((at.getTime() - gen.getTime()) / DAY) + ' days old',
          'Save a new reliability history to see the current state.', '');
      }
    }

    var bat = r.battery && !r.battery.error && !r.battery.unsupportedLanguage ? r.battery : null;
    if (bat && bat.healthPct !== null) {
      out.batteryHealthPct = bat.healthPct;
      if (bat.healthPct < 80) {
        add('battery', bat.healthPct < 60 ? 'risk' : 'warn', 'Battery holds ' + bat.healthPct + ' % of its original charge',
          (bat.cycles !== null ? plural(bat.cycles, 'charge cycle', 'charge cycles') + ' so far. ' : '') + 'Batteries lose capacity with age and heat.',
          bat.healthPct < 60 ? 'Plan a battery replacement with your PC maker or a repair shop.' : 'Normal wear. Avoid keeping it at 100 % and hot for long periods; many laptops have a battery-care mode in the maker’s app.');
      }
    }

    var msi = r.msinfo && !r.msinfo.error && !r.msinfo.unsupportedLanguage ? r.msinfo : null;
    if (msi) {
      out.os = msi.os; out.model = msi.model; out.ramGb = msi.ramGb;
      if (/Windows 10/i.test(msi.os || '')) {
        add('windows10', 'warn', 'Windows 10 no longer gets free security updates', 'Support ended in October 2025.',
          'Upgrade to Windows 11 if the PC supports it (Settings > Windows Update), or enrol in Extended Security Updates.');
      }
      if (msi.problemDevices && msi.problemDevices.length) {
        add('devices', 'warn', plural(msi.problemDevices.length, 'device has a problem', 'devices have problems'),
          msi.problemDevices.slice(0, 5).join('; '), 'Open Device Manager (Win + X > Device Manager) and update or reinstall the driver for each device marked with a warning.');
      }
    }

    var risks = findings.filter(function (f) { return f.severity === 'risk'; }).length;
    var warns = findings.filter(function (f) { return f.severity === 'warn'; }).length;
    out.score = Math.max(0, 100 - 25 * risks - 10 * warns);

    if (out.os) facts.push({ label: 'System', value: out.os });
    if (out.model) facts.push({ label: 'Model', value: out.model });
    if (msi && msi.cpu) facts.push({ label: 'Processor', value: msi.cpu });
    if (out.ramGb) facts.push({ label: 'Memory', value: out.ramGb + ' GB' });
    if (bat) facts.push({ label: 'Battery health', value: bat.healthPct + ' %' + (bat.cycles !== null ? ' (' + plural(bat.cycles, 'cycle', 'cycles') + ')' : '') });
    if (out.stabilityNow !== null) facts.push({ label: 'Stability index', value: out.stabilityNow + ' / 10' });
    if (out.shutdowns30d !== null) facts.push({ label: 'Unexpected shutdowns (30 days)', value: String(out.shutdowns30d) });
    if (out.reportDate) facts.push({ label: 'Report from', value: out.reportDate.toISOString().slice(0, 10) });
    facts.forEach(function (f) { f.value = anonymise(f.value, out.names); });
    findings.forEach(function (f) { f.title = anonymise(f.title, out.names); f.detail = anonymise(f.detail, out.names); });
    return out;
  }

  // ---------------------------------------------------------------------------
  // The only thing that may ever be sent for an AI explanation: a small, whitelisted summary
  // ---------------------------------------------------------------------------
  // Control (Cc) and format (Cf) characters, which the server rejects: removed rather than sent.
  var CONTROL_FORMAT_RE = /[\u0000-\u001F\u007F-\u009F\u00AD\u0600-\u0605\u061C\u06DD\u070F\u0890\u0891\u08E2\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFEFF\uFFF9-\uFFFB]|\uD804[\uDCBD\uDCCD]|\uD80D[\uDC30-\uDC3F]|\uD82F[\uDCA0-\uDCA3]|\uD834[\uDD73-\uDD7A]|\uDB40[\uDC01\uDC20-\uDC7F]/g;

  // At most 80 characters counted as code points (as the server counts them). An emoji is kept whole or
  // dropped whole, and lone surrogates are removed, so the JSON is always valid UTF-8.
  function cap(s) {
    if (s === null || s === undefined) return null;
    var str = String(s).replace(CONTROL_FORMAT_RE, '');
    var out = '';
    var n = 0;
    for (var i = 0; i < str.length && n < 80; i++) {
      var c = str.charCodeAt(i);
      if (c >= 0xD800 && c <= 0xDBFF) {
        var d = str.charCodeAt(i + 1);
        if (d >= 0xDC00 && d <= 0xDFFF) { out += str.charAt(i) + str.charAt(i + 1); i++; n++; }
      } else if (c < 0xDC00 || c > 0xDFFF) {
        out += str.charAt(i);
        n++;
      }
    }
    return out;
  }

  function buildSummary(e) {
    var names = e.names || [];
    return {
      os: cap(e.os === null ? null : anonymise(e.os, names)),
      model: cap(e.model === null ? null : anonymise(e.model, names)),
      ramGb: typeof e.ramGb === 'number' ? e.ramGb : null,
      score: e.score,
      findings: e.findings.slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      topCrashApps: e.topCrashApps.slice(0, 3).map(function (a) { return { name: cap(anonymise(a.name, names)), count: a.count }; }),
      batteryHealthPct: typeof e.batteryHealthPct === 'number' ? e.batteryHealthPct : null,
      shutdowns30d: typeof e.shutdowns30d === 'number' ? e.shutdowns30d : null,
      hardwareErrors30d: typeof e.hardwareErrors30d === 'number' ? e.hardwareErrors30d : null,
      stabilityNow: typeof e.stabilityNow === 'number' ? e.stabilityNow : null
    };
  }

  window.PCSys = {
    decode: decode, parseReliability: parseReliability, parseBattery: parseBattery, parseMsinfo: parseMsinfo,
    evaluateWindows: evaluateWindows, anonymise: anonymise, buildSummary: buildSummary
  };
})();
