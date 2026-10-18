/*!
 * PC Check system reports | CyberSecInfo | MIT License
 * Reads the reports Windows writes and the Linux command output a visitor pastes, entirely in the browser. Pure functions only:
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
  // Problem texts of an English Windows (the only language PC Check reads in this report so far).
  var RELIABILITY_PROBLEMS = ['Stopped working', 'Stopped responding and was closed', 'Stopped responding', 'Hardware error',
    'Shut down unexpectedly', 'Windows was not properly shut down', 'Failed Windows Update', 'Successful Windows Update'];

  function isKnownProblem(problem) {
    return RELIABILITY_PROBLEMS.indexOf(problem) !== -1 || /^(Successful|Failed) (application|driver|Windows)\b/.test(problem);
  }

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

    // Tags are language-neutral but the Problem text is the Windows display language. If none of the
    // events reads as a problem we know, the rules below would count nothing and call a crashing PC
    // healthy, so say the language is not supported instead.
    if (events.length && !events.some(function (e) { return isKnownProblem(e.problem); })) return { unsupportedLanguage: true };

    return {
      generated: generated || (points[0] ? points[0].time : null),
      stabilityNow: points.length ? points[0].value : null,
      stabilityMin30d: recent.length ? Math.min.apply(null, recent.map(function (p) { return p.value; })) : null,
      events: events
    };
  }

  // ---------------------------------------------------------------------------
  // Battery: powercfg /batteryreport (HTML; labels are localised, only English ones are read)
  // ---------------------------------------------------------------------------
  var BATTERY_LABELS = {
    design: ['DESIGN CAPACITY'],
    full: ['FULL CHARGE CAPACITY'],
    cycles: ['CYCLE COUNT']
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
  // System information: msinfo32 -> File -> Export (UTF-16 text, localised labels, only English ones are read)
  // ---------------------------------------------------------------------------
  var MSINFO = {
    summary: ['[System Summary]'],
    problems: ['[Problem Devices]'],
    fields: {
      os: ['OS Name'],
      version: ['Version'],
      model: ['System Model'],
      manufacturer: ['System Manufacturer'],
      cpu: ['Processor'],
      ram: ['Installed Physical Memory (RAM)'],
      bios: ['BIOS Version/Date']
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
        if (name && !/^Device$/i.test(name)) problems.push(name);
      }
    }
    // Computer and user names are kept only so the anonymiser can remove them everywhere else.
    var names = [];
    ['System Name'].forEach(function (k) { if (map[k]) names.push(map[k]); });
    ['Username', 'User Name'].forEach(function (k) {
      if (map[k]) map[k].split('\\').forEach(function (part) { if (part.trim()) names.push(part.trim()); });
    });
    return {
      os: field('os'), version: field('version'), model: field('model'), manufacturer: field('manufacturer'),
      cpu: field('cpu'), ramGb: ram === null || isNaN(ram) ? null : ram, bios: field('bios'), problemDevices: problems,
      names: names
    };
  }

  // ---------------------------------------------------------------------------
  // Linux: text pasted from five read-only commands (run with LC_ALL=C, so English month and day names)
  // ---------------------------------------------------------------------------
  var LINUX_PASTE_CAP = 2000000; // characters per paste box
  var LINUX_MAX_LINES = 20000;   // journal lines read per box
  var MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  // Out-of-the-box hostnames: replacing them would garble the distro name, and they identify nobody.
  var DEFAULT_HOSTNAMES = ['localhost', 'ubuntu', 'debian', 'fedora', 'linux', 'raspberrypi', 'archlinux', 'kali', 'mint',
    'pop-os', 'opensuse', 'manjaro'];
  // System accounts seen in journal lines: not personal, and common words in the messages themselves.
  var SYSTEM_USERS = ['root', 'nobody', 'gdm', 'lightdm', 'sddm', 'messagebus', 'polkitd', 'daemon', 'syslog', 'avahi',
    'colord', 'geoclue', 'rtkit', 'pulse', 'kernoops', 'whoopsie', 'user', 'unknown'];

  function linuxText(text) {
    var s = String(text === null || text === undefined ? '' : text);
    return { text: s.slice(0, LINUX_PASTE_CAP), cut: s.length > LINUX_PASTE_CAP };
  }

  function round1(n) { return Math.round(n * 10) / 10; }

  function addName(list, n) {
    if (n && list.indexOf(n) === -1) list.push(n);
  }

  function addHostname(list, host) {
    var h = String(host || '').trim();
    if (!h || DEFAULT_HOSTNAMES.indexOf(h.toLowerCase()) !== -1) return;
    addName(list, h);
    var label = h.split('.')[0];
    if (label && DEFAULT_HOSTNAMES.indexOf(label.toLowerCase()) === -1) addName(list, label);
  }

  function addUser(list, user) {
    var u = String(user || '').trim();
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(u)) return;
    if (SYSTEM_USERS.indexOf(u.toLowerCase()) !== -1 || /^systemd-/.test(u)) return;
    addName(list, u);
  }

  // uname -a; cat /etc/os-release
  function parseLinuxSystem(text) {
    var lines = linuxText(text).text.split(/\r?\n/);
    var hostname = null;
    var kernel = null;
    var rel = {};
    lines.forEach(function (raw) {
      var line = raw.trim();
      var u = /^Linux (\S+) (\S+)/.exec(line);
      if (u && hostname === null) { hostname = u[1]; kernel = u[2]; return; }
      var kv = /^([A-Z][A-Z0-9_]*)=(.*)$/.exec(line);
      if (!kv || kv[1] in rel) return;
      var v = kv[2].trim();
      var q = /^"(.*)"$/.exec(v) || /^'(.*)'$/.exec(v);
      if (q) v = q[1].replace(/\\(["'\\$`])/g, '$1');
      rel[kv[1]] = v;
    });
    if (hostname === null && !('ID' in rel)) return { error: 'not_system' };
    var distro = rel.PRETTY_NAME || ((rel.NAME || '') + ' ' + (rel.VERSION_ID || '')).trim() || null;
    var end = /^(\d{4})-(\d\d)-(\d\d)$/.exec(rel.SUPPORT_END || '');
    var names = [];
    addHostname(names, hostname);
    return {
      hostname: hostname, kernel: kernel, distro: distro, id: rel.ID || null, versionId: rel.VERSION_ID || null,
      supportEnd: end ? new Date(+end[1], +end[2] - 1, +end[3]) : null, names: names
    };
  }

  // Shapes of one journal line. Each regex is anchored and has no nested quantifiers.
  var J_SHORT = /^([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d) (\S+) (.*)$/;
  var J_ISO = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:[.,]\d+)?(Z|[+-]\d\d:?\d\d)? (\S+) (.*)$/;
  var J_ANY_DATE = /^\S{2,5}\.? \d{1,2} \d\d:\d\d:\d\d /; // any language's "Mon DD HH:MM:SS "
  var J_SOURCE = /^(\S+?): (.*)$/;

  function splitSource(rest) {
    var m = J_SOURCE.exec(rest);
    if (!m) return { source: '', message: rest };
    return { source: m[1].replace(/\[\d+\]$/, '').replace(/\]+$/, ''), message: m[2] };
  }

  function collectUsers(names, source, message) {
    var re = /\/(?:home|media)\/([^\/\s\]\[:;,'"]+)/g;
    var m;
    while ((m = re.exec(message)) !== null) addUser(names, m[1]);
    re = /\b(?:user|logname|ruser)=([^\s;,\]\)'"]+)/g;
    while ((m = re.exec(message)) !== null) addUser(names, m[1]);
    if (source === 'pkexec' || source === 'sudo') {
      m = /^([A-Za-z_][A-Za-z0-9_.-]{0,31}) ?: /.exec(message);
      if (m) addUser(names, m[1]);
    }
  }

  // journalctl -p 3 -o short (or short-iso). yearHint: a year, or the report Date (then a month later than the
  // report month means the year before, because short lines carry no year).
  function parseJournal(text, yearHint) {
    var src = linuxText(text);
    var all = src.text.split(/\r?\n/);
    var truncated = src.cut || all.length > LINUX_MAX_LINES;
    var hint = yearHint instanceof Date && !isNaN(yearHint.getTime()) ? yearHint : null;
    var year = hint ? hint.getFullYear() : (typeof yearHint === 'number' ? yearHint : new Date().getFullYear());
    var refMonth = hint ? hint.getMonth() : null;
    var out = [];
    var names = [];
    var noEntries = false;
    var partial = false;
    var recognised = false;
    var inHint = false;
    var nonEmpty = false;
    for (var i = 0; i < all.length && out.length < LINUX_MAX_LINES; i++) {
      var line = all[i].replace(/\s+$/, '');
      if (!line) { inHint = false; continue; }
      nonEmpty = true;
      if (inHint && /^\s/.test(line)) continue;
      inHint = false;
      var m = J_SHORT.exec(line);
      if (m && MONTHS.indexOf(m[1]) !== -1) {
        var mon = MONTHS.indexOf(m[1]);
        var y = refMonth !== null && mon > refMonth ? year - 1 : year;
        var p = splitSource(m[7]);
        out.push({ time: new Date(y, mon, +m[2], +m[3], +m[4], +m[5]), source: p.source, message: p.message });
        addHostname(names, m[6]);
        collectUsers(names, p.source, p.message);
        continue;
      }
      if (J_ANY_DATE.test(line)) return { unsupportedLanguage: true };
      m = J_ISO.exec(line);
      if (m) {
        var zone = m[7] ? (m[7] === 'Z' ? 'Z' : m[7].slice(0, 3) + ':' + m[7].slice(-2)) : '';
        var t = new Date(m[1] + '-' + m[2] + '-' + m[3] + 'T' + m[4] + ':' + m[5] + ':' + m[6] + zone);
        var q = splitSource(m[9]);
        out.push({ time: isNaN(t.getTime()) ? null : t, source: q.source, message: q.message });
        addHostname(names, m[8]);
        collectUsers(names, q.source, q.message);
        continue;
      }
      var trimmed = line.trim();
      if (trimmed === '-- No entries --') { noEntries = true; recognised = true; continue; }
      if (/^-- .* --$/.test(trimmed)) { recognised = true; continue; }
      if (/^Hint: You are currently not seeing messages/.test(trimmed)) { partial = true; recognised = true; inHint = true; continue; }
      if (/^No journal files were opened due to insufficient permissions/.test(trimmed)) { partial = true; recognised = true; continue; }
      if (/^No journal files were found/.test(trimmed)) { noEntries = true; recognised = true; continue; }
    }
    if (nonEmpty && !out.length && !recognised) return { error: 'not_journal' };
    return { lines: out, total: out.length, truncated: truncated, noEntries: noEntries && !out.length, partial: partial, names: names };
  }

  // journalctl --list-boots | tail -5; journalctl -b -1 -p 3 -o short
  var BOOT_ROW = /^\s*(-?\d+)\s+([0-9a-f]{32})\s+(.*)$/;
  var BOOT_STAMP = /([^\s\d\u2014\u2013>-]+) (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/g;

  function parseBoots(text) {
    var lines = linuxText(text).text.split(/\r?\n/);
    var boots = [];
    var rest = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^\s*IDX\s+BOOT ID\b/.test(line)) continue;
      var row = BOOT_ROW.exec(line);
      if (!row) { rest.push(line); continue; }
      var stamps = [];
      var s;
      BOOT_STAMP.lastIndex = 0;
      while ((s = BOOT_STAMP.exec(row[3])) !== null && stamps.length < 2) {
        if (WEEKDAYS.indexOf(s[1]) === -1) return { unsupportedLanguage: true };
        stamps.push(new Date(+s[2], +s[3] - 1, +s[4], +s[5], +s[6], +s[7]));
      }
      if (stamps.length < 2) {
        if (/\d{4}-\d\d-\d\d \d\d:\d\d:\d\d/.test(row[3])) return { unsupportedLanguage: true };
        rest.push(line);
        continue;
      }
      boots.push({ idx: +row[1], first: stamps[0], last: stamps[1] });
    }
    var newest = null;
    boots.forEach(function (b) { if (!newest || b.idx > newest.idx) newest = b; });
    var reportDate = newest ? newest.last : null;
    var previous = parseJournal(rest.join('\n'), reportDate || undefined);
    if (previous.unsupportedLanguage) return { unsupportedLanguage: true };
    if (previous.error) {
      if (!boots.length) return { error: 'not_boots' };
      previous = { lines: [], total: 0, truncated: false, noEntries: false, partial: false, names: [] };
    }
    if (!boots.length && !previous.total) return { error: 'not_boots' };
    return { boots: boots, previous: previous, reportDate: reportDate };
  }

  // upower -i $(upower -e | grep BAT). Only the energy figures are kept: never the vendor, model or serial.
  function parseUpower(text) {
    var s = linuxText(text).text;
    if (!s.trim() || /^\s*Usage:/m.test(s) || /upower \[OPTION/.test(s)) return { present: false };
    if (!/\benergy/.test(s) && !/native-path/.test(s)) return { error: 'not_battery' };
    function wh(key) {
      var m = new RegExp('^\\s*' + key + ':\\s*([0-9]+(?:[.,][0-9]+)?)\\s*Wh', 'm').exec(s);
      return m ? parseFloat(m[1].replace(',', '.')) : null;
    }
    var full = wh('energy-full');
    var design = wh('energy-full-design');
    var c = /^\s*charge-cycles:\s*(\d+)\s*$/m.exec(s);
    return {
      present: true, fullWh: full, designWh: design, cycles: c ? parseInt(c[1], 10) : null,
      healthPct: full !== null && design ? round1((full / design) * 100) : null
    };
  }

  // df -h; lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
  var DF_HEADER = /^Filesystem\s+(?:Size|1K-blocks|1M-blocks)\s+Used\s+Avail(?:able)?\s+(?:Use|Capacity)%\s+Mounted on\s*$/;
  var DF_ROW = /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S.*)$/;
  var DF_CONT = /^\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S.*)$/; // df wraps a long device name onto its own line
  var LSBLK_HEADER = /^NAME\s+SIZE\s+TYPE\b/;
  var LSBLK_ROW = /^[\s|`\u2502\u251C\u2514\u2500-]*([^\s|`\u2502\u251C\u2514\u2500-]\S*)\s+(\S+)\s+(\S+)/;

  function parseDisks(text) {
    var lines = linuxText(text).text.split(/\r?\n/);
    var mode = null;
    var sawDf = false;
    var sawLsblk = false;
    var filesystems = [];
    var byDevice = {};
    var disks = [];
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].replace(/\s+$/, '');
      if (DF_HEADER.test(line)) { mode = 'df'; sawDf = true; continue; }
      if (LSBLK_HEADER.test(line)) { mode = 'lsblk'; sawLsblk = true; continue; }
      if (!line) continue;
      if (mode === 'df') {
        var m = DF_ROW.exec(line);
        var dev, size, pct, mount;
        if (m) { dev = m[1]; size = m[2]; pct = +m[5]; mount = m[6]; }
        else if (/^\S+$/.test(line) && i + 1 < lines.length && (m = DF_CONT.exec(lines[i + 1].replace(/\s+$/, '')))) {
          dev = line; size = m[1]; pct = +m[4]; mount = m[5]; i++;
        } else continue;
        if (!/^\/dev\//.test(dev) || /^\/dev\/loop/.test(dev)) continue;
        if (byDevice[dev]) { byDevice[dev].mounts.push(mount); continue; }
        var entry = { device: dev, sizeText: size, usedPct: pct, mount: mount, mounts: [mount] };
        byDevice[dev] = entry;
        filesystems.push(entry);
      } else if (mode === 'lsblk') {
        var b = LSBLK_ROW.exec(line);
        if (b && b[3] === 'disk' && !/^zram/.test(b[1]) && !/^0B?$/.test(b[2])) disks.push({ name: b[1], sizeText: b[2] });
      } else if (!sawDf && /^[^\d]*\S%\s+\S[^\d]*$/.test(line)) {
        return { unsupportedLanguage: true }; // a df header in another language
      }
    }
    if (!sawDf && !sawLsblk) return { error: 'not_disks' };
    var worst = null;
    filesystems.forEach(function (f) { if (worst === null || f.usedPct > worst) worst = f.usedPct; });
    return { filesystems: filesystems, disks: disks, worstPct: worst };
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

  // YYYY-MM-DD in the viewer's time zone: Windows writes local times, and a report saved late in the
  // evening must not show the next day's UTC date.
  function localDate(d) {
    if (!d || isNaN(d.getTime())) return null;
    var pad = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

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

    var rel = r.reliability && !r.reliability.error && !r.reliability.unsupportedLanguage ? r.reliability : null;
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
    if (out.reportDate) facts.push({ label: 'Report from', value: localDate(out.reportDate) });
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
    evaluateWindows: evaluateWindows, anonymise: anonymise, buildSummary: buildSummary,
    LINUX_PASTE_CAP: LINUX_PASTE_CAP, LINUX_MAX_LINES: LINUX_MAX_LINES,
    parseLinuxSystem: parseLinuxSystem, parseJournal: parseJournal, parseBoots: parseBoots,
    parseUpower: parseUpower, parseDisks: parseDisks
  };
})();
