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

  var LINE_CHARS = 4096; // per-line work is bounded, so one huge line cannot stall the page
  var DEFAULT_HOST_SET = toSet(DEFAULT_HOSTNAMES);
  var SYSTEM_USER_SET = toSet(SYSTEM_USERS);

  function toSet(list) {
    var o = Object.create(null);
    list.forEach(function (k) { o[k] = true; });
    return o;
  }

  function round1(n) { return Math.round(n * 10) / 10; }

  // Trailing whitespace removed with a loop: /\s+$/ is quadratic on a long line full of spaces.
  function trimEnd(s) {
    var n = s.length;
    while (n > 0) {
      var c = s.charCodeAt(n - 1);
      if (c !== 32 && c !== 9 && c !== 13 && c !== 11 && c !== 12 && c !== 160) break;
      n--;
    }
    return n === s.length ? s : s.slice(0, n);
  }

  // Names collected for the anonymiser: a list in first-seen order plus a set for O(1) lookups. users holds the subset
  // that are account names (user=, /home/<x>, e-mail local parts), which must never be shown as a log source.
  function nameSet() { return { list: [], seen: Object.create(null), users: [], userSeen: Object.create(null) }; }

  function addName(set, n) {
    if (n && !set.seen[n]) { set.seen[n] = true; set.list.push(n); }
  }

  // Generic words and distribution names found inside hostnames ("jdoe-laptop", "arch-box"): never names on their own,
  // so they do not garble the distro string or ordinary words.
  var HOST_PART_STOPLIST = toSet(['desktop', 'laptop', 'linux', 'home', 'server', 'user', 'local', 'localdomain', 'host',
    'workstation', 'computer', 'machine', 'main', 'test', 'work', 'office', 'node', 'guest', 'admin', 'root', 'wifi',
    'arch', 'mint', 'elementary', 'zorin', 'endeavouros', 'gentoo', 'void', 'nixos', 'centos', 'rocky', 'alma', 'rhel',
    'suse', 'kubuntu', 'xubuntu', 'lubuntu', 'neon', 'deepin', 'solus', 'garuda', 'slackware', 'tumbleweed', 'leap',
    'raspberry', 'thinkpad', 'macbook', 'dell', 'lenovo', 'asus', 'acer']);

  function addHostname(set, host) {
    var h = String(host || '').trim();
    if (!h || set.seen[h] || DEFAULT_HOST_SET[h.toLowerCase()]) return;
    addName(set, h);
    var label = h.split('.')[0];
    if (label && !DEFAULT_HOST_SET[label.toLowerCase()]) addName(set, label);
    // Parts of 4+ characters ("tuxbox-jdoe" -> "tuxbox", "jdoe"): a user name inside the hostname often shows up
    // elsewhere too (jdoe-sync.sh) where no other rule would catch it.
    h.split(/[-_.]/).forEach(function (part) {
      var p = part.toLowerCase();
      if (part.length >= 4 && !DEFAULT_HOST_SET[p] && !HOST_PART_STOPLIST[p] && !/^\d+$/.test(part)) addName(set, part);
    });
  }

  function addUser(set, user) {
    var u = String(user || '').trim();
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,31}$/.test(u)) return;
    if (SYSTEM_USER_SET[u.toLowerCase()] || /^systemd-/.test(u)) return;
    addName(set, u);
    if (!set.userSeen[u]) { set.userSeen[u] = true; set.users.push(u); }
  }

  // uname -a; cat /etc/os-release
  function parseLinuxSystem(text) {
    var lines = linuxText(text).text.split(/\r?\n/);
    var hostname = null;
    var kernel = null;
    var rel = {};
    lines.forEach(function (raw) {
      var line = raw.slice(0, LINE_CHARS).trim();
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
    var names = nameSet();
    addHostname(names, hostname);
    return {
      hostname: hostname, kernel: kernel, distro: distro, id: rel.ID || null, versionId: rel.VERSION_ID || null,
      supportEnd: end ? new Date(+end[1], +end[2] - 1, +end[3]) : null, names: names.list
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
    // The local part of an e-mail address is usually the person's name or user name
    re = /([A-Za-z0-9._%+-]{1,64})@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
    while (message.indexOf('@') !== -1 && (m = re.exec(message)) !== null) {
      var local = m[1];
      if (local.length >= 3 && !SYSTEM_USER_SET[local.toLowerCase()]) { addName(names, local); addUser(names, local); }
    }
    if (source === 'pkexec' || source === 'sudo') {
      m = /^([A-Za-z_][A-Za-z0-9_.-]{0,31}) ?: /.exec(message);
      if (m) addUser(names, m[1]);
    }
  }

  // Short journal lines carry no year. They take the reference year, except that a month later than the reference
  // month belongs to the year before (December lines in a January report). The reference is the report Date when
  // given; a year number means the whole of that year (or up to today, for the current year); nothing means today.
  function referenceMonth(yearHint) {
    var now = new Date();
    if (yearHint instanceof Date && !isNaN(yearHint.getTime())) return { year: yearHint.getFullYear(), month: yearHint.getMonth() };
    if (typeof yearHint === 'number' && isFinite(yearHint)) {
      return { year: yearHint, month: yearHint < now.getFullYear() ? 11 : (yearHint > now.getFullYear() ? 0 : now.getMonth()) };
    }
    return { year: now.getFullYear(), month: now.getMonth() };
  }

  function isJournalLine(line) {
    var m = J_SHORT.exec(line);
    return (m !== null && MONTHS.indexOf(m[1]) !== -1) || J_ISO.test(line);
  }

  // journalctl -p 3 -o short (or short-iso). yearHint: the report Date, or a year number (see referenceMonth).
  // truncated: the 20,000-line cap was reached with journal lines still unread. cut: the paste was over 2 MB.
  function parseJournal(text, yearHint) {
    var src = linuxText(text);
    var all = src.text.split(/\r?\n/);
    var truncated = false;
    var ref = referenceMonth(yearHint);
    var year = ref.year;
    var refMonth = ref.month;
    var out = [];
    var names = nameSet();
    var noEntries = false;
    var partial = false;
    var recognised = false;
    var inHint = false;
    var nonEmpty = false;
    for (var i = 0; i < all.length; i++) {
      var line = trimEnd(all[i].slice(0, LINE_CHARS));
      if (out.length >= LINUX_MAX_LINES) {
        if (isJournalLine(line)) { truncated = true; break; }
        continue;
      }
      if (!line) { inHint = false; continue; }
      nonEmpty = true;
      if (inHint && /^\s/.test(line)) continue;
      inHint = false;
      var m = J_SHORT.exec(line);
      if (m && MONTHS.indexOf(m[1]) !== -1) {
        var mon = MONTHS.indexOf(m[1]);
        var y = mon > refMonth ? year - 1 : year;
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
    return { lines: out, total: out.length, truncated: truncated, cut: src.cut, noEntries: noEntries && !out.length, partial: partial, names: names.list, users: names.users };
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
      var head = line.slice(0, 500); // a boot row is about 100 characters
      if (/^\s*IDX\s+BOOT ID\b/.test(head)) continue;
      var row = BOOT_ROW.exec(head);
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
      previous = { lines: [], total: 0, truncated: false, cut: false, noEntries: false, partial: false, names: [], users: [] };
    }
    if (!boots.length && !previous.total) return { error: 'not_boots' };
    return { boots: boots, previous: previous, reportDate: reportDate };
  }

  // upower -i $(upower -e | grep BAT). Only the energy figures are kept: never the vendor, model or serial.
  function parseUpower(text) {
    var s = linuxText(text).text;
    if (!s.trim() || /^[ \t]*Usage:/m.test(s) || /upower \[OPTION/.test(s)) return { present: false };
    if (!/\benergy/.test(s) && !/native-path/.test(s)) return { error: 'not_battery' };
    function wh(key) {
      var m = new RegExp('^[ \\t]*' + key + ':[ \\t]*([0-9]+(?:[.,][0-9]+)?)[ \\t]*Wh', 'm').exec(s);
      return m ? parseFloat(m[1].replace(',', '.')) : null;
    }
    var full = wh('energy-full');
    var design = wh('energy-full-design');
    var c = /^[ \t]*charge-cycles:[ \t]*(\d+)[ \t]*$/m.exec(s);
    return {
      present: true, fullWh: full, designWh: design, cycles: c ? parseInt(c[1], 10) : null,
      healthPct: full !== null && design ? round1((full / design) * 100) : null
    };
  }

  // df -h (also -hT and -i); lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
  var DF_HEADER = /^Filesystem\s+(Type\s+)?(?:Size|1K-blocks|1M-blocks|1024-blocks|Inodes)\s+I?Used\s+(?:Avail(?:able)?|IFree)\s+(?:I?Use|Capacity)%\s+Mounted on$/;
  var DF_ROW = /^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S.*)$/;
  var DF_ROW_T = /^(\S+)\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S.*)$/;
  var DF_CONT = /^\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S.*)$/; // df wraps a long device name onto its own line
  var DF_CONT_T = /^\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%\s+(\S.*)$/;
  var LSBLK_HEADER = /^NAME\s+SIZE\s+TYPE\b/;
  var LSBLK_ROW = /^[\s|`│├└─-]*([^\s|`│├└─-]\S*)\s+(\S+)\s+(\S+)(?:\s+(\S.*))?$/;
  var DF_PCT_TOKEN = /^[^\s\d%~@:$#\/\\<>|=()\[\]{}"']+%$/;

  // A df header in another language: no digits, no English header words, at least three column names, then a
  // "Use%"-like column, then the mount column name. Prompts ("user@pc:~% df -h") and progress lines do not qualify.
  function isForeignDfHeader(line) {
    if (/\d/.test(line) || /Filesystem|Mounted/.test(line)) return false;
    var tokens = line.trim().split(/\s+/);
    for (var k = 3; k < tokens.length - 1; k++) if (DF_PCT_TOKEN.test(tokens[k])) return true;
    return false;
  }

  function parseDisks(text) {
    var src = linuxText(text);
    var lines = src.text.split(/\r?\n/);
    var mode = null;
    var typed = false;
    var inodes = false;
    var sawDf = false;
    var sawLsblk = false;
    var filesystems = [];
    var byDevice = Object.create(null);
    var disks = [];
    var names = nameSet();
    for (var i = 0; i < lines.length; i++) {
      var line = trimEnd(lines[i].slice(0, LINE_CHARS));
      var h = DF_HEADER.exec(line);
      if (h) { mode = 'df'; sawDf = true; typed = !!h[1]; inodes = /Inodes/.test(line); continue; }
      if (LSBLK_HEADER.test(line)) { mode = 'lsblk'; sawLsblk = true; continue; }
      if (!line) continue;
      if (mode === 'df') {
        var m = (typed ? DF_ROW_T : DF_ROW).exec(line);
        var dev, size, pct, mount;
        if (m) { dev = m[1]; size = m[2]; pct = +m[5]; mount = m[6]; }
        else if (/^\S+$/.test(line) && i + 1 < lines.length && (m = (typed ? DF_CONT_T : DF_CONT).exec(trimEnd(lines[i + 1].slice(0, LINE_CHARS))))) {
          dev = line; size = m[1]; pct = +m[4]; mount = m[5]; i++;
        } else continue;
        collectUsers(names, '', mount);
        // Real block filesystems only: snap loop images and optical discs / ISOs are always 100 % full.
        if (!/^\/dev\//.test(dev) || /^\/dev\/(loop|sr\d)/.test(dev)) continue;
        if (byDevice[dev]) { byDevice[dev].mounts.push(mount); continue; }
        var entry = { device: dev, sizeText: size, usedPct: pct, mount: mount, mounts: [mount] };
        byDevice[dev] = entry;
        filesystems.push(entry);
      } else if (mode === 'lsblk') {
        var b = LSBLK_ROW.exec(line);
        if (!b) continue;
        if (b[4]) collectUsers(names, '', b[4]);
        if (b[3] === 'disk' && !/^zram/.test(b[1]) && !/^0B?$/.test(b[2])) disks.push({ name: b[1], sizeText: b[2] });
      } else if (!sawDf && isForeignDfHeader(line.slice(0, 500))) {
        return { unsupportedLanguage: true };
      }
    }
    if (!sawDf && !sawLsblk) return { error: 'not_disks' };
    var worst = null;
    filesystems.forEach(function (f) { if (worst === null || f.usedPct > worst) worst = f.usedPct; });
    return { filesystems: filesystems, disks: disks, worstPct: worst, inodes: inodes, names: names.list, users: names.users };
  }

  // ---------------------------------------------------------------------------
  // Mac: System Information report (.spx, an XML property list) and diagnostic reports (.ips, .panic, .crash)
  // ---------------------------------------------------------------------------
  var MAC_REPORT_HEAD = 1048576; // characters read from each diagnostic report (panicString comes early in the body)
  // macOS majors in release order (numbering jumped from 15 to 26); the last three are the supported ones.
  var MACOS_MAJORS = [10, 11, 12, 13, 14, 15, 26, 27];
  var SPX_TYPES = toSet(['SPHardwareDataType', 'SPSoftwareDataType', 'SPPowerDataType', 'SPStorageDataType']);
  var BATTERY_SERVICE = toSet(['fair', 'poor', 'service recommended', 'replace soon', 'replace now', 'service battery', 'check battery']);
  var PLIST_MAX_DEPTH = 32;
  var NAME_LETTER = /[A-Za-z\u00C0-\u024F]/g;

  function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof Date); }
  function pstr(v) { return typeof v === 'string' ? v : null; }

  // ISO 8601 UTC dates of a property list ("2026-10-18T08:12:44Z"), parsed by hand
  function plistDate(s) {
    var m = /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d{1,9})?Z$/.exec(String(s).trim());
    if (!m) return null;
    var t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
    return isNaN(t) ? null : new Date(t);
  }

  // One plist element as a JS value. Dicts get a null prototype, so no key can reach Object.prototype.
  function plistValue(node, depth) {
    if (!node || depth > PLIST_MAX_DEPTH) return null;
    var tag = node.nodeName;
    var c;
    if (tag === 'dict') {
      var o = Object.create(null);
      var key = null;
      for (c = node.firstElementChild; c; c = c.nextElementSibling) {
        if (c.nodeName === 'key') { key = c.textContent; continue; }
        if (key !== null) { o[key] = plistValue(c, depth + 1); key = null; }
      }
      return o;
    }
    if (tag === 'array') {
      var a = [];
      for (c = node.firstElementChild; c; c = c.nextElementSibling) a.push(plistValue(c, depth + 1));
      return a;
    }
    if (tag === 'true') return true;
    if (tag === 'false') return false;
    var text = node.textContent;
    if (tag === 'string') return text;
    if (tag === 'integer') { var i = parseInt(text, 10); return isNaN(i) ? null : i; }
    if (tag === 'real') { var f = parseFloat(text); return isNaN(f) ? null : f; }
    if (tag === 'date') return plistDate(text);
    return null; // data and anything unknown
  }

  // The value element that follows <key>name</key> among a dict's children, without converting anything
  function dictEntry(dict, name) {
    for (var c = dict.firstElementChild; c; c = c.nextElementSibling) {
      if (c.nodeName === 'key' && c.textContent === name) {
        var v = c.nextElementSibling;
        return v && v.nodeName !== 'key' ? v : null;
      }
    }
    return null;
  }

  // "Export as Text": a heading line ending in ":" and indented "Label: value" lines, in the Mac's language
  function looksLikeSpxText(head) {
    var lines = head.split(/\r?\n/);
    var first = null;
    for (var i = 0; i < lines.length && first === null; i++) if (lines[i].trim()) first = trimEnd(lines[i]);
    if (first === null || first.charAt(first.length - 1) !== ':') return false;
    return lines.some(function (l) { return /^[ \t]+[^ \t:][^:]*: \S/.test(l); });
  }

  function letters(s) { return (String(s).match(NAME_LETTER) || []).length; }

  // Volume names macOS or disk makers give out of the box: never personal, and masking them would garble ordinary
  // words everywhere ("Data" in "Kernel data abort"). Compared lower-case, without a trailing number ("Untitled 2").
  var GENERIC_VOLUME = toSet(['macintosh hd', 'macintosh', 'untitled', 'usb', 'usb drive', 'usb disk', 'usb stick', 'backup', 'backups',
    'data', 'disk', 'drive', 'external', 'external drive', 'external disk', 'volume', 'storage', 'no name', 'time machine',
    'time machine backups', 'recovery', 'preboot', 'update', 'boot camp', 'bootcamp', 'windows', 'shared', 'photos', 'music',
    'media', 'files', 'documents', 'archive', 'work', 'home', 'samsung', 'sandisk', 'seagate', 'lacie', 'kingston']);
  function genericKey(name) { return String(name).trim().toLowerCase().replace(/\s+\d+$/, ''); }

  // Computer name, user, serials, UUIDs and volume names, kept only so the anonymiser can remove them elsewhere.
  // Plain strings are replaced as substrings; {word} entries only as whole words.
  function spxNames(hw, sw, battery, volumes) {
    var list = [];
    var seen = Object.create(null);
    function add(v) { var s = pstr(v); if (s && s.trim() && !seen['s:' + s]) { seen['s:' + s] = true; list.push(s); } }
    function addWord(v) {
      var s = pstr(v);
      if (!s || !s.trim()) return;
      var k = 'w:' + s.toLowerCase();
      if (!seen[k]) { seen[k] = true; list.push({ word: s }); }
    }
    var computer = pstr(sw && sw.local_host_name);
    if (computer) {
      computer = computer.slice(0, 256);
      add(computer);
      add(computer.replace(/[\u2019']/g, function (ch) { return ch === '\u2019' ? "'" : '\u2019'; }));
      add(computer.replace(/[\u2019']/g, '').trim().replace(/\s+/g, '-'));
    }
    var user = pstr(sw && sw.user_name);
    var full = null;
    if (user) {
      user = user.slice(0, 256);
      var m = /^([^()]*)\(([^()]*)\)\s*$/.exec(user);
      full = (m ? m[1] : user).trim();
      add(full);
      if (m) add(m[2].trim());
    }
    if (full) full.split(/[\s,]+/).forEach(function (w) { if (letters(w) >= 4) addWord(w); });
    if (computer) {
      var re = /([A-Za-z\u00C0-\u024F]+)[\u2019']s(?![A-Za-z\u00C0-\u024F])/g;
      var p;
      while ((p = re.exec(computer)) !== null) if (p[1].length >= 4) addWord(p[1]);
    }
    if (hw) { add(hw.serial_number); add(hw.platform_UUID); add(hw.provisioning_UDID); }
    if (battery) add(battery.serial);
    volumes.forEach(function (v) {
      var mount = pstr(v.mount_point) || '';
      var name = pstr(v._name);
      if (name && mount.indexOf('/System/Volumes/') !== 0 && letters(name) >= 4 && !GENERIC_VOLUME[genericKey(name)]) addWord(name);
      add(v.volume_uuid);
    });
    return list;
  }

  // System Information -> File -> Save... (.spx). One DOMParser call; only four data types are converted.
  function parseSpx(text) {
    var s = String(text === null || text === undefined ? '' : text);
    var head = s.slice(0, 2000);
    if (head.indexOf('<plist') === -1 || s.indexOf('<key>_dataType</key>') === -1) {
      return looksLikeSpxText(head) ? { error: 'spx_text' } : { error: 'not_spx' };
    }
    if (head.slice(0, 5) === '<?xml') { var end = head.indexOf('?>'); if (end > 0) s = s.slice(end + 2); }
    var doc;
    try { doc = new DOMParser().parseFromString(s, 'application/xml'); } catch (e) { return { error: 'not_spx' }; }
    if (!doc || doc.getElementsByTagName('parsererror').length) return { error: 'not_spx' };
    var root = doc.documentElement;
    var arr = root && root.nodeName === 'plist' ? root.firstElementChild : null;
    if (!arr || arr.nodeName !== 'array') return { error: 'not_spx' };

    var found = Object.create(null);
    var any = false;
    var reportDate = null;
    for (var d = arr.firstElementChild; d; d = d.nextElementSibling) {
      if (d.nodeName !== 'dict') continue;
      var stamp = dictEntry(d, '_timeStamp');
      if (stamp && stamp.nodeName === 'date') {
        var t = plistDate(stamp.textContent);
        if (t && (!reportDate || t.getTime() > reportDate.getTime())) reportDate = t;
      }
      var typeNode = dictEntry(d, '_dataType');
      var type = typeNode && typeNode.nodeName === 'string' ? typeNode.textContent : '';
      if (SPX_TYPES[type] && !found[type]) {
        var items = dictEntry(d, '_items');
        var list = items && items.nodeName === 'array' ? plistValue(items, 0) : [];
        found[type] = list.filter(isObj);
        any = true;
      }
    }
    if (!any) return { error: 'not_spx' };

    function item(type, name, fallback) {
      var l = found[type] || [];
      for (var i = 0; i < l.length; i++) if (l[i]._name === name) return l[i];
      return fallback && l.length ? l[0] : null;
    }
    var hw = item('SPHardwareDataType', 'hardware_overview', true);
    var sw = item('SPSoftwareDataType', 'os_overview', true);
    var macos = pstr(sw && sw.os_version);
    var major = macos ? /^(?:macOS|Mac OS X|OS X) (\d+)/.exec(macos) : null;
    var chipType = pstr(hw && hw.chip_type);
    var cpuType = pstr(hw && hw.cpu_type);
    var memText = pstr(hw && hw.physical_memory);
    var memMb = memText ? /\bMB\b/i.test(memText) : false;
    // "8,192 MB" / "8.192 MB": in megabytes the separator groups thousands; in gigabytes it is a decimal mark
    var mem = memText ? parseFloat(memMb ? memText.replace(/[,.\s'](?=\d{3}(?!\d))/g, '') : memText.replace(',', '.')) : NaN;
    if (!isNaN(mem) && memMb) mem = round1(mem / 1024);
    if (!isNaN(mem) && /\bTB\b/i.test(memText)) mem = mem * 1024;

    var battery = { present: false };
    var batSerial = null;
    var bi = item('SPPowerDataType', 'spbattery_information', false);
    if (bi) {
      var health = isObj(bi.sppower_battery_health_info) ? bi.sppower_battery_health_info : {};
      var model = isObj(bi.sppower_battery_model_info) ? bi.sppower_battery_model_info : {};
      batSerial = model.sppower_battery_serial_number;
      var capText = health.sppower_battery_health_maximum_capacity;
      var cap = capText === null || capText === undefined ? NaN : parseFloat(String(capText).replace(',', '.'));
      var cyc = health.sppower_battery_cycle_count;
      if (typeof cyc === 'string') cyc = parseInt(cyc, 10);
      var condition = pstr(health.sppower_battery_health);
      battery = {
        present: true,
        healthPct: isNaN(cap) ? null : cap,
        cycles: typeof cyc === 'number' && !isNaN(cyc) ? cyc : null,
        condition: condition,
        service: !!(condition && BATTERY_SERVICE[condition.trim().toLowerCase()])
      };
    }

    var storage = found.SPStorageDataType || [];
    var volumes = [];
    storage.forEach(function (v) {
      var mount = pstr(v.mount_point);
      var size = v.size_in_bytes;
      var free = v.free_space_in_bytes;
      if (!mount || typeof size !== 'number' || size < 1000000000 || mount.indexOf('/System/Volumes/') === 0) return;
      var drive = isObj(v.physical_drive) ? v.physical_drive : {};
      var startup = mount === '/';
      volumes.push({
        where: startup ? 'startup' : (drive.is_internal_disk === 'yes' ? 'internal' : 'external'),
        mount: startup ? '/' : '/Volumes/[volume]',
        usedPct: typeof free === 'number' && free >= 0 && free <= size ? round1((size - free) / size * 100) : null,
        smart: pstr(drive.smart_status)
      });
    });

    return {
      reportDate: reportDate,
      macos: macos,
      osMajor: major ? +major[1] : null,
      modelName: pstr(hw && hw.machine_name),
      modelId: pstr(hw && hw.machine_model),
      chip: chipType || cpuType || null,
      chipKind: chipType ? 'chip' : (cpuType ? 'cpu' : null),
      ramGb: isNaN(mem) ? null : mem,
      battery: battery,
      volumes: volumes,
      names: spxNames(hw, sw, { serial: batSerial }, storage)
    };
  }

  // "2026-10-14 22:41:07.00 +0100" -> Date. By hand: Safari's Date() rejects this form.
  function macReportTime(s) {
    var m = /^(\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))? ([+-])(\d\d):?(\d\d)$/.exec(String(s === null || s === undefined ? '' : s).slice(0, 64).trim());
    if (!m) return null;
    var ms = m[7] ? Math.round(parseFloat('0.' + m[7]) * 1000) : 0;
    var offset = (+m[9] * 60 + +m[10]) * 60000 * (m[8] === '-' ? -1 : 1);
    var t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], ms) - offset;
    return isNaN(t) ? null : new Date(t);
  }

  // Tested in this order on the first line of the panic string
  var PANIC_CAUSES = [
    { name: 'cpu_error', re: /CATERR|IERR|Machine Check|\bMCA\b/i },
    { name: 'sleep_wake', re: /Sleep Wake failure|SleepWake|wake failure/i },
    { name: 'gpu', re: /\bGPU\b|AGX|AMDRadeon|NVDA|IOAccelerator|IntelFramebuffer/i },
    { name: 'watchdog', re: /watchdog/i },
    { name: 'data_abort', re: /data abort|instruction fetch abort|page fault|Kernel trap at/i }
  ];

  function panicCause(line) {
    for (var i = 0; i < PANIC_CAUSES.length; i++) if (PANIC_CAUSES[i].re.test(line)) return PANIC_CAUSES[i].name;
    return 'other';
  }

  // Third-party kernel extensions named after "Kernel Extensions in backtrace:", up to the next blank line (at most 3)
  function panicExtensions(panicText) {
    var marker = 'Kernel Extensions in backtrace:';
    var at = panicText.indexOf(marker);
    if (at === -1) return [];
    var lines = panicText.slice(at + marker.length, at + marker.length + 16384).split('\n');
    var out = [];
    for (var i = 0; i < lines.length && out.length < 3; i++) {
      var line = lines[i].slice(0, 1024);
      if (i > 0 && !line.trim()) break;
      var re = /\bcom\.(?!apple\.)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?=\()/g;
      var m;
      while ((m = re.exec(line)) !== null && out.length < 3) if (out.indexOf(m[0]) === -1) out.push(m[0]);
    }
    return out;
  }

  function skipSpace(s, i) {
    while (i < s.length) {
      var c = s.charCodeAt(i);
      if (c !== 32 && c !== 9 && c !== 10 && c !== 13 && c !== 0xFEFF) break;
      i++;
    }
    return i;
  }

  function macPanic(body, time) {
    var panicText = null;
    if (body.charAt(skipSpace(body, 0)) === '{') {
      var m = /"panicString"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/.exec(body);
      if (m) { try { panicText = JSON.parse('"' + m[1] + '"'); } catch (e) { panicText = null; } }
    } else {
      var p = body.indexOf('panic(');
      if (p !== -1) panicText = body.slice(p);
    }
    if (typeof panicText !== 'string' || !panicText) return { error: 'not_mac_report' };
    var nl = panicText.indexOf('\n');
    var first = trimEnd((nl === -1 ? panicText : panicText.slice(0, nl)).slice(0, LINE_CHARS));
    var rest = first.replace(/^panic\(cpu \d+ caller 0x[0-9a-fA-F]+\):\s*/, '');
    return {
      kind: 'panic', time: time, cause: panicCause(rest),
      causeLine: anonymise(rest).slice(0, 120).trim(),
      extensions: panicExtensions(panicText)
    };
  }

  function macCrash(header, body, time) {
    var head = body.slice(0, 65536);
    var app = pstr(header.app_name) || pstr(header.name);
    if (!app) { var p = /"procName"\s*:\s*"([^"\\]*)"/.exec(head); app = p ? p[1] : ''; }
    var ex = /"exception"\s*:\s*\{[^}]{0,4096}"type"\s*:\s*"([A-Z_]+)"/.exec(head);
    return { kind: 'crash', time: time, app: app.slice(0, 256), exception: ex ? ex[1] : null };
  }

  // Legacy .crash text (macOS 11 and earlier): "Process:  Safari [1234]", "Date/Time:  2026-10-01 09:09:09.123 +0100"
  function macLegacyCrash(s) {
    var lines = s.slice(0, 65536).split('\n');
    var app = null;
    var date = null;
    var ex = null;
    for (var i = 0; i < lines.length; i++) {
      var line = trimEnd(lines[i].slice(0, LINE_CHARS));
      var m;
      if (app === null && (m = /^Process:\s+(.+?) \[\d+\]/.exec(line))) app = m[1];
      else if (date === null && (m = /^Date\/Time:\s+(.+)$/.exec(line))) date = m[1];
      else if (ex === null && (m = /^Exception Type:\s+([A-Z_]+)/.exec(line))) ex = m[1];
    }
    if (app === null || date === null) return { error: 'not_mac_report' };
    return { kind: 'crash', time: macReportTime(date), app: app.slice(0, 256), exception: ex };
  }

  // One diagnostic report (.ips, .panic, .crash). Only the first MAC_REPORT_HEAD characters are read; the file name
  // is never passed in (older ones carry the computer name).
  function parseMacReport(text) {
    var s = String(text === null || text === undefined ? '' : text).slice(0, MAC_REPORT_HEAD);
    var nl = s.indexOf('\n');
    var first = nl === -1 ? s : s.slice(0, nl);
    var header = null;
    if (first.length <= 8192) { try { header = JSON.parse(first); } catch (e) { header = null; } }
    if (isObj(header) && typeof header.bug_type === 'string') {
      var body = nl === -1 ? '' : s.slice(nl + 1);
      var time = macReportTime(header.timestamp);
      if (header.bug_type === '210') return macPanic(body, time);
      if (header.bug_type === '309' || header.bug_type === '109') return macCrash(header, body, time);
      return { kind: 'other' };
    }
    return macLegacyCrash(s);
  }

  // ---------------------------------------------------------------------------
  // Anonymiser: nothing personal may reach the AI summary or the PDF
  // ---------------------------------------------------------------------------
  function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // Compressed IPv6 ("2001:db8::1f", "fe80::1"): hex groups around a "::", not glued to a word ("std::vector").
  var IPV6_COMPRESSED = /(^|[^\w:])((?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})(?![\w]|[:.][0-9a-f])/gi;
  // 16+ hex characters in one case (boot IDs, USB serials), or 32+ in any case, not glued to letters or digits
  // ("_" counts as a separator, so unit_<id> is caught too)
  var HEX_RUN = /(^|[^0-9A-Za-z])([0-9a-f]{16,}|[0-9A-F]{16,}|[0-9a-fA-F]{32,})(?![0-9A-Za-z])/g;

  // At most 300 names (first seen, 3+ characters) go into one alternation, longest first, built once per list:
  // a huge paste with tens of thousands of hostnames must not cost one regex per name per string.
  var ANON_NAME_CAP = 300;
  var NO_NAMES = { list: null, length: -1, re: null, wordRe: null };
  var nameReCache = NO_NAMES;
  // Letters and digits that may not touch a {word} name (no Unicode property escapes: they are ES2018)
  var WORD_CHARS = 'A-Za-z0-9\u00C0-\u024F';

  function isWordName(n) { return n !== null && typeof n === 'object' && typeof n.word === 'string'; }

  // Plain names (strings) are matched as substrings, exactly as before; {word} names only as whole words.
  function namesRegex(names) {
    if (!names || !names.length) return NO_NAMES;
    if (nameReCache.list === names && nameReCache.length === names.length) return nameReCache;
    var picked = [];
    var words = [];
    var seen = Object.create(null);
    var wordSeen = Object.create(null);
    for (var i = 0; i < names.length && (picked.length < ANON_NAME_CAP || words.length < ANON_NAME_CAP); i++) {
      if (isWordName(names[i])) {
        var w = names[i].word;
        var wk = w.toLowerCase();
        if (w.length < 3 || wordSeen[wk] || words.length >= ANON_NAME_CAP) continue;
        wordSeen[wk] = true;
        words.push(w);
        continue;
      }
      var n = names[i] === null || names[i] === undefined ? '' : String(names[i]);
      var key = n.toLowerCase();
      if (n.length < 3 || seen[key] || picked.length >= ANON_NAME_CAP) continue;
      seen[key] = true;
      picked.push(n);
    }
    var longestFirst = function (a, b) { return b.length - a.length; };
    picked.sort(longestFirst);
    words.sort(longestFirst);
    nameReCache = {
      list: names, length: names.length,
      re: picked.length ? new RegExp(picked.map(escapeRe).join('|'), 'gi') : null,
      wordRe: words.length ? new RegExp('(^|[^' + WORD_CHARS + '])(?:' + words.map(escapeRe).join('|') + ')(?=$|[^' + WORD_CHARS + '])', 'gi') : null
    };
    return nameReCache;
  }

  function anonymise(value, names) {
    var s = String(value === null || value === undefined ? '' : value)
      .replace(/\\x2d/gi, '-') // systemd unit names escape "-" as \x2d (dev-disk-by\x2duuid-…)
      .replace(/\bssid[ \t]*[=:]?[ \t]*"[^"\r\n]{0,128}"/gi, 'ssid="[wifi]"')
      .replace(/\bssid[ \t]*[=:]?[ \t]*'[^'\r\n]{0,128}'/gi, 'ssid="[wifi]"')
      .replace(/\bssid=(?!["'])[^\s,;]{1,128}/gi, 'ssid="[wifi]"')
      .replace(IPV6_COMPRESSED, function (all, before, ip) { return /\d/.test(ip) ? before + '[ip]' : all; })
      // Mac: volume names in /Volumes/<name>, and Apple silicon provisioning UDIDs (before HEX_RUN takes half of one)
      .replace(/(\/Volumes\/)(?!\[volume\])[^\/"\n]+/g, '$1[volume]') // already-masked text passes through unchanged
      .replace(/\b[0-9A-F]{8}-[0-9A-F]{16}\b/gi, '[id]')
      .replace(HEX_RUN, '$1[id]');
    var nameRe = namesRegex(names);
    if (nameRe.re) s = s.replace(nameRe.re, '[name]');
    if (nameRe.wordRe) s = s.replace(nameRe.wordRe, '$1[name]');
    return s
      .replace(/([A-Za-z]:\\Users\\)[^\\\s]+/gi, '$1[user]')
      .replace(/(\/(?:home|Users|run\/media|media)\/)[^\/\s]+/g, '$1[user]')
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
    var out = { platform: 'windows', score: 100, findings: findings, facts: facts, reportDate: null,
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
  // Linux rules: findings, score and facts from the five pasted outputs
  // ---------------------------------------------------------------------------
  // Used only when os-release has no SUPPORT_END (end of standard support; Ubuntu ESM and Debian LTS are not counted
  // beyond what is listed). Unknown distributions or versions: no finding.
  var LINUX_EOL = {
    ubuntu: { '20.04': '2025-05-31', '22.04': '2027-04-30', '24.04': '2029-04-30', '24.10': '2025-07-10', '25.04': '2026-01-15', '25.10': '2026-07-09' },
    debian: { '10': '2024-06-30', '11': '2026-08-31', '12': '2028-06-30' }
  };
  var ACPI_NOISE = /^ACPI (BIOS )?Error|ACPI Error/;
  var DISK_ERROR = /I\/O error, dev (sd|nvme|mmcblk|vd|hd)\w*|Buffer I\/O error on dev|failed command: (READ|WRITE)|critical medium error|Medium Error|nvme\d+: (I\/O \d+ QID \d+ timeout|controller is down)|EXT4-fs error|BTRFS( error|: error)|XFS .*(corruption|Internal error)|Currently unreadable|Offline uncorrectable|SMART .*FAIL/i;
  var DISK_NAME = /(?:\/dev\/|\bdev(?:ice)?:? |\b(?=nvme\d+:))((?:sd[a-z]+|vd[a-z]+|hd[a-z]+|nvme\d+(?:n\d+)?|mmcblk\d+)(?:p?\d+)?)/gi;
  var READONLY_FS = /Remounting filesystem read-only|forced readonly|remount.*read-only/i;
  var HW_RISK = /\[Hardware Error\]|Machine check/i;
  var HW_WARN = /PCIe Bus Error|AER: .*error/i;
  var GPU_DRIVER = /^(?:(amdgpu|i915|xe|nouveau|nvidia|radeon)\b|\[drm:\S*? \[(amdgpu|i915|xe|nouveau|nvidia|radeon)\]\]|(NVRM):)/;
  var GPU_TROUBLE = /ERROR|timeout|timed out|\bhang|reset.*fail/i;
  var WIFI_DRIVER = /^(iwlwifi|ath\d+k?|rtw\d*|mt7\d+\w*?)(?:_\w+)?(?=[\s:])/; // "ath10k_pci" -> ath10k
  var WIFI_TROUBLE = /error|fail|timeout|timed out/i;
  var FIRMWARE_FAIL = /Direct firmware load .* failed|firmware: failed to load/;
  var CORE_DUMP = /Process \d+ \((.+?)\) of user \d+ dumped core/;
  var SEGFAULT = /(\S+?)\[\d+\]: segfault at/;
  var OOM_KILLED = /Out of memory: Killed process \d+ \((.+?)\)/;
  var OOM_ANY = /oom-kill:/;
  var PREV_CRASH = /Kernel panic|BUG: (soft|hard) lockup|watchdog: BUG|hard LOCKUP|\bOops\b|general protection fault|kernel BUG at/i;
  var PREV_CRASH_KINDS = [
    { re: /Kernel panic/i, what: 'kernel panic' }, { re: /soft lockup/i, what: 'soft lockup (frozen CPU)' },
    { re: /hard lockup|hard LOCKUP/i, what: 'hard lockup (frozen CPU)' }, { re: /\bOops\b|kernel BUG at|general protection fault/i, what: 'kernel crash (oops)' },
    { re: /watchdog: BUG/i, what: 'watchdog alert' }
  ];
  var LINUX_FIX = {
    disk_errors: 'Back up your files now, then open the Disks app, select the disk and check SMART Data & Self-Tests. Plan to replace the disk.',
    readonly_fs: 'Back up your files now. Restart; if the disk turns read-only again, check it in the Disks app (SMART Data & Self-Tests) and plan to replace it.',
    hardware: 'Install firmware (BIOS/UEFI) updates from Software Updater / GNOME Software or your PC maker. If the errors continue, have the memory and processor tested by a repair shop.',
    hardwarePcie: 'Install firmware (BIOS/UEFI) updates from Software Updater / GNOME Software or your PC maker. If the errors continue, reseat the card or device in that slot.',
    driver_errors: 'Install all updates in Software Updater / GNOME Software / Discover and restart. On Ubuntu, Additional Drivers may offer a recommended graphics or Wi-Fi driver.',
    repeated_errors: 'Install all updates and restart. If one program keeps logging errors, update, reinstall or remove it in GNOME Software or Discover.',
    crashes: 'Update these apps in Software Updater / GNOME Software / Discover. If one keeps crashing, reinstall it or try its Flatpak or Snap version.',
    oom: 'Close memory-hungry apps and browser tabs; System Monitor shows what uses the most memory. If it keeps happening, the PC may need more RAM.',
    prev_boot_crash: 'Install all updates, including firmware updates, in Software Updater / GNOME Software and restart. On Ubuntu, Additional Drivers may offer a more stable graphics driver.',
    disk_full: 'Open Disk Usage Analyzer to find large folders; empty the Trash and remove apps you don’t use in GNOME Software or Discover.',
    disk_inodes: 'Open Disk Usage Analyzer to find folders with very many small files (caches, old downloads); empty the Trash and remove what you don’t need.',
    batteryRisk: 'Plan a battery replacement with the laptop maker or a repair shop.',
    batteryWarn: 'Normal wear. Avoid keeping it at 100 % and hot for long periods; some laptops can limit the charge in Settings > Power.',
    eol_release: 'Upgrade to a supported release with Software Updater / GNOME Software, after a backup.',
    journal_partial: 'Copy the output from an administrator’s account, which can read the system’s messages, then analyse again.'
  };

  // Program-like identifiers: known services, daemons ("...d"), and dotted, hyphenated or underscored names.
  var DAEMON_LIKE = /^(?:kernel|systemd|sudo|pkexec|login|cron|anacron|dbus|NetworkManager|ModemManager|pipewire|wireplumber|pulseaudio|gnome|kde|plasma|xdg|snap|flatpak|polkit|udisks|bluetooth|cups|avahi|rtkit|colord|gdm|lightdm|sddm|Xorg|kwin)|[._-]|[a-z]{2,}d$/i;

  function usable(x) { return x && !x.error && !x.unsupportedLanguage ? x : null; }

  function byCountThenName(a, b) {
    if (b.count !== a.count) return b.count - a.count;
    return a.name < b.name ? -1 : (a.name > b.name ? 1 : 0);
  }

  function countList(map) {
    return Object.keys(map).map(function (k) { return { name: k, count: map[k] }; }).sort(byCountThenName);
  }

  // "476.9G" -> bytes, for ordering the disk sizes in the facts
  function sizeBytes(t) {
    var m = /^([\d.,]+)([BKMGTPE]?)/i.exec(String(t || ''));
    if (!m) return 0;
    return parseFloat(m[1].replace(',', '.')) * Math.pow(1024, 'BKMGTPE'.indexOf((m[2] || 'B').toUpperCase()));
  }

  // Mount points shown on screen and in the PDF: standard system folders as they are, anything else (/media, /run/media,
  // /mnt, custom folders) as "a removable or extra drive", because the path holds the user name and the volume label.
  var SYSTEM_MOUNTS = toSet(['/', '/home', '/boot', '/boot/efi', '/efi', '/var', '/var/log', '/var/lib', '/var/tmp', '/tmp', '/srv',
    '/opt', '/usr', '/usr/local', '/root', '/nix']);
  var EXTRA_DRIVE = 'a removable or extra drive';
  var ANOTHER_EXTRA_DRIVE = 'another removable or extra drive';

  function shownMount(m) { return SYSTEM_MOUNTS[m] ? m : EXTRA_DRIVE; }

  function diskOf(name) {
    var n = name.toLowerCase();
    return n.replace(/^((?:sd|vd|hd)[a-z]+)\d+$/, '$1').replace(/^(nvme\d+n\d+|mmcblk\d+)p\d+$/, '$1');
  }

  function evaluateLinux(reports, now) {
    var r = reports || {};
    var at = now || new Date();
    var findings = [];
    var facts = [];
    var sys = usable(r.system);
    var journal = usable(r.journal);
    var boots = usable(r.boots);
    var bat = usable(r.battery);
    var disks = usable(r.disks);
    var prev = boots && boots.previous ? boots.previous : null;

    // Every name any paste revealed (hostnames, users), minus out-of-the-box hostnames that are also distro names.
    var names = nameSet();
    [r.names, sys && sys.names, journal && journal.names, prev && prev.names, disks && disks.names].forEach(function (list) {
      (list || []).forEach(function (n) { if (n && !DEFAULT_HOST_SET[String(n).toLowerCase()]) addName(names, n); });
    });
    // A log source named after a person (logger tags its lines with the login name) is never listed: any account name,
    // or a hostname (or part of one) that does not look like a program.
    var personal = Object.create(null);
    [r.users, journal && journal.users, prev && prev.users, disks && disks.users].forEach(function (list) {
      (list || []).forEach(function (u) { personal[String(u).toLowerCase()] = 'user'; });
    });
    names.list.forEach(function (n) { var k = String(n).toLowerCase(); if (!personal[k]) personal[k] = 'host'; });
    function isPersonalSource(src) {
      var kind = personal[String(src).toLowerCase()];
      return kind === 'user' || (kind === 'host' && !DAEMON_LIKE.test(src));
    }

    var out = { platform: 'linux', score: 100, findings: findings, facts: facts,
      reportDate: boots && boots.reportDate ? boots.reportDate : at,
      distro: sys ? sys.distro : null, kernel: sys ? sys.kernel : null,
      bootErrors: journal ? journal.total : null, topErrorSources: [], topCrashApps: [], oomKills: null,
      previousBootErrors: prev ? prev.total : null, diskMaxUsedPct: disks ? disks.worstPct : null,
      diskInodes: !!(disks && disks.inodes), // diskMaxUsedPct is then the share of file entries (df -i), not space
      batteryHealthPct: bat && bat.present && typeof bat.healthPct === 'number' ? bat.healthPct : null, names: names.list };
    function add(id, severity, title, detail, fix) { findings.push({ id: id, severity: severity, title: title, detail: detail || '', fix: fix || '' }); }

    // This boot's lines feed every rule except prev_boot_crash. ACPI firmware noise counts in the totals only.
    var lines = journal ? journal.lines : [];
    var bySource = Object.create(null);
    var diskDevices = nameSet();
    var diskHits = 0;
    var readonly = 0;
    var hwRisk = 0;
    var hwWarn = 0;
    var drivers = nameSet();
    var crashes = Object.create(null);
    var oomKilled = 0;
    var oomAny = 0;
    var oomApps = nameSet();
    lines.forEach(function (l) {
      var src = l.source || '';
      if (src) bySource[src] = (bySource[src] || 0) + 1;
      var msg = l.message || '';
      if (ACPI_NOISE.test(msg)) return;
      if (DISK_ERROR.test(msg)) {
        diskHits++;
        var d;
        DISK_NAME.lastIndex = 0;
        while ((d = DISK_NAME.exec(msg)) !== null) addName(diskDevices, diskOf(d[1]));
      }
      if (READONLY_FS.test(msg)) readonly++;
      if (HW_RISK.test(msg)) hwRisk++;
      else if (HW_WARN.test(msg)) hwWarn++;
      if (src === 'kernel') {
        var g = GPU_DRIVER.exec(msg);
        if (g && GPU_TROUBLE.test(msg)) addName(drivers, g[1] || g[2] || 'nvidia');
        var w = WIFI_DRIVER.exec(msg);
        if (w && WIFI_TROUBLE.test(msg)) addName(drivers, w[1]);
        if (FIRMWARE_FAIL.test(msg)) {
          var owner = /^([a-z][a-z0-9_]*) [0-9a-f]{4}:/.exec(msg);
          addName(drivers, 'missing firmware' + (owner ? ' (' + owner[1] + ')' : ''));
        }
      }
      var c = CORE_DUMP.exec(msg) || SEGFAULT.exec(msg);
      if (c) crashes[c[1]] = (crashes[c[1]] || 0) + 1;
      var o = OOM_KILLED.exec(msg);
      if (o) { oomKilled++; addName(oomApps, o[1]); }
      else if (OOM_ANY.test(msg)) oomAny++;
    });
    var sources = countList(bySource).filter(function (s) { return !isPersonalSource(s.name); });
    out.topErrorSources = sources.slice(0, 3);
    var crashList = countList(crashes);
    out.topCrashApps = crashList.slice(0, 3);
    if (journal) out.oomKills = oomKilled || oomAny;

    if (diskHits) {
      add('disk_errors', 'risk', 'A disk reported read or write errors',
        (diskDevices.list.length ? 'Errors on ' + diskDevices.list.slice(0, 5).join(', ') + '. ' : '') + 'Failing reads or writes usually mean the disk is wearing out or its cable is loose.',
        LINUX_FIX.disk_errors);
    }
    if (readonly) {
      add('readonly_fs', 'risk', 'A disk was switched to read-only after errors',
        'Linux stops writing to a filesystem when it finds damage, to protect your files. New files cannot be saved there until it is fixed.',
        LINUX_FIX.readonly_fs);
    }
    if (hwRisk) {
      add('hardware', 'risk', 'The processor or memory reported a hardware error',
        'Machine-check errors come from the processor, memory or motherboard; firmware updates fix some of them.', LINUX_FIX.hardware);
    } else if (hwWarn) {
      add('hardware', 'warn', 'A PCIe device reported errors',
        'PCIe errors come from a card or built-in device (graphics, Wi-Fi, disk). Many are corrected automatically, but repeated ones point to firmware or hardware trouble.',
        LINUX_FIX.hardwarePcie);
    }
    if (drivers.list.length) {
      add('driver_errors', 'warn', 'Graphics or Wi-Fi drivers logged errors',
        'Drivers with errors this boot: ' + drivers.list.slice(0, 5).join(', ') + '. These can cause freezes, screen glitches or dropped Wi-Fi.',
        LINUX_FIX.driver_errors);
    }
    var repeated = sources.filter(function (s) { return s.name !== 'kernel' && s.count >= 5; });
    if (repeated.length) {
      add('repeated_errors', 'warn', 'Some programs keep logging errors',
        'Most errors this boot: ' + repeated.slice(0, 3).map(function (s) { return s.name + ' (' + plural(s.count, 'error', 'errors') + ')'; }).join('; ') + '.',
        LINUX_FIX.repeated_errors);
    }
    var crashTotal = crashList.reduce(function (n, a) { return n + a.count; }, 0);
    if (crashTotal) {
      add('crashes', crashTotal >= 3 ? 'warn' : 'info', crashTotal >= 3 ? 'Some programs keep crashing' : (crashTotal === 1 ? 'A program crashed this boot' : 'Programs crashed this boot'),
        'Crashes this boot: ' + crashList.slice(0, 3).map(function (a) { return a.name + ' (' + plural(a.count, 'crash', 'crashes') + ')'; }).join('; ') + '.',
        LINUX_FIX.crashes);
    }
    if (out.oomKills) {
      add('oom', 'warn', 'The system ran out of memory',
        'Linux closed ' + (oomApps.list.length ? oomApps.list.slice(0, 3).join(', ') : 'a program') + ' to free memory. Unsaved work in it was lost.',
        LINUX_FIX.oom);
    }
    var prevLines = prev ? prev.lines : [];
    var kinds = nameSet();
    prevLines.forEach(function (l) {
      var msg = l.message || '';
      if (!PREV_CRASH.test(msg)) return;
      var k = PREV_CRASH_KINDS.filter(function (x) { return x.re.test(msg); })[0];
      addName(kinds, k ? k.what : 'kernel crash');
    });
    if (kinds.list.length) {
      add('prev_boot_crash', 'risk', 'The previous session ended in a system crash or freeze',
        'The previous boot logged: ' + kinds.list.join(', ') + '. Drivers, overheating or failing hardware are the usual causes.',
        LINUX_FIX.prev_boot_crash);
    }
    if (disks && disks.worstPct !== null && disks.worstPct >= 90) {
      var full = disks.filesystems.filter(function (f) { return f.usedPct >= 90; }).sort(function (a, b) { return b.usedPct - a.usedPct; });
      var extraShown = false;
      var where = full.slice(0, 5).map(function (f) {
        var shown = nameSet();
        (f.mounts || [f.mount]).forEach(function (m) { addName(shown, shownMount(m)); });
        return shown.list.map(function (m) {
          if (m !== EXTRA_DRIVE) return m;
          var label = extraShown ? ANOTHER_EXTRA_DRIVE : EXTRA_DRIVE;
          extraShown = true;
          return label;
        }).join(' and ') + ' (' + f.usedPct + ' %)';
      }).join('; ');
      var sev = disks.worstPct >= 95 ? 'risk' : 'warn';
      if (disks.inodes) {
        add('disk_full', sev, 'A disk is running out of file entries (inodes)',
          'File entries used: ' + where + '. When none are left, no new file can be saved, even with free space.', LINUX_FIX.disk_inodes);
      } else {
        add('disk_full', sev, disks.worstPct >= 95 ? 'A disk is almost full' : 'A disk is getting full',
          'Space used: ' + where + '. A full disk can stop updates and apps from saving.', LINUX_FIX.disk_full);
      }
    }
    if (out.batteryHealthPct !== null && out.batteryHealthPct < 80) {
      var h = out.batteryHealthPct;
      add('battery', h < 60 ? 'risk' : 'warn', 'Battery holds ' + h + ' % of its original charge',
        (bat.cycles !== null ? plural(bat.cycles, 'charge cycle', 'charge cycles') + ' so far. ' : '') + 'Batteries lose capacity with age and heat.',
        h < 60 ? LINUX_FIX.batteryRisk : LINUX_FIX.batteryWarn);
    }
    if (sys) {
      var end = sys.supportEnd ? localDate(sys.supportEnd) : null;
      if (!end && sys.id && sys.versionId && LINUX_EOL[sys.id.toLowerCase()]) end = LINUX_EOL[sys.id.toLowerCase()][sys.versionId] || null;
      if (end && end < localDate(out.reportDate)) {
        add('eol_release', 'warn', (sys.distro || 'This Linux release') + ' no longer gets security updates',
          'Support ended on ' + end + '.', LINUX_FIX.eol_release);
      }
    }
    if ((journal && journal.partial) || (prev && prev.partial)) {
      add('journal_partial', 'info', 'The error log was only partly readable',
        'This account can only see its own messages, not the system’s, so some problems may be missing.', LINUX_FIX.journal_partial);
    }

    var risks = findings.filter(function (f) { return f.severity === 'risk'; }).length;
    var warns = findings.filter(function (f) { return f.severity === 'warn'; }).length;
    out.score = Math.max(0, 100 - 25 * risks - 10 * warns);

    if (out.distro) facts.push({ label: 'System', value: out.distro });
    if (out.kernel) facts.push({ label: 'Kernel', value: out.kernel });
    if (disks && disks.disks.length) {
      var sizes = disks.disks.slice().sort(function (a, b) { return sizeBytes(a.sizeText) - sizeBytes(b.sizeText); })
        .map(function (d) { return d.sizeText; });
      facts.push({ label: 'Disks', value: disks.disks.length + ' (' + sizes.join(', ') + ')' });
    }
    if (disks && disks.worstPct !== null) {
      var worst = disks.filesystems.filter(function (f) { return f.usedPct === disks.worstPct; })[0];
      var worstMount = worst ? ((worst.mounts || [worst.mount]).filter(function (m) { return SYSTEM_MOUNTS[m]; })[0] || EXTRA_DRIVE) : null;
      facts.push({ label: 'Fullest disk', value: disks.worstPct + ' %' + (disks.inodes ? ' of file entries' : '') + (worstMount ? ' (' + worstMount + ')' : '') });
    }
    if (bat && !bat.present) facts.push({ label: 'Battery health', value: 'No battery reported' });
    else if (out.batteryHealthPct !== null) {
      facts.push({ label: 'Battery health', value: out.batteryHealthPct + ' %' + (bat.cycles !== null ? ' (' + plural(bat.cycles, 'cycle', 'cycles') + ')' : '') });
    }
    if (journal) facts.push({ label: 'Errors this boot', value: String(journal.total) });
    if (journal || boots) facts.push({ label: 'Logs from', value: localDate(out.reportDate) });
    facts.forEach(function (f) { f.value = anonymise(f.value, out.names); });
    findings.forEach(function (f) { f.title = anonymise(f.title, out.names); f.detail = anonymise(f.detail, out.names); });
    // Every text field of the evaluation is anonymised here too, so no screen or PDF can show a raw value by mistake.
    out.distro = out.distro === null ? null : anonymise(out.distro, out.names);
    out.kernel = out.kernel === null ? null : anonymise(out.kernel, out.names);
    var anonList = function (items) {
      return items.map(function (a) { return { name: anonymise(a.name, out.names), count: a.count }; }).sort(byCountThenName);
    };
    out.topErrorSources = anonList(out.topErrorSources);
    out.topCrashApps = anonList(out.topCrashApps);
    return out;
  }

  // Mac fixes point to System Settings, the App Store, Disk Utility, Time Machine, Apple Diagnostics or Apple Support:
  // never Terminal or a command.
  var MAC_FIX = {
    panics: 'Install macOS updates (System Settings > General > Software Update). Update or remove apps that add drivers or extensions (System Settings > General > Login Items & Extensions), and unplug hubs, docks and other accessories to see if the restarts stop. If they continue, run Apple Diagnostics (Apple Support explains how to start it) or contact Apple Support.',
    crashes: 'Update the app from the App Store or its own updater. If it keeps crashing, quit it, delete it and install it again.',
    disk_smart: 'Back up now with Time Machine (System Settings > General > Time Machine). Then open Disk Utility, select the disk and run First Aid. A disk that reports a SMART failure should be replaced; contact Apple Support or a repair shop.',
    disk_full: 'Open System Settings > General > Storage to see what takes space, empty the Trash, and remove large files and apps you don\'t use.',
    batteryReplace: 'Plan a battery replacement with Apple or an Apple Authorised Service Provider. System Settings > Battery shows Apple\'s own assessment.',
    batteryWear: 'Normal wear. System Settings > Battery > Battery Health can optimise charging to slow it down.',
    old_macos: 'Open System Settings > General > Software Update to upgrade. If this Mac can\'t run a newer macOS, avoid using it for banking and keep your browser up to date.'
  };
  var MAC_PANIC_CAUSE_ORDER = ['watchdog', 'data_abort', 'cpu_error', 'sleep_wake', 'gpu', 'other'];
  var MAC_PANIC_CAUSE_TEXT = {
    watchdog: 'The system stopped responding, often because of a driver, an extension or a connected device.',
    data_abort: 'A memory access fault inside macOS, usually a driver or kernel extension, sometimes faulty memory.',
    cpu_error: 'The processor reported a hardware error; on Intel Macs this often points to the logic board, power or overheating.',
    sleep_wake: 'It failed while going to sleep or waking up, often because of a connected device.',
    gpu: 'The graphics system failed.',
    other: 'The cause is not one PC Check recognises.'
  };
  var MAC_DISK_WHERE = { startup: 'startup disk', internal: 'internal disk', external: 'external disk' };
  var UNNAMED_APP = 'An unnamed app';

  function capitalise(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // input: {spx: parseSpx result, reports: [parseMacReport results]}. Errors and non-crash reports are ignored.
  function evaluateMac(input, now) {
    var r = input || {};
    var at = now || new Date();
    var findings = [];
    var facts = [];
    var spx = usable(r.spx);
    var given = Array.isArray(r.reports) && r.reports.length > 0;
    var reports = (given ? r.reports : []).filter(function (x) {
      return x && !x.error && (x.kind === 'panic' || x.kind === 'crash');
    });
    var names = spx && Array.isArray(spx.names) ? spx.names : [];

    // Report date: the .spx's newest time stamp, else the newest diagnostic report, else now
    var reportDate = spx && spx.reportDate instanceof Date ? spx.reportDate : null;
    if (!reportDate) {
      reports.forEach(function (x) {
        if (x.time instanceof Date && !isNaN(x.time.getTime()) && (!reportDate || x.time.getTime() > reportDate.getTime())) reportDate = x.time;
      });
    }
    if (!reportDate) reportDate = at;
    var from = reportDate.getTime() - 30 * DAY;
    var to = reportDate.getTime() + DAY;
    var inWindow = reports.filter(function (x) {
      var t = x.time instanceof Date ? x.time.getTime() : NaN;
      return !isNaN(t) && t >= from && t <= to;
    });
    var panics = inWindow.filter(function (x) { return x.kind === 'panic'; })
      .sort(function (a, b) { return b.time.getTime() - a.time.getTime(); });
    var crashes = inWindow.filter(function (x) { return x.kind === 'crash'; });

    var causeCount = Object.create(null);
    var extensions = [];
    panics.forEach(function (p) {
      var c = MAC_PANIC_CAUSE_TEXT[p.cause] ? p.cause : 'other';
      causeCount[c] = (causeCount[c] || 0) + 1;
      (Array.isArray(p.extensions) ? p.extensions : []).forEach(function (id) {
        if (extensions.length < 3 && extensions.indexOf(id) === -1) extensions.push(String(id));
      });
    });
    // App names are masked before counting, so two apps that both carry a personal name are one "[name]" entry
    var appCount = Object.create(null);
    crashes.forEach(function (c) {
      var app = anonymise(c.app || '', names).trim() || UNNAMED_APP;
      appCount[app] = (appCount[app] || 0) + 1;
    });
    var apps = countList(appCount);

    var battery = spx && spx.battery ? spx.battery : null;
    var volumes = spx && Array.isArray(spx.volumes) ? spx.volumes : [];
    var measured = volumes.filter(function (v) { return typeof v.usedPct === 'number'; });
    var worst = null;
    measured.forEach(function (v) { if (!worst || v.usedPct > worst.usedPct) worst = v; });
    var model = !spx ? null : (spx.modelName && spx.modelId ? spx.modelName + ' (' + spx.modelId + ')' : spx.modelName || spx.modelId || null);

    var out = { platform: 'mac', score: 100, findings: findings, facts: facts, reportDate: reportDate,
      macos: spx ? spx.macos : null, model: model, chip: spx ? spx.chip : null,
      ramGb: spx && typeof spx.ramGb === 'number' ? spx.ramGb : null,
      panics30d: given ? panics.length : null, panicCauses: countList(causeCount),
      crashes30d: given ? crashes.length : null, topCrashApps: apps.slice(0, 3),
      diskMaxUsedPct: worst ? worst.usedPct : null,
      batteryHealthPct: battery && battery.present && typeof battery.healthPct === 'number' ? battery.healthPct : null,
      batteryCycles: battery && battery.present && typeof battery.cycles === 'number' ? battery.cycles : null,
      names: names };
    function add(id, severity, title, detail, fix) { findings.push({ id: id, severity: severity, title: title, detail: detail || '', fix: fix || '' }); }

    if (panics.length) {
      var last = panics[0];
      var line = anonymise(last.causeLine || '', names).trim();
      var detail = 'Most recent: ' + localDate(last.time) + (line ? ': ' + line.replace(/[.\s]+$/, '') : '') + '.';
      MAC_PANIC_CAUSE_ORDER.forEach(function (c) { if (causeCount[c]) detail += ' ' + MAC_PANIC_CAUSE_TEXT[c]; });
      if (extensions.length) detail += ' A non-Apple kernel extension was involved: ' + extensions.join(', ') + '.';
      add('panics', panics.length >= 2 ? 'risk' : 'warn',
        'Your Mac restarted after a kernel panic ' + plural(panics.length, 'time', 'times') + ' in 30 days', detail, MAC_FIX.panics);
    }
    if (crashes.length) {
      add('crashes', crashes.length >= 3 ? 'warn' : 'info', 'Apps crashed ' + plural(crashes.length, 'time', 'times') + ' in 30 days',
        'Most crashes: ' + apps.slice(0, 3).map(function (a) { return a.name + ' (' + plural(a.count, 'crash', 'crashes') + ')'; }).join('; ') + '.',
        MAC_FIX.crashes);
    }
    var failing = volumes.filter(function (v) { return typeof v.smart === 'string' && v.smart.trim().toLowerCase() === 'failing'; });
    if (failing.length) {
      var wheres = nameSet();
      failing.forEach(function (v) { addName(wheres, MAC_DISK_WHERE[v.where] || 'disk'); });
      add('disk_smart', 'risk', 'A disk reports that it is failing',
        wheres.list.map(function (w) { return capitalise(w) + ': SMART status Failing.'; }).join(' '), MAC_FIX.disk_smart);
    }
    if (worst && worst.usedPct >= 90) {
      var full = measured.filter(function (v) { return v.usedPct >= 90; }).sort(function (a, b) { return b.usedPct - a.usedPct; });
      add('disk_full', worst.usedPct >= 95 ? 'risk' : 'warn', capitalise(MAC_DISK_WHERE[worst.where] || 'disk') + ' is ' + worst.usedPct + ' % full',
        'Space used: ' + full.map(function (v) { return (MAC_DISK_WHERE[v.where] || 'disk') + ' (' + v.mount + ') ' + v.usedPct + ' %'; }).join('; ') +
        '. A full disk can stop updates and apps from saving.', MAC_FIX.disk_full);
    }
    if (battery && battery.present) {
      var h = out.batteryHealthPct;
      var service = battery.service === true;
      if ((h !== null && h < 80) || service) {
        var bDetail = (out.batteryCycles !== null ? plural(out.batteryCycles, 'charge cycle', 'charge cycles') + ' so far. ' : '') +
          (battery.condition ? 'macOS rates it: ' + battery.condition + '.' : '');
        add('battery', h !== null && h < 60 ? 'risk' : 'warn',
          h !== null ? 'Battery holds ' + h + ' % of its original charge' : 'macOS recommends a battery service',
          bDetail.trim(), (h !== null && h < 60) || service ? MAC_FIX.batteryReplace : MAC_FIX.batteryWear);
      }
    }
    var major = spx && typeof spx.osMajor === 'number' ? spx.osMajor : null;
    if (major !== null && major < MACOS_MAJORS[MACOS_MAJORS.length - 3]) {
      add('old_macos', 'warn', 'macOS ' + major + ' is not one of the three latest versions',
        'Apple gives the full set of security fixes only to current macOS versions.', MAC_FIX.old_macos);
    }
    var age = Math.floor((at.getTime() - reportDate.getTime()) / DAY);
    if (age > 30) add('old_report', 'info', 'This report is ' + age + ' days old', 'Save a new System Information report to see the current state.', '');

    var risks = findings.filter(function (f) { return f.severity === 'risk'; }).length;
    var warns = findings.filter(function (f) { return f.severity === 'warn'; }).length;
    out.score = Math.max(0, 100 - 25 * risks - 10 * warns);

    if (out.macos) facts.push({ label: 'System', value: out.macos });
    if (out.model) facts.push({ label: 'Model', value: out.model });
    if (out.chip) facts.push({ label: spx.chipKind === 'cpu' ? 'Processor' : 'Chip', value: out.chip });
    if (out.ramGb !== null) facts.push({ label: 'Memory', value: out.ramGb + ' GB' });
    var startup = measured.filter(function (v) { return v.where === 'startup'; })[0];
    if (startup) facts.push({ label: 'Startup disk', value: startup.usedPct + ' % used' });
    if (battery && !battery.present) facts.push({ label: 'Battery health', value: 'No battery reported' });
    else if (battery && (out.batteryHealthPct !== null || out.batteryCycles !== null || battery.service)) {
      var parts = [];
      if (out.batteryHealthPct !== null) parts.push(out.batteryHealthPct + ' %' + (out.batteryCycles !== null ? ' (' + plural(out.batteryCycles, 'cycle', 'cycles') + ')' : ''));
      else if (out.batteryCycles !== null) parts.push(plural(out.batteryCycles, 'cycle', 'cycles'));
      if (battery.service && battery.condition) parts.push(battery.condition);
      facts.push({ label: 'Battery health', value: parts.join(', ') });
    }
    if (given) {
      facts.push({ label: 'Kernel panics (30 days)', value: String(panics.length) });
      facts.push({ label: 'App crashes (30 days)', value: String(crashes.length) });
    }
    if (spx || given) facts.push({ label: 'Report from', value: localDate(reportDate) });

    // Every text field is anonymised here too (the parsers did not have the .spx names), so no screen or PDF shows a raw value.
    facts.forEach(function (f) { f.value = anonymise(f.value, names); });
    findings.forEach(function (f) { f.title = anonymise(f.title, names); f.detail = anonymise(f.detail, names); });
    ['macos', 'model', 'chip'].forEach(function (k) { if (out[k] !== null && out[k] !== undefined) out[k] = anonymise(out[k], names); });
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

  var SUMMARY_KERNEL = /^[0-9][0-9A-Za-z._+~-]{0,79}$/; // what the server accepts as a kernel release

  function summaryNumber(v, max) { return typeof v === 'number' && isFinite(v) && v >= 0 && v <= max ? v : null; }

  function buildLinuxSummary(e) {
    var names = e.names || [];
    var str = function (v) { return v === null || v === undefined ? null : cap(anonymise(v, names)); };
    var kernel = str(e.kernel);
    var list = function (items) {
      return (items || []).map(function (a) { return { name: str(a.name), count: Math.min(a.count, 100000) }; }).sort(byCountThenName).slice(0, 3);
    };
    return {
      platform: 'linux',
      distro: str(e.distro),
      kernel: kernel !== null && SUMMARY_KERNEL.test(kernel) ? kernel : null,
      score: e.score,
      findings: e.findings.slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      bootErrors: summaryNumber(e.bootErrors, 100000),
      topErrorSources: list(e.topErrorSources),
      topCrashApps: list(e.topCrashApps),
      oomKills: summaryNumber(e.oomKills, 100000),
      previousBootErrors: summaryNumber(e.previousBootErrors, 100000),
      diskMaxUsedPct: summaryNumber(e.diskMaxUsedPct, 100),
      diskInodes: e.diskInodes === true,
      batteryHealthPct: summaryNumber(e.batteryHealthPct, 200)
    };
  }

  // What the server accepts as a macOS version ("macOS 26.0.1 (25A362)", "Mac OS X 10.13.6 (17G66)")
  var SUMMARY_MACOS = /^(?:macOS|Mac OS X|OS X) [0-9][0-9A-Za-z.() ]{0,63}$/;
  var SUMMARY_MAC_CAUSES = toSet(MAC_PANIC_CAUSE_ORDER);

  function summaryCount(v) { return typeof v === 'number' && isFinite(v) && v >= 0 && Math.floor(v) === v ? Math.min(v, 100000) : null; }

  function buildMacSummary(e) {
    var names = e.names || [];
    var str = function (v) { return v === null || v === undefined ? null : cap(anonymise(v, names)); };
    var macos = str(e.macos);
    return {
      platform: 'mac',
      macos: macos !== null && SUMMARY_MACOS.test(macos) ? macos : null,
      model: str(e.model),
      chip: str(e.chip),
      ramGb: summaryNumber(e.ramGb, 4096),
      score: e.score,
      findings: e.findings.slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      panics30d: summaryCount(e.panics30d),
      panicCauses: (e.panicCauses || []).filter(function (c) { return SUMMARY_MAC_CAUSES[c.name]; })
        .map(function (c) { return { name: c.name, count: summaryCount(c.count) || 0 }; }).sort(byCountThenName).slice(0, 3),
      crashes30d: summaryCount(e.crashes30d),
      topCrashApps: (e.topCrashApps || []).map(function (a) { return { name: str(a.name), count: summaryCount(a.count) || 0 }; })
        .sort(byCountThenName).slice(0, 3),
      diskMaxUsedPct: summaryNumber(e.diskMaxUsedPct, 100),
      batteryHealthPct: summaryNumber(e.batteryHealthPct, 200),
      batteryCycles: summaryCount(e.batteryCycles)
    };
  }

  function buildSummary(e) {
    if (e && e.platform === 'mac') return buildMacSummary(e);
    if (e && e.platform === 'linux') return buildLinuxSummary(e);
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
    evaluateWindows: evaluateWindows, evaluateLinux: evaluateLinux, anonymise: anonymise, buildSummary: buildSummary,
    LINUX_PASTE_CAP: LINUX_PASTE_CAP, LINUX_MAX_LINES: LINUX_MAX_LINES,
    parseLinuxSystem: parseLinuxSystem, parseJournal: parseJournal, parseBoots: parseBoots,
    parseUpower: parseUpower, parseDisks: parseDisks,
    MAC_REPORT_HEAD: MAC_REPORT_HEAD, MACOS_MAJORS: MACOS_MAJORS, parseSpx: parseSpx, parseMacReport: parseMacReport,
    evaluateMac: evaluateMac
  };
})();
