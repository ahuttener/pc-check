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

  // The first cause in the table whose regex matches the line, else 'other'
  function panicCauseFrom(line, table) {
    for (var i = 0; i < table.length; i++) if (table[i].re.test(line)) return table[i].name;
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

  function isJsonBody(body) { return body.charAt(skipSpace(body, 0)) === '{'; }

  // One .ips report (macOS 12+, iOS): line 1 is a one-line JSON header with a string bug_type, the rest is the body.
  // Only the first MAC_REPORT_HEAD characters are read. null when the text has no such header.
  function readIps(text) {
    var s = String(text === null || text === undefined ? '' : text).slice(0, MAC_REPORT_HEAD);
    var nl = s.indexOf('\n');
    var first = nl === -1 ? s : s.slice(0, nl);
    var header = null;
    if (first.length <= 8192) { try { header = JSON.parse(first); } catch (e) { header = null; } }
    if (!isObj(header) || typeof header.bug_type !== 'string') return null;
    return { header: header, body: nl === -1 ? '' : s.slice(nl + 1), time: macReportTime(header.timestamp) };
  }

  // The panic text of a panic report: the unescaped "panicString" of a JSON body, or everything from the first
  // "panic(" of a text body. null when there is none.
  function ipsPanicText(body) {
    var panicText = null;
    if (isJsonBody(body)) {
      var m = /"panicString"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"/.exec(body);
      if (m) { try { panicText = JSON.parse('"' + m[1] + '"'); } catch (e) { panicText = null; } }
    } else {
      var p = body.indexOf('panic(');
      if (p !== -1) panicText = body.slice(p);
    }
    return typeof panicText === 'string' && panicText ? panicText : null;
  }

  // The first line of the panic text (at most LINE_CHARS) without its "panic(cpu N caller 0x…): " prefix
  function panicFirstLine(panicText) {
    var nl = panicText.indexOf('\n');
    var first = trimEnd((nl === -1 ? panicText : panicText.slice(0, nl)).slice(0, LINE_CHARS));
    return first.replace(/^panic\(cpu \d+ caller 0x[0-9a-fA-F]+\):\s*/, '');
  }

  function macPanic(body, time) {
    var panicText = ipsPanicText(body);
    if (panicText === null) return { error: 'not_mac_report' };
    var rest = panicFirstLine(panicText);
    return {
      kind: 'panic', time: time, cause: panicCauseFrom(rest, PANIC_CAUSES),
      // Kept whole (at most LINE_CHARS): evaluateMac cuts it to 120 only after masking the .spx names, so a name
      // straddling the cut can never leave a fragment behind.
      causeLine: anonymise(rest).trim(),
      extensions: panicExtensions(panicText)
    };
  }

  // An app crash (bug_type 309 with a JSON body, or 109 with a legacy text body)
  function ipsCrash(header, body, time) {
    var head = body.slice(0, 65536);
    var app = pstr(header.app_name) || pstr(header.name);
    if (!app) { var p = /"procName"\s*:\s*"([^"\\]*)"/.exec(head); app = p ? p[1] : ''; }
    var ex = isJsonBody(head) ? /"exception"\s*:\s*\{[^}]{0,4096}"type"\s*:\s*"([A-Z_]+)"/.exec(head)
      : /^Exception Type:[ \t]+([A-Z_]{1,64})/m.exec(head);
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
    var ips = readIps(text);
    if (ips) {
      // An iPhone or iPad log (mirror of parseIosReport's mac_report): the step says to choose iPhone above
      if (typeof ips.header.os_version === 'string' && /^(?:iPhone OS|iPadOS|iOS)\b/.test(ips.header.os_version)) return { error: 'ios_report' };
      var bug = ips.header.bug_type;
      if (bug === '210') return macPanic(ips.body, ips.time);
      if (bug === '309' || bug === '109') return ipsCrash(ips.header, ips.body, ips.time);
      return { kind: 'other' };
    }
    return macLegacyCrash(String(text === null || text === undefined ? '' : text).slice(0, MAC_REPORT_HEAD));
  }

  // ---------------------------------------------------------------------------
  // iPhone: diagnostic logs saved from Settings > Privacy & Security > Analytics & Improvements > Analytics Data
  // ---------------------------------------------------------------------------
  var IOS_REPORT_HEAD = 1048576; // the same head as the Mac reader (readIps), exported on its own
  // iOS majors in release order (numbering jumped from 18 to 26); the last two are the supported ones.
  var IOS_MAJORS = [15, 16, 17, 18, 26, 27];
  var IOS_MODEL = /^(?:iPhone|iPad|iPod)[0-9]{1,2},[0-9]{1,2}$/;
  var IOS_KEY = /^[0-9A-Fa-f-]{8,64}$/;
  // Pre-iOS 15 crash text: an iPhone, iPad or iPod model, or an iOS version
  var OLD_IOS_CRASH = /^(?:Hardware Model:[ \t]+(?:iPhone|iPad|iPod)|OS Version:[ \t]+(?:iPhone OS|iPadOS|iOS)\b)/m;

  // Tested in this order on the first line of the panic string (a thermalmonitord watchdog is thermal, not watchdog)
  var IOS_PANIC_CAUSES = [
    { name: 'sensor', re: /Missing sensor|AOP PANIC|SMC PANIC|\bi2c\d*\b/i },
    { name: 'thermal', re: /thermalmonitord|\bthermal\b/i },
    { name: 'sep', re: /\bSEP\b|AppleSEP|sep_panic/ },
    { name: 'storage', re: /ANS2|\bNAND\b|AppleNVMe|\bnvme\b|AppleANS/i },
    { name: 'gpu', re: /\bGPU\b|AGX|IOAccelerator/i },
    { name: 'watchdog', re: /watchdog/i },
    { name: 'data_abort', re: /data abort|instruction fetch abort|page fault/i }
  ];

  function iosModel(m) { return m && IOS_MODEL.test(m[1]) ? m[1] : null; }

  function iosJetsam(body, time) {
    var largest = null;
    var overLimit = [];
    var doc = null;
    try { doc = JSON.parse(body); } catch (e) { doc = null; }
    if (isObj(doc)) {
      if (typeof doc.largestProcess === 'string' && doc.largestProcess) largest = doc.largestProcess.slice(0, 256);
      var procs = Array.isArray(doc.processes) ? doc.processes : [];
      for (var i = 0; i < procs.length && overLimit.length < 3; i++) {
        var p = procs[i];
        if (!isObj(p) || p.reason !== 'per-process-limit' || typeof p.name !== 'string' || !p.name) continue;
        var name = p.name.slice(0, 256);
        if (overLimit.indexOf(name) === -1) overLimit.push(name);
      }
    } else {
      // Cut short (only the head was read): the largest process still comes early in the body
      var m = /"largestProcess"\s*:\s*"([^"\\]{1,256})"/.exec(body.slice(0, 65536));
      if (m) largest = m[1];
    }
    return { kind: 'jetsam', time: time, largest: largest, overLimit: overLimit };
  }

  // One iPhone log. Only the first IOS_REPORT_HEAD characters are read; the file name is never passed in.
  function parseIosReport(text) {
    var ips = readIps(text);
    if (!ips) {
      var plainText = String(text === null || text === undefined ? '' : text).slice(0, IOS_REPORT_HEAD);
      // A .crash from iOS 14 and earlier (no .ips header): not read, the step says it is an old format
      if (OLD_IOS_CRASH.test(plainText.slice(0, 65536))) return { error: 'old_ios_report' };
      var legacy = macLegacyCrash(plainText);
      return legacy.error ? { error: 'not_ios_report' } : { error: 'mac_report' };
    }
    var header = ips.header;
    var body = ips.body;
    var os = typeof header.os_version === 'string' ? header.os_version : '';
    if (/^(?:macOS|Mac OS X|OS X)/.test(os)) return { error: 'mac_report' };
    if (/^(?:Watch OS|watchOS)/.test(os)) return { kind: 'other' };
    var head = body.slice(0, 65536);
    var out;
    var model = null;
    if (header.bug_type === '210') {
      var panicText = ipsPanicText(body);
      if (panicText === null) return { error: 'not_ios_report' };
      var rest = panicFirstLine(panicText);
      // causeLine is kept whole (at most LINE_CHARS); evaluateIos cuts it to 120 after masking, as on the Mac
      out = { kind: 'panic', time: ips.time, cause: panicCauseFrom(rest, IOS_PANIC_CAUSES), causeLine: anonymise(rest).trim() };
      model = iosModel(/"product"\s*:\s*"([^"\\]{1,32})"/.exec(head));
    } else if (header.bug_type === '309' || header.bug_type === '109') {
      out = ipsCrash(header, body, ips.time);
      model = iosModel(isJsonBody(head) ? /"modelCode"\s*:\s*"([^"\\]{1,32})"/.exec(head) : /^Hardware Model:[ \t]+(\S{1,32})/m.exec(head));
    } else if (header.bug_type === '298') {
      out = iosJetsam(body, ips.time);
      model = iosModel(/"product"\s*:\s*"([^"\\]{1,32})"/.exec(head));
    } else {
      return { kind: 'other' };
    }
    var id = header.incident_id;
    // No incident_id and no time: null, so uniqueIosReports keeps every such log (they are outside the 30-day counts)
    out.key = typeof id === 'string' && IOS_KEY.test(id) ? id :
      (out.time ? out.kind + ' ' + out.time.toISOString() + ' ' + (out.app || '') : null);
    out.ios = os && os.length <= 64 ? os : null;
    out.model = model;
    return out;
  }

  // The first report per key (a panic-base and a panic-full copy of one panic, or a log saved twice, share their
  // incident_id). A null key (no incident_id, no time) is never shared: each such log is kept. Errors and skipped
  // logs are dropped. Returns a new array.
  function uniqueIosReports(list) {
    var seen = {};
    var out = [];
    (Array.isArray(list) ? list : []).forEach(function (x, i) {
      if (!x || x.error || (x.kind !== 'panic' && x.kind !== 'crash' && x.kind !== 'jetsam') || (typeof x.key !== 'string' && x.key !== null)) return;
      var key = x.key === null ? '#' + i : x.key;
      if (Object.prototype.hasOwnProperty.call(seen, key)) return;
      seen[key] = true;
      out.push(x);
    });
    return out;
  }

  // ---------------------------------------------------------------------------
  // Android bug report (the dumpstate main text), scanned as a stream of text chunks: one pending line, bounded lists,
  // only the sections, services and property keys PC Check needs. Nothing else is kept.
  // ---------------------------------------------------------------------------
  var ANDROID_TEXT_CAP = 31457280; // decompressed bytes read from the main entry (30 MiB)
  var ANDROID_MAX_EVENTS = 10000;  // per list
  var ANDROID_MAX_BOOTS = 64;
  var ANDROID_PROP_CHARS = 64;
  var ANDROID_APP_CHARS = 256;
  var ANDROID_PROPS = toSet(['ro.build.version.release', 'ro.build.version.release_or_codename', 'ro.build.version.sdk',
    'ro.build.version.security_patch', 'ro.product.manufacturer', 'ro.product.model', 'sys.boot.reason', 'ro.boot.bootreason',
    'persist.sys.boot.reason.history']);
  var BOOT_HISTORY_KEY = 'persist.sys.boot.reason.history';
  var A_DUMPSTATE = /^== dumpstate: (\d{4})-(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)/;
  var A_FINGERPRINT = /^Build fingerprint: '?[^\/' ]{1,64}\/[^\/' ]{1,64}\/[^:\/' ]{1,64}:([^\/' ]{1,64})\//;
  var A_PROP = /^\[([A-Za-z0-9._-]{1,128})\]: \[(.*)$/;
  var A_LOG_TIME = /^(\d\d)-(\d\d) (\d\d):(\d\d):(\d\d)\.(\d{3})\s/;
  var A_BOOT_ENTRY = /^(.{1,64}),(\d{1,12})$/;
  var A_HEALTH = /^\s*health: (\d{1,2})\s*$/;
  var A_CYCLES = /(?:^|\s)(?:[Cc]ycle count|mBatteryCycleCount)\s*[:=]\s*(\d{1,7})(?!\d)/;
  var A_DESIGN = /^\s*Estimated battery capacity: (\d{1,6}) mAh/;
  var A_LEARNED = /^\s*Last learned battery capacity: (\d{1,6}) mAh/;
  var A_DATA_FREE = /^Data-Free: (\d{1,15})K \/ (\d{1,15})K total/;
  var A_SERVICE_PRIORITY = /^(?:CRITICAL|HIGH|NORMAL) /;
  // What the server accepts as an Android version (api/_lib.php): a codename ("Baklava") or free text is skipped
  var SUMMARY_ANDROID = /^[0-9]{1,2}(?:\.[0-9]{1,2}){0,2}$/;

  // Unexpected restarts (AOSP bootstat canonical reasons); expected and unknown reasons give null
  function androidBootCause(reason) {
    if (typeof reason !== 'string' || !reason || reason.length > 128) return null;
    var r = reason.toLowerCase();
    if (/^(?:kernel_panic|panic)\b/.test(r)) return 'kernel_panic';
    if (/^watchdog\b|,watchdog\b|\bwdog\b|\bwdt\b/.test(r)) return 'watchdog';
    if (/\bthermal/.test(r)) return 'thermal';
    if (/\blongkey\b/.test(r)) return 'forced';
    if (/^(?:hard|warm)\b|\bhw_reset\b|\bpmic\b|\bocp\b|\bundervoltage\b/.test(r)) return 'hardware_reset';
    return null;
  }

  function validLocal(y, mo, d, h, mi, s, ms) {
    if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null;
    var t = new Date(y, mo - 1, d, h, mi, s, ms);
    return isNaN(t.getTime()) || t.getDate() !== d || t.getMonth() !== mo - 1 ? null : t;
  }

  // Log lines carry no year: the report's year, or the year before when the month-day is more than one day after
  // the report's (calendar days, so the time of day and the time zone cannot tip it).
  function androidLogTime(m, ref) {
    var mo = +m[1];
    var d = +m[2];
    var r = ref || new Date();
    var y = r.getFullYear();
    if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
    if (Date.UTC(y, mo - 1, d) - Date.UTC(y, r.getMonth(), r.getDate()) > DAY) y--;
    return validLocal(y, mo, d, +m[3], +m[4], +m[5], +m[6]);
  }

  function androidProcess(name) {
    var s = String(name);
    var colon = s.indexOf(':');
    if (colon >= 0) s = s.slice(0, colon);
    s = s.trim();
    return s.length > ANDROID_APP_CHARS ? s.slice(0, ANDROID_APP_CHARS) : s;
  }

  // Field 3 (the process name) of "[User,PID,Process Name,…]"; the free-text fields after it are never kept
  function bracketField(line, from, index) {
    var p = from;
    for (var i = 0; i < index; i++) {
      p = line.indexOf(',', p);
      if (p < 0) return null;
      p++;
    }
    var end = line.indexOf(',', p);
    if (end < 0) end = line.indexOf(']', p);
    if (end < 0) end = line.length;
    return line.slice(p, end);
  }

  function logList() { return { crashes: [], anrs: [], first: null, last: null }; }

  function androidScanner() {
    var time = null;
    var seenDumpstate = false;
    var seenProps = false;
    var inHeader = true;
    var fingerprint = null;
    var props = Object.create(null);
    var boots = [];
    var section = '';
    var service = '';
    var contKey = null; // a property value spanning lines
    var kmsgPanic = false;
    var kmsgWatchdog = false;
    var kmsgSeen = false;
    var events = null;
    var fatal = null;
    var fatalPending = null;
    var battery = { health: null, cycles: null, designMah: null, learnedMah: null };
    var storage = null;
    var lines = 0;
    var pending = '';
    var over = false; // the pending line passed LINE_CHARS: the rest of it is dropped

    function setProp(key, value) {
      if (!ANDROID_PROPS[key] || key in props) return;
      props[key] = value.length && value.length <= ANDROID_PROP_CHARS ? value : null;
    }

    function bootEntry(s) {
      if (boots.length >= ANDROID_MAX_BOOTS) return;
      var m = A_BOOT_ENTRY.exec(s.trim());
      if (!m) return;
      var t = new Date(+m[2] * 1000);
      if (!isNaN(t.getTime())) boots.push({ reason: m[1], time: t });
    }

    // A line cut at LINE_CHARS is treated as closed: it cannot swallow the next property
    function propLine(line, cut) {
      if (contKey !== null) {
        var closes = cut || line.charCodeAt(line.length - 1) === 93; // ]
        if (contKey === BOOT_HISTORY_KEY) bootEntry(closes ? line.slice(0, -1) : line);
        if (closes) contKey = null;
        return;
      }
      if (line.charCodeAt(0) !== 91) return; // [
      var m = A_PROP.exec(line);
      if (!m) return;
      var key = m[1];
      var rest = m[2];
      var closed = rest.charCodeAt(rest.length - 1) === 93;
      var single = cut || closed;
      var value = closed ? rest.slice(0, -1) : rest;
      if (key === BOOT_HISTORY_KEY) {
        if (!(key in props)) {
          props[key] = true;
          if (value) bootEntry(value);
          if (!single) contKey = key;
        } else if (!single) {
          contKey = '#';
        }
        return;
      }
      if (!single) contKey = '#'; // another key's value spans lines: skip to its closing bracket
      else setProp(key, value);
    }

    function logTimeOf(line, list) {
      if (line.charCodeAt(0) < 48 || line.charCodeAt(0) > 57) return null;
      var m = A_LOG_TIME.exec(line);
      if (!m) return null;
      var t = androidLogTime(m, time);
      if (t && list) {
        if (list.first === null) list.first = t;
        list.last = t;
      }
      return t;
    }

    function eventLine(line) {
      var t = logTimeOf(line, events);
      if (!t) return;
      var i = line.indexOf(' am_crash: [');
      var kind = 'crashes';
      if (i < 0) {
        i = line.indexOf(' am_anr: [');
        kind = 'anrs';
        if (i < 0) return;
        i += 10;
      } else {
        i += 12;
      }
      if (events[kind].length >= ANDROID_MAX_EVENTS) return;
      var name = bracketField(line, i, 2);
      if (name !== null) events[kind].push({ time: t, app: androidProcess(name) });
    }

    function systemLine(line) {
      var t = logTimeOf(line, fatal);
      if (!t) return;
      if (line.indexOf('AndroidRuntime: FATAL EXCEPTION') >= 0) { fatalPending = t; return; }
      if (fatalPending === null) return;
      var p = line.indexOf('AndroidRuntime: Process: ');
      if (p < 0) return;
      var rest = line.slice(p + 25);
      var comma = rest.indexOf(',');
      if (fatal.crashes.length < ANDROID_MAX_EVENTS) fatal.crashes.push({ time: fatalPending, app: androidProcess(comma >= 0 ? rest.slice(0, comma) : rest) });
      fatalPending = null;
    }

    function serviceLine(line) {
      var m;
      if (service === 'battery') {
        if (battery.health === null && (m = A_HEALTH.exec(line))) {
          var h = +m[1];
          if (h >= 1 && h <= 7) battery.health = h;
        } else if (battery.cycles === null && line.indexOf('ycle') >= 0 && (m = A_CYCLES.exec(line))) {
          battery.cycles = +m[1];
        }
      } else if (service === 'batterystats') {
        if (line.indexOf('battery capacity') < 0) return;
        if (battery.designMah === null && (m = A_DESIGN.exec(line))) battery.designMah = +m[1];
        else if (battery.learnedMah === null && (m = A_LEARNED.exec(line))) battery.learnedMah = +m[1];
      } else if (service === 'diskstats') {
        if (storage === null && line.charCodeAt(0) === 68 && line.startsWith('Data-Free: ') && (m = A_DATA_FREE.exec(line))) {
          storage = { freeKb: +m[1], totalKb: +m[2] };
        }
      }
    }

    function sectionHeader(line) {
      // "------ TITLE (command) ------" opens a section; "------ 0.4s was the duration of 'TITLE' ------" closes it
      var inner = line.slice(7, line.length - 7);
      service = '';
      contKey = null;
      fatalPending = null;
      if (inner.indexOf(' was the duration of ') >= 0) { section = ''; return; }
      var paren = inner.indexOf(' (');
      section = paren >= 0 ? inner.slice(0, paren) : inner;
      inHeader = false;
      if (section === 'SYSTEM PROPERTIES') seenProps = true;
      else if (section === 'EVENT LOG') { if (events === null) events = logList(); }
      else if (section === 'SYSTEM LOG') { if (fatal === null) fatal = logList(); }
      else if (section === 'LAST KMSG') kmsgSeen = true;
    }

    function handle(line, cut) {
      lines++;
      var n = line.length;
      if (n && line.charCodeAt(n - 1) === 13) line = line.slice(0, --n);
      if (!n) return;
      var c = line.charCodeAt(0);
      if (c === 45 && n >= 14 && line.startsWith('------ ') && line.endsWith(' ------')) { sectionHeader(line); return; }
      if (c === 61 && line.startsWith('== dumpstate:')) {
        seenDumpstate = true;
        if (time === null) {
          var d = A_DUMPSTATE.exec(line);
          if (d) time = validLocal(+d[1], +d[2], +d[3], +d[4], +d[5], +d[6], 0);
        }
        return;
      }
      if (inHeader) {
        if (fingerprint === null && c === 66 && line.startsWith('Build fingerprint: ')) {
          var f = A_FINGERPRINT.exec(line);
          if (f) fingerprint = f[1];
        }
        return;
      }
      if (section === 'SYSTEM PROPERTIES') { propLine(line, cut); return; }
      if (section === 'EVENT LOG') { eventLine(line); return; }
      if (section === 'SYSTEM LOG') { systemLine(line); return; }
      if (section === 'LAST KMSG') {
        if (!kmsgPanic && line.indexOf('Kernel panic - not syncing') >= 0) kmsgPanic = true;
        if (!kmsgWatchdog && line.toLowerCase().indexOf('watchdog bark') >= 0) kmsgWatchdog = true;
        return;
      }
      if (c === 68 && line.startsWith('DUMP OF SERVICE ')) {
        var name = line.slice(16);
        if (name.endsWith(':')) name = name.slice(0, -1);
        service = name.replace(A_SERVICE_PRIORITY, '');
        return;
      }
      if (c === 45 && line.startsWith('--------- ') && line.indexOf(' was the duration of dumpsys ') >= 0) { service = ''; return; }
      if (service) serviceLine(line);
    }

    function push(text) {
      var s = String(text);
      var pos = 0;
      var n = s.length;
      while (pos < n) {
        var nl = s.indexOf('\n', pos);
        var end = nl < 0 ? n : nl;
        if (!over) {
          var room = LINE_CHARS - pending.length;
          if (end - pos > room) { pending += s.slice(pos, pos + room); over = true; }
          else pending += s.slice(pos, end);
        }
        if (nl < 0) break;
        var line = pending;
        var cut = over;
        pending = '';
        over = false;
        handle(line, cut);
        pos = nl + 1;
      }
    }

    function finish() {
      if (pending.length || over) {
        var line = pending;
        var cut = over;
        pending = '';
        over = false;
        handle(line, cut);
      }
      if (!seenDumpstate && !seenProps) return { error: 'not_bugreport' };
      var sdk = props['ro.build.version.sdk'];
      // The first of the three that is a plain version number: a codename falls back to the release
      var android = [props['ro.build.version.release_or_codename'], props['ro.build.version.release'], fingerprint]
        .filter(function (v) { return typeof v === 'string' && SUMMARY_ANDROID.test(v); })[0] || null;
      return {
        kind: 'android',
        time: time,
        android: android,
        sdk: typeof sdk === 'string' && /^[0-9]{1,3}$/.test(sdk) ? +sdk : null,
        securityPatch: props['ro.build.version.security_patch'] || null,
        manufacturer: props['ro.product.manufacturer'] || null,
        model: props['ro.product.model'] || null,
        boots: boots.slice(),
        bootReason: props['sys.boot.reason'] || props['ro.boot.bootreason'] || null,
        kmsgPanic: kmsgPanic,
        kmsgWatchdog: kmsgWatchdog,
        kmsgSeen: kmsgSeen,
        events: events === null ? null : { crashes: events.crashes.slice(), anrs: events.anrs.slice(), first: events.first, last: events.last },
        fatal: fatal === null ? null : { crashes: fatal.crashes.slice(), first: fatal.first, last: fatal.last },
        battery: { health: battery.health, cycles: battery.cycles, designMah: battery.designMah, learnedMah: battery.learnedMah },
        storage: storage === null ? null : { freeKb: storage.freeKb, totalKb: storage.totalKb },
        lines: lines
      };
    }

    return { push: push, finish: finish };
  }

  function parseAndroidBugreport(text) {
    var s = androidScanner();
    s.push(typeof text === 'string' ? text : '');
    return s.finish();
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

  // iPhone: everything under the mobile user's home (data containers hold personal file names, with spaces) up to the
  // end of the quoted value or line; possessive device names in any case ("Jane\u2019s iPhone", "JANE'S IPHONE",
  // "Mary Ann Smith's iPhone 15 Pro Max (2)": up to three name parts, a preceding ordinary word may be masked too, and
  // the model and copy counter after the device word go with it); device host names ("Janes-iPhone.local");
  // international phone numbers with at least 8 digits (a "+0100" time zone or a "+0x1c" offset never matches).
  var IOS_MOBILE_PATH = /(\/var\/mobile\/)[^"\n]*/g;
  var DEVICE_POSSESSIVE = /(^|[^A-Za-z0-9\u00C0-\u024F])(?:[A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F.\-]{0,30} ){0,2}[A-Za-z\u00C0-\u024F][A-Za-z\u00C0-\u024F.\-]{0,30}['`\u2018\u2019\u02BC][sS]?\s+(?:[iI][pP][hH][oO][nN][eE]|[iI][pP][aA][dD]|[iI][pP][oO][dD] [tT][oO][uU][cC][hH]|[iI][pP][oO][dD]|[aA][pP][pP][lL][eE] [wW][aA][tT][cC][hH])(?:(?: [0-9]{1,2}e?)? (?:Pro Max|PRO MAX|Pro|PRO|Plus|PLUS|Max|MAX|mini|MINI|Air|AIR|SE)(?: [0-9]{1,2}(?= ?\(\d{1,3}\)|[)\].,;:!?"'\r\n]|$))?| (?:[0-9]{1,2}e?|SE|XR|XS|X)(?= ?\(\d{1,3}\)|[)\].,;:!?"'\r\n]|$))?(?: ?\(\d{1,3}\))?(?![A-Za-z0-9])/g;
  // Default device names in other languages ("iPhone de Ana Maria Silva", "iPad von Jan van Dijk", "iPhone di Gio"):
  // up to three capitalised name parts, with a lower-case particle between them, so "iPhone de la maison" stays.
  var DEVICE_OF_NAME = /(^|[^A-Za-z0-9\u00C0-\u024F])(?:iPhone|iPad|iPod)\s+(?:de|von|di)\s+[A-Z\u00C0-\u00DE][A-Za-z\u00C0-\u024F.\-]{0,30}(?:\s+(?:(?:da|das|de|del|della|der|den|di|do|dos|du|la|le|van|von|zu)\s+)?[A-Z\u00C0-\u00DE][A-Za-z\u00C0-\u024F.\-]{0,30}){0,2}(?![A-Za-z0-9])/g;
  var DEVICE_HOST = /(^|[^A-Za-z0-9\u00C0-\u024F-])[A-Za-z0-9\u00C0-\u024F-]{1,40}-(?:iPhone|iPad|iPod)(?:-\d{1,3})?(?:\.local)?(?![A-Za-z0-9])/gi;
  var PHONE_INTL = /\+[1-9][0-9 ().-]{6,20}[0-9]/g;
  // Android: shared-storage and app-data paths up to the end of the quoted value or line; account names
  // ("Account {name=…, type=…}"); serials and phone numbers labelled by their key (lower-case serials the upper-case
  // rule misses); possessive device names ("Jane's Pixel 8", "Jane Doe's Galaxy A51", "Jane’s phone"); device host
  // names ("Janes-Pixel-8"); 15-digit IMEI-like numbers (16+ digit runs are already HEX_RUN).
  var ANDROID_STORAGE_PATH = /(\/storage\/emulated\/\d{1,3}\/|\/sdcard\/|\/data\/user(?:_de)?\/\d{1,3}\/|\/data\/media\/\d{1,3}\/)[^"\n]*/g;
  var ANDROID_ACCOUNT = /(\bAccount\s*\{\s*name=)[^,}\n]{1,128}/g;
  var ANDROID_SERIAL = /(\b(?:ro\.(?:boot\.)?serialno|serialno|serial_?number|androidboot\.serialno)\b["'\]]?\s*[:=]\s*\[?["']?)[A-Za-z0-9._-]{4,64}/gi;
  var ANDROID_PHONE_KEY = /(\b(?:mLine1Number|line1Number|mMsisdn|msisdn|phoneNumber|phone_number)\b\s*[=:]\s*["']?)\+?[0-9][0-9 ()-]{3,20}[0-9]/gi;
  var ANDROID_DEVICE_POSSESSIVE = /(^|[^A-Za-z0-9À-ɏ])(?:[A-Za-zÀ-ɏ][A-Za-zÀ-ɏ.\-]{0,30} ){0,2}[A-Za-zÀ-ɏ][A-Za-zÀ-ɏ.\-]{0,30}['`‘’ʼ]s?\s+(?:Pixel|Galaxy|OnePlus|Xperia|Redmi|Xiaomi|Moto|Nokia|Phone|phone|Tablet|tablet|Tab)(?:\s+(?:[0-9][A-Za-z0-9+]{0,5}|[A-Z][0-9][A-Za-z0-9+]{0,5}|Pro|Plus|Ultra|Lite|FE|XL|5G|mini|Fold|Flip)){0,3}(?![A-Za-z0-9])/g;
  var ANDROID_DEVICE_HOST = /(^|[^A-Za-z0-9À-ɏ-])[A-Za-z0-9À-ɏ-]{1,40}-(?:Pixel|Galaxy|Phone)(?:-[A-Za-z0-9]{1,8}){0,3}(?:\.local|\.lan)?(?![A-Za-z0-9])/g;
  var ANDROID_IMEI = /(^|[^0-9A-Za-z.])[0-9]{15}(?![0-9A-Za-z])/g;
  var ANON_MAX_CHARS = 8192; // longer than any title, detail, fact or cause line PC Check builds

  // Not a phone number: glued to a word, a number or a version ("gcc 12.2.0+20231010"), or starting with a
  // time-zone offset ("13:05:12 +1000 2026", "+1100 (2026)")
  var TZ_TOKEN = /^\+(?:0\d|1[0-4])[0-5]\d(?=\s|$|\))/;
  function maskPhone(m, offset, all) {
    if (offset > 0 && /[A-Za-z0-9.\u00C0-\u024F]/.test(all.charAt(offset - 1))) return m;
    if (TZ_TOKEN.test(m)) return m;
    return m.replace(/[^0-9]/g, '').length >= 8 ? '[phone]' : m;
  }

  // The Android rules (shared-storage paths, accounts, labelled serials and phone numbers, Android device and host names,
  // IMEI-like numbers) run only in the Android pass: on other systems' text they would mask ordinary words
  // ("Microsoft's Phone Link", "Report Id 123456789012345"). Windows, Linux, Mac and iPhone text uses anonymise().
  function anonymise(value, names) { return anonymiseText(value, names, false); }
  function anonymiseAndroid(value, names) { return anonymiseText(value, names, true); }

  function anonymiseText(value, names, android) {
    var raw = String(value === null || value === undefined ? '' : value);
    // Some rules backtrack on long runs (60,000 hyphens took seconds): a longer string is cut first, and the token
    // the cut ran through is dropped, so a half identifier cannot slip past the rules.
    if (raw.length > ANON_MAX_CHARS) {
      var end = ANON_MAX_CHARS;
      if (!/\s/.test(raw.charAt(end))) while (end > 0 && !/\s/.test(raw.charAt(end - 1))) end--;
      raw = raw.slice(0, end);
    }
    var s = raw
      .replace(/\\x2d/gi, '-') // systemd unit names escape "-" as \x2d (dev-disk-by\x2duuid-…)
      .replace(/\bssid[ \t]*[=:]?[ \t]*"[^"\r\n]{0,128}"/gi, 'ssid="[wifi]"')
      .replace(/\bssid[ \t]*[=:]?[ \t]*'[^'\r\n]{0,128}'/gi, 'ssid="[wifi]"')
      .replace(/\bssid=(?!["'])[^\s,;]{1,128}/gi, 'ssid="[wifi]"')
      .replace(IPV6_COMPRESSED, function (all, before, ip) { return /\d/.test(ip) ? before + '[ip]' : all; })
      // Mac: volume names in /Volumes/<name>, and Apple silicon provisioning UDIDs (before HEX_RUN takes half of one)
      .replace(/(\/Volumes\/)(?!\[volume\](?:[\/"\n)]|$))[^\/"\n]+/g, '$1[volume]') // already-masked text passes through unchanged
      .replace(/\b[0-9A-F]{8}-[0-9A-F]{16}\b/gi, '[id]')
      .replace(HEX_RUN, '$1[id]');
    var nameRe = namesRegex(names);
    if (nameRe.re) s = s.replace(nameRe.re, '[name]');
    if (nameRe.wordRe) s = s.replace(nameRe.wordRe, '$1[name]');
    s = s
      .replace(IOS_MOBILE_PATH, '$1[path]')
      .replace(DEVICE_POSSESSIVE, '$1[device]')
      .replace(DEVICE_OF_NAME, '$1[device]')
      .replace(DEVICE_HOST, '$1[device]')
      .replace(PHONE_INTL, maskPhone);
    if (android) {
      s = s
        .replace(ANDROID_STORAGE_PATH, '$1[path]')
        .replace(ANDROID_ACCOUNT, '$1[account]')
        .replace(ANDROID_SERIAL, '$1[serial]')
        .replace(ANDROID_PHONE_KEY, '$1[phone]')
        .replace(ANDROID_DEVICE_POSSESSIVE, '$1[device]')
        .replace(ANDROID_DEVICE_HOST, '$1[device]');
    }
    s = s
      .replace(/([A-Za-z]:\\Users\\)[^\\\s]+/gi, '$1[user]')
      .replace(/(\/(?:home|Users|run\/media|media)\/)[^\/\s]+/g, '$1[user]')
      .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]')
      .replace(/\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/gi, '[mac]')
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, '[id]')
      .replace(/\b\d{1,3}(\.\d{1,3}){3}\b/g, '[ip]')
      .replace(/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/gi, '[ip]')
      .replace(/\b(DESKTOP|LAPTOP|PC)-[A-Z0-9]{4,}\b/g, '[pc]');
    if (android) s = s.replace(ANDROID_IMEI, '$1[id]');
    return s.replace(/\b(?=[A-Z0-9]*\d)(?=[A-Z0-9]*[A-Z])[A-Z0-9]{10,}\b/g, '[id]');
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
  // A blue screen, a power loss or a forced restart. "Windows was not properly shut down" is counted on its own: it is
  // usually a shutdown that did not finish (an update or app hung, the battery ran out), not a crash.
  var SHUTDOWN_PROBLEMS = ['Shut down unexpectedly'];
  var UNCLEAN_SHUTDOWN_PROBLEMS = ['Windows was not properly shut down'];

  // YYYY-MM-DD in the viewer's time zone: Windows writes local times, and a report saved late in the
  // evening must not show the next day's UTC date.
  function localDate(d) {
    if (!d || isNaN(d.getTime())) return null;
    var pad = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  var STORE_PACKAGE = /^9[A-Z0-9]{11}-/;
  // Crash source as shown: without a trailing .exe; Java's updater appears under both names
  var CRASH_ALIASES = { jusched: 'Java Update Scheduler' };
  // The same update across versions: its KB number when it has one, else the source without a trailing
  // "(Version …)" or "(1.2.3)" ("… KB2267602 (Version 1.439.100.0)" and "… (Version 1.439.103.0)" are one update).
  function updateKey(source) {
    var src = String(source === null || source === undefined ? '' : source);
    var kb = /\bKB\d{6,8}\b/i.exec(src);
    if (kb) return kb[0].toUpperCase();
    return src.replace(/\s*\((?:Version[^)]*|\d+(?:\.\d+)+)\)\s*$/i, '').trim().toLowerCase();
  }

  function mixedCase(s) { return /[a-z]/.test(s) && /[A-Z]/.test(s); }

  function crashAppName(source) {
    var name = String(source === null || source === undefined ? '' : source).replace(/\.exe$/i, '');
    var k = name.toLowerCase();
    return Object.prototype.hasOwnProperty.call(CRASH_ALIASES, k) ? CRASH_ALIASES[k] : name;
  }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }

  // Good news shown on screen and in the PDF only (never scored, never summarised): a battery read from 80 to 100 %
  // with no battery finding. A list of {title}.
  function batteryGoodNews(pct, cycles, findings) {
    if (typeof pct !== 'number' || !isFinite(pct) || pct < 80 || pct > 100 || findings.some(function (f) { return f.id === 'battery'; })) return [];
    return [{ title: 'Battery is healthy \u2014 it holds ' + pct + ' % of its original capacity' +
      (typeof cycles === 'number' && isFinite(cycles) ? ' after ' + plural(cycles, 'cycle', 'cycles') : '') + '.' }];
  }

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
          'Usually a blue screen or a sudden power loss. This report does not include the blue-screen error code.',
          'Install pending Windows updates, then update the graphics, chipset and storage drivers from your PC maker’s support page. If it happens under heavy load, check that the fans and vents are clean.');
      }
      var unclean = count(UNCLEAN_SHUTDOWN_PROBLEMS);
      out.uncleanShutdowns30d = unclean;
      if (unclean >= 1) {
        add('unclean_shutdowns', unclean >= 3 ? 'warn' : 'info', 'Windows didn\u2019t finish shutting down ' + plural(unclean, 'time', 'times') + ' in 30 days',
          'A shutdown or restart didn\u2019t complete \u2014 often because an update or app hung while shutting down, the battery ran out, or the PC was switched off before it finished. This is usually harmless on its own.',
          'If it happens again, let shutdowns finish (wait for the screen to go dark), keep Windows Update current, and make sure the battery isn\u2019t running out. If it keeps happening, check for app or driver updates.');
      }
      var hardware = count(['Hardware error']);
      out.hardwareErrors30d = hardware;
      if (hardware >= 1) {
        add('hardware', 'warn', 'Windows logged ' + plural(hardware, 'hardware error', 'hardware errors') + ' in 30 days',
          'Hardware errors are often caused by drivers or firmware, and sometimes by memory or storage.',
          'Update the BIOS and drivers from your PC maker. If the errors keep appearing, run Windows Memory Diagnostic (Win + R, mdsched) and check the disk’s health.');
      }

      // One app, one entry: "AcerRegistrationBackGroundTask" and "AcerRegistrationBackGroundTask.exe" are merged
      // (case-insensitive, without .exe), and a known alias joins its display name.
      var bySource = Object.create(null);
      var order = [];
      recent.forEach(function (e) {
        if (CRASH_PROBLEMS.indexOf(e.problem) === -1) return;
        var name = crashAppName(e.source);
        var key = name.toLowerCase();
        if (!bySource[key]) { bySource[key] = { name: name, count: 0 }; order.push(key); }
        // Prefer the mixed-case spelling ("AcerRegistrationBackGroundTask" over "acerregistrationbackgroundtask")
        else if (!mixedCase(bySource[key].name) && mixedCase(name)) bySource[key].name = name;
        bySource[key].count++;
      });
      var top = order.map(function (k) { return bySource[k]; })
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
          'Windows scores stability from 1 to 10 using the crashes and failures above.', 'The score climbs back up on its own a few days after the problems above stop.');
      }
      // A failed update that later installed (a "Successful Windows Update" with the same source, anywhere in the
      // report) is not counted. Microsoft Store app packages ("9PLM9XGG6VKS-OpenAI.Codex") are counted apart.
      var failed = recent.filter(function (e) {
        return e.problem === 'Failed Windows Update' && !rel.events.some(function (o) {
          return o.problem === 'Successful Windows Update' && o.time.getTime() > e.time.getTime() && updateKey(o.source) === updateKey(e.source);
        });
      });
      var storeFailed = failed.filter(function (e) { return STORE_PACKAGE.test(e.source || ''); }).length;
      var failedUpdates = failed.length - storeFailed;
      if (failedUpdates >= 3) {
        add('updates', 'warn', plural(failedUpdates, 'update failed', 'updates failed') + ' in 30 days', '',
          'Open Settings > Windows Update and retry. If one keeps failing, run Settings > System > Troubleshoot > Windows Update.');
      }
      if (storeFailed >= 3) {
        add('store_updates', 'info', plural(storeFailed, 'app update', 'app updates') + ' from the Microsoft Store failed in 30 days',
          'These are updates of apps installed from the Microsoft Store, not Windows updates. The Store usually retries them by itself.',
          'Open Microsoft Store > Library > Get updates. If an app keeps failing, update or reinstall it from the Store.');
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

    out.goodNews = batteryGoodNews(out.batteryHealthPct, bat ? bat.cycles : null, findings);

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
    if (out.uncleanShutdowns30d) facts.push({ label: 'Unfinished shutdowns (30 days)', value: String(out.uncleanShutdowns30d) });
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
    out.goodNews = batteryGoodNews(out.batteryHealthPct, bat ? bat.cycles : null, findings);
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
        // A time after tomorrow is a wrong clock or a forged file: it must not move the window away from the real reports
        if (x.time instanceof Date && !isNaN(x.time.getTime()) && x.time.getTime() <= at.getTime() + DAY &&
          (!reportDate || x.time.getTime() > reportDate.getTime())) reportDate = x.time;
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
      var app = anonymise(c.app || '', names).replace(CONTROL_FORMAT_RE, '').trim() || UNNAMED_APP;
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
      var line = anonymise(last.causeLine || '', names).slice(0, 120).trim();
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
    out.goodNews = batteryGoodNews(out.batteryHealthPct, out.batteryCycles, findings);
    ['macos', 'model', 'chip'].forEach(function (k) { if (out[k] !== null && out[k] !== undefined) out[k] = anonymise(out[k], names); });
    return out;
  }

  // ---------------------------------------------------------------------------
  // iPhone rules. Fixes point only to iPhone Settings, the App Store, restarting, an iCloud backup, Apple Support
  // or an Apple Authorised Service Provider: never a computer, a profile or a third-party app.
  // ---------------------------------------------------------------------------
  var IOS_FIX = {
    panics: 'Install the latest iOS (Settings > General > Software Update), update your apps in the App Store and restart the iPhone. If it keeps restarting by itself, back up to iCloud and contact Apple Support or an Apple Authorised Service Provider: repeated restarts often mean a hardware fault such as the battery, the charging port or a sensor.',
    crashes: 'Update the app in the App Store. If it keeps crashing, delete it (Settings > General > iPhone Storage > the app > Delete App) and install it again.',
    jetsam: 'This is normal now and then. If an app you are using closes often, update it, close apps you no longer use and restart the iPhone.',
    batteryReplace: 'Plan a battery replacement with Apple or an Apple Authorised Service Provider. Settings > Battery > Battery Health shows Apple\'s own assessment.',
    batteryWear: 'The battery is worn. A replacement by Apple or an Apple Authorised Service Provider restores battery life and full performance.',
    old_ios: 'Open Settings > General > Software Update to upgrade. If this iPhone can\'t run a newer iOS, keep your apps up to date and avoid using it for banking.'
  };
  var IOS_PANIC_CAUSE_ORDER = ['sensor', 'thermal', 'sep', 'storage', 'gpu', 'watchdog', 'data_abort', 'other'];
  var IOS_PANIC_CAUSE_TEXT = {
    sensor: 'The iPhone reported a missing or failed sensor, which usually needs a repair.',
    thermal: 'A temperature monitor stopped responding. On iPhones this often points to the battery, the charging port or a sensor.',
    sep: 'The Secure Enclave, which protects Face ID, Touch ID and the passcode, failed.',
    storage: 'The storage chip reported an error.',
    gpu: 'The graphics system failed.',
    watchdog: 'The system stopped responding, often because of a stuck process or a hardware fault.',
    data_abort: 'A memory access fault inside iOS, usually a software bug, sometimes a hardware fault.',
    other: 'The cause is not one PC Check recognises.'
  };
  // Exactly what the server accepts (api/_lib.php, bsc_validate_ios_summary) as an iOS version: the header's
  // os_version ("iPhone OS 26.0.1 (23A355)", a Rapid Security Response "iOS 16.5.1 (c) (20F770750d)"). Never free text.
  var SUMMARY_IOS = /^(?:iPhone OS|iOS|iPadOS) [0-9]{1,2}(?:\.[0-9]{1,3}){0,2}(?: \([a-z]\))?(?: \([0-9]{2}[A-Z][0-9]{1,6}[a-z]?\))?$/;

  function batteryOk(v) { return typeof v === 'number' && isFinite(v) && Math.floor(v) === v && v >= 1 && v <= 100; }

  // An app name as shown and summarised: masked first (with the names and the device rules), then cut to 80 code
  // points without control or format characters; an empty result is "An unnamed app".
  function iosAppName(raw, names) {
    return (cap(anonymise(typeof raw === 'string' ? raw : '', names)) || '').trim() || UNNAMED_APP;
  }

  function iosVersionOk(v) { return typeof v === 'string' && SUMMARY_IOS.test(v); }

  // input: {reports: [parseIosReport results], batteryPct: 1..100 | null, names?: [...]}. The window is the 30 days
  // before "now" (the logs are copied off the phone minutes before the analysis); a log dated after now + 1 day is ignored.
  function evaluateIos(input, now) {
    var r = input || {};
    var at = now || new Date();
    var findings = [];
    var facts = [];
    var names = Array.isArray(r.names) ? r.names : [];
    var reports = uniqueIosReports(r.reports);
    var given = reports.length > 0;
    var bp = r.batteryPct;
    var batteryPct = batteryOk(bp) ? bp : null;
    var to = at.getTime() + DAY;
    var from = at.getTime() - 30 * DAY;
    var timed = reports.filter(function (x) {
      return x.time instanceof Date && !isNaN(x.time.getTime()) && x.time.getTime() <= to;
    }).sort(function (a, b) { return b.time.getTime() - a.time.getTime(); });
    var reportDate = timed.length ? timed[0].time : null;
    var ios = null;
    var model = null;
    timed.forEach(function (x) {
      if (ios === null && iosVersionOk(x.ios)) ios = x.ios;
      if (model === null && typeof x.model === 'string' && IOS_MODEL.test(x.model)) model = x.model;
    });
    var inWindow = timed.filter(function (x) { return x.time.getTime() >= from; });
    var panics = inWindow.filter(function (x) { return x.kind === 'panic'; });
    var crashes = inWindow.filter(function (x) { return x.kind === 'crash'; });
    var jetsams = inWindow.filter(function (x) { return x.kind === 'jetsam'; });

    var causeCount = Object.create(null);
    panics.forEach(function (p) {
      var c = IOS_PANIC_CAUSE_TEXT[p.cause] ? p.cause : 'other';
      causeCount[c] = (causeCount[c] || 0) + 1;
    });
    // App names are masked and cut before counting, so two names that differ only in a masked part are one entry
    var appCount = Object.create(null);
    crashes.forEach(function (c) {
      var app = iosAppName(c.app, names);
      appCount[app] = (appCount[app] || 0) + 1;
    });
    var apps = countList(appCount);
    var largestCount = Object.create(null);
    var overCount = Object.create(null);
    jetsams.forEach(function (j) {
      if (typeof j.largest === 'string' && j.largest) {
        var big = iosAppName(j.largest, names);
        largestCount[big] = (largestCount[big] || 0) + 1;
      }
      var seen = Object.create(null);
      (Array.isArray(j.overLimit) ? j.overLimit : []).slice(0, 3).forEach(function (o) {
        var n = iosAppName(o, names);
        if (seen[n]) return;
        seen[n] = true;
        overCount[n] = (overCount[n] || 0) + 1;
      });
    });
    var largest = countList(largestCount);
    var over = countList(overCount).slice(0, 3);

    var out = { platform: 'ios', score: 100, findings: findings, facts: facts, reportDate: reportDate,
      ios: ios, model: model,
      panics30d: given ? panics.length : null, panicCauses: countList(causeCount),
      crashes30d: given ? crashes.length : null, topCrashApps: apps.slice(0, 3),
      jetsam30d: given ? jetsams.length : null,
      batteryHealthPct: batteryPct, names: names };
    function add(id, severity, title, detail, fix) { findings.push({ id: id, severity: severity, title: title, detail: detail || '', fix: fix || '' }); }

    if (panics.length) {
      var last = panics[0];
      // Masked first, then cut: a name straddling the cut can never leave a fragment behind
      var line = anonymise(typeof last.causeLine === 'string' ? last.causeLine : '', names).replace(CONTROL_FORMAT_RE, '').slice(0, 120).trim();
      var detail = 'Most recent: ' + localDate(last.time) + (line ? ': ' + line.replace(/[.\s]+$/, '') : '') + '.';
      IOS_PANIC_CAUSE_ORDER.forEach(function (c) { if (causeCount[c]) detail += ' ' + IOS_PANIC_CAUSE_TEXT[c]; });
      add('panics', panics.length >= 2 ? 'risk' : 'warn',
        'Your iPhone restarted by itself ' + plural(panics.length, 'time', 'times') + ' in 30 days', detail, IOS_FIX.panics);
    }
    if (crashes.length) {
      add('crashes', crashes.length >= 3 ? 'warn' : 'info', 'Apps crashed ' + plural(crashes.length, 'time', 'times') + ' in 30 days',
        'Most crashes: ' + apps.slice(0, 3).map(function (a) { return a.name + ' (' + plural(a.count, 'crash', 'crashes') + ')'; }).join('; ') + '.',
        IOS_FIX.crashes);
    }
    if (jetsams.length) {
      var jDetail = (largest.length ? 'Biggest memory user most often: ' + largest[0].name + '.' : '') +
        (over.length ? ' Closed for going over their own memory limit: ' + over.map(function (a) { return a.name; }).join(', ') + '.' : '');
      add('jetsam', 'info', 'iOS closed apps to free memory ' + plural(jetsams.length, 'time', 'times') + ' in 30 days', jDetail.trim(), IOS_FIX.jetsam);
    }
    if (batteryPct !== null && batteryPct < 80) {
      add('battery', batteryPct < 60 ? 'risk' : 'warn', 'Battery holds ' + batteryPct + ' % of its original capacity',
        'As read in Settings > Battery > Battery Health. Apple considers a battery worn below 80 %.',
        batteryPct < 60 ? IOS_FIX.batteryReplace : IOS_FIX.batteryWear);
    }
    var majorMatch = ios !== null ? /^(?:iPhone OS|iOS|iPadOS) ([0-9]{1,2})/.exec(ios) : null;
    var major = majorMatch ? +majorMatch[1] : null;
    if (major !== null && major < IOS_MAJORS[IOS_MAJORS.length - 2]) {
      add('old_ios', 'warn', 'iOS ' + major + ' is not one of the two latest versions',
        'Apple gives every security fix only to the latest iOS.', IOS_FIX.old_ios);
    }
    if (reportDate) {
      var age = Math.floor((at.getTime() - reportDate.getTime()) / DAY);
      if (age > 30) add('old_report', 'info', 'The newest log is ' + age + ' days old', 'Save newer logs from Analytics Data to see the current state.', '');
    }

    var risks = findings.filter(function (f) { return f.severity === 'risk'; }).length;
    var warns = findings.filter(function (f) { return f.severity === 'warn'; }).length;
    out.score = Math.max(0, 100 - 25 * risks - 10 * warns);

    if (ios !== null) facts.push({ label: 'System', value: ios });
    if (model !== null) facts.push({ label: 'Model', value: model });
    if (batteryPct !== null) facts.push({ label: 'Battery maximum capacity', value: batteryPct + ' %' });
    if (given) {
      facts.push({ label: 'Panics (30 days)', value: String(panics.length) });
      facts.push({ label: 'App crashes (30 days)', value: String(crashes.length) });
      facts.push({ label: 'Low-memory events (30 days)', value: String(jetsams.length) });
    }
    if (reportDate) facts.push({ label: 'Newest log from', value: localDate(reportDate) });

    facts.forEach(function (f) { f.value = anonymise(f.value, names); });
    findings.forEach(function (f) { f.title = anonymise(f.title, names); f.detail = anonymise(f.detail, names); });
    out.goodNews = batteryGoodNews(batteryPct, null, findings);
    return out;
  }

  // ---------------------------------------------------------------------------
  // Android rules (Design decisions 6-13). Fixes point only to the phone's own Settings (reached by the search box,
  // because menu names vary by maker), the Play Store, a restart, the phone maker's support or an authorised repair
  // shop: never a computer, a cable, rooting, USB debugging or a cleaner, booster or antivirus app.
  // ---------------------------------------------------------------------------
  var ANDROID_FIX = {
    reboots: 'Install the latest software update (open Settings and search for “Software update”), update your apps in the Play Store and restart the phone. If it keeps restarting by itself, back up the phone (search Settings for “Backup”) and contact the phone maker\'s support or an authorised repair shop: repeated restarts can mean a battery or hardware fault.',
    crashes: 'Update the app in the Play Store. If it keeps crashing, open Settings > Apps, pick the app, tap Storage and then Clear cache; if that does not help, uninstall it and install it again.',
    anrs: 'Update the app in the Play Store and restart the phone. If one app keeps freezing, open Settings > Apps, pick the app, tap Storage and then Clear cache.',
    batteryFault: 'Stop using the phone if the battery is swollen or very hot, and have the battery checked by the phone maker\'s support or an authorised repair shop.',
    batteryHeat: 'Let the phone cool down, take off a thick case while charging and avoid heavy use while it charges. If it keeps overheating, have the battery checked by the phone maker\'s support or an authorised repair shop.',
    batteryLow: 'Open Settings > Battery to see which apps use the most power. If the battery runs down quickly, plan a battery replacement with the phone maker\'s support or an authorised repair shop.',
    batteryInfo: 'Nothing to do now. If the battery starts running down quickly, check Settings > Battery and consider a replacement.',
    storage: 'Open Settings > Storage to see what takes space, delete files, photos and apps you no longer need, and clear app caches in Settings > Apps.',
    old_patch: 'Open Settings and search for “Software update”, then install any update offered. If none is offered, this phone may no longer get updates from its maker: keep your apps up to date and avoid using it for banking.'
  };
  // Shown once with every Android result (the page and the PDF): the bug report holds personal data
  var ANDROID_REMINDER = 'When you are done, turn Developer options off again (the switch at the top of the Developer options screen) and delete the bug report from Downloads: it holds personal data.';
  var ANDROID_REBOOT_CAUSE_ORDER = ['kernel_panic', 'watchdog', 'thermal', 'hardware_reset', 'forced'];
  var ANDROID_REBOOT_CAUSE_TEXT = {
    kernel_panic: 'The Android system crashed (a kernel panic).',
    watchdog: 'The system stopped responding and was restarted automatically.',
    thermal: 'The phone restarted or switched off because it got too hot.',
    hardware_reset: 'The hardware reset itself, which can point to a battery or hardware fault.',
    forced: 'The power button was held to force a restart, usually because the phone froze.'
  };
  // BatteryManager health 1..7, as sent in the summary
  var ANDROID_BATTERY_STATUS = ['unknown', 'good', 'overheat', 'dead', 'over_voltage', 'failure', 'cold'];
  var ANDROID_STATUS_FACT = { unknown: 'Unknown', good: 'Good', overheat: 'Overheating', dead: 'Failed', over_voltage: 'Over-voltage', failure: 'Failed', cold: 'Cold' };
  var ANDROID_STATUS_WORD = { overheat: 'overheating', dead: 'dead', over_voltage: 'over-voltage', failure: 'failed' };
  // Exactly what the server accepts (api/_lib.php, bsc_validate_android_summary)
  var SUMMARY_PATCH = /^20[0-9]{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$/;
  var SUMMARY_ANDROID_MODEL = /^[A-Za-z0-9][A-Za-z0-9 ._+()-]{0,47}$/;
  var SUMMARY_PACKAGE = /^[A-Za-z][A-Za-z0-9_]{0,79}(?:\.[A-Za-z0-9_]{1,79}){0,15}$/;
  // Client-only extra guard: 7+ digits in a row can be a phone number, an IMEI or a serial; never shown or sent
  var LONG_DIGITS = /[0-9]{7}/;
  // One part of the model (ro.product.manufacturer, ro.product.model) before they are joined
  var ANDROID_MODEL_PART = /^[A-Za-z0-9 ._+()-]{1,40}$/;

  function intIn(v, lo, hi) { return typeof v === 'number' && isFinite(v) && Math.floor(v) === v && v >= lo && v <= hi ? v : null; }

  function androidModelOk(v) { return typeof v === 'string' && SUMMARY_ANDROID_MODEL.test(v) && !LONG_DIGITS.test(v); }

  // "<manufacturer> <model>" (just the model when it already starts with the manufacturer). A part outside the plain
  // charset, longer than 40 characters, with an "@" or a long digit run, or one the anonymiser would change, is never
  // shown: the model is then unknown.
  function androidModel(manufacturer, model) {
    var part = function (v) {
      if (typeof v !== 'string') return null;
      var x = v.trim();
      return ANDROID_MODEL_PART.test(x) && !LONG_DIGITS.test(x) ? x : null;
    };
    var mo = part(model);
    if (mo === null) return null;
    var ma = part(manufacturer);
    var joined = ma !== null && mo.toLowerCase().indexOf(ma.toLowerCase()) !== 0 ? ma + ' ' + mo : mo;
    return anonymiseAndroid(joined) === joined && androidModelOk(joined) ? joined : null;
  }

  // An app as shown and summarised: only an Android package or process name ("com.example.snapnotes",
  // "system_server") that the anonymiser leaves alone; anything else (a path, an e-mail, a phone number, a name with
  // spaces, 80+ characters, an empty name) is "An unnamed app".
  function androidAppName(raw) {
    var s = typeof raw === 'string' ? raw : '';
    return s.length <= 80 && SUMMARY_PACKAGE.test(s) && !LONG_DIGITS.test(s) && anonymiseAndroid(s) === s ? s : UNNAMED_APP;
  }

  function validTime(d) { return d instanceof Date && !isNaN(d.getTime()); }

  // input: {report: androidScanner().finish() result, truncated?: boolean}. The window is the 30 days before the report
  // time (the "== dumpstate:" line, else the analysis time) up to one day after it.
  // "once" / "2 times" (Android texts only)
  function times(n) { return n === 1 ? 'once' : n + ' times'; }
  function evaluateAndroid(input, now) {
    var r = input || {};
    var rep = r.report && r.report.kind === 'android' ? r.report : {};
    var at = now || new Date();
    var findings = [];
    var facts = [];
    var reportDate = validTime(rep.time) ? rep.time : null;
    var ref = reportDate || at;
    var from = ref.getTime() - 30 * DAY;
    var to = ref.getTime() + DAY;
    var inWindow = function (d) { return validTime(d) && d.getTime() >= from && d.getTime() <= to; };
    var android = typeof rep.android === 'string' && SUMMARY_ANDROID.test(rep.android) ? rep.android : null;
    var securityPatch = typeof rep.securityPatch === 'string' && SUMMARY_PATCH.test(rep.securityPatch) ? rep.securityPatch : null;
    var model = androidModel(rep.manufacturer, rep.model);

    // Unexpected restarts: the boot-reason history when there is one, else the last boot reason, else LAST KMSG.
    // The raw reasons are never kept: only the mapped cause and its time.
    var boots = Array.isArray(rep.boots) ? rep.boots : [];
    var restarts = [];
    var reboots30d = null;
    if (boots.length) {
      boots.forEach(function (b) {
        var c = b ? androidBootCause(b.reason) : null;
        if (c && inWindow(b.time)) restarts.push({ cause: c, time: b.time });
      });
      reboots30d = restarts.length;
    } else if (typeof rep.bootReason === 'string' || rep.kmsgSeen || rep.kmsgPanic || rep.kmsgWatchdog) {
      var cause = androidBootCause(rep.bootReason);
      var kmsgCause = false;
      if (!cause && rep.kmsgPanic) { cause = 'kernel_panic'; kmsgCause = true; }
      else if (!cause && rep.kmsgWatchdog) { cause = 'watchdog'; kmsgCause = true; }
      if (cause) restarts.push({ cause: cause, time: ref, kmsgOnly: kmsgCause });
      reboots30d = restarts.length;
    }
    restarts.sort(function (a, b) { return b.time.getTime() - a.time.getTime(); });
    var causeCount = Object.create(null);
    restarts.forEach(function (x) { causeCount[x.cause] = (causeCount[x.cause] || 0) + 1; });

    // App crashes and "not responding": the EVENT LOG, else crashes from the SYSTEM LOG (ANRs then unknown)
    var log = rep.events ? rep.events : (rep.fatal ? rep.fatal : null);
    var crashList = log ? (Array.isArray(log.crashes) ? log.crashes : []).filter(function (x) { return x && inWindow(x.time); }) : null;
    var anrList = rep.events ? (Array.isArray(rep.events.anrs) ? rep.events.anrs : []).filter(function (x) { return x && inWindow(x.time); }) : null;
    var logDays = null;
    if (log && validTime(log.first) && validTime(log.last)) {
      logDays = Math.min(30, Math.max(1, Math.ceil((log.last.getTime() - log.first.getTime()) / DAY)));
    }
    var tally = function (list) {
      var m = Object.create(null);
      (list || []).forEach(function (x) { var n = androidAppName(x.app); m[n] = (m[n] || 0) + 1; });
      return countList(m);
    };
    var crashApps = tally(crashList);
    var anrApps = tally(anrList);

    // Battery: Android's status and its own capacity estimate (learned / design, both 500..20,000 mAh, 1..120 %)
    var bat = rep.battery || {};
    var health = intIn(bat.health, 1, 7);
    var status = health === null ? null : ANDROID_BATTERY_STATUS[health - 1];
    var cycles = intIn(bat.cycles, 0, 100000);
    var design = intIn(bat.designMah, 500, 20000);
    var learned = intIn(bat.learnedMah, 500, 20000);
    var estimate = null;
    if (design !== null && learned !== null) {
      var ratio = learned / design * 100;
      if (ratio >= 1 && ratio <= 120) estimate = Math.min(100, Math.round(ratio));
    }

    var st = rep.storage;
    var storageFreePct = null;
    if (st && typeof st.freeKb === 'number' && typeof st.totalKb === 'number' && isFinite(st.freeKb) && isFinite(st.totalKb) &&
      st.totalKb > 0 && st.freeKb >= 0 && st.freeKb <= st.totalKb) {
      storageFreePct = Math.floor(st.freeKb * 100 / st.totalKb);
    }

    // Whole calendar days from the patch date to the report's date (UTC arithmetic on the Y-M-D parts)
    var patchAgeDays = null;
    if (securityPatch !== null) {
      var p = securityPatch.split('-');
      var age = Math.round((Date.UTC(ref.getFullYear(), ref.getMonth(), ref.getDate()) - Date.UTC(+p[0], +p[1] - 1, +p[2])) / DAY);
      if (age >= 0) patchAgeDays = age;
    }

    var out = { platform: 'android', score: 100, findings: findings, facts: facts, reportDate: reportDate,
      android: android, securityPatch: securityPatch, patchAgeDays: patchAgeDays, model: model,
      reboots30d: reboots30d, rebootCauses: countList(causeCount),
      crashes: crashList === null ? null : crashList.length, anrs: anrList === null ? null : anrList.length,
      topCrashApps: crashApps.slice(0, 3), topAnrApps: anrApps.slice(0, 3), logDays: logDays,
      batteryHealthPct: estimate, batteryCycles: cycles, batteryStatus: status, storageFreePct: storageFreePct,
      truncated: r.truncated === true, reminder: ANDROID_REMINDER, names: [] };
    function add(id, severity, title, detail, fix) { findings.push({ id: id, severity: severity, title: title, detail: detail || '', fix: fix || '' }); }
    var inLogs = function () { return logDays !== null ? ' in the last ' + (logDays === 1 ? 'day' : logDays + ' days') + ' of logs' : ' in the logs'; };

    if (restarts.length) {
      var detail;
      if (restarts.length === 1 && restarts[0].kmsgOnly) {
        // Only the last-kmsg fallback: its time is the report's, not the crash's, so no date
        detail = restarts[0].cause === 'kernel_panic' ? 'The log from the previous start shows a kernel panic.' :
          'The log from the previous start shows the system stopped responding and was restarted automatically.';
      } else {
        detail = 'Most recent: ' + localDate(restarts[0].time) + '.';
        ANDROID_REBOOT_CAUSE_ORDER.forEach(function (c) { if (causeCount[c]) detail += ' ' + ANDROID_REBOOT_CAUSE_TEXT[c]; });
      }
      add('reboots', restarts.length >= 2 ? 'risk' : 'warn',
        'Your phone restarted by itself ' + times(restarts.length) + ' in 30 days', detail, ANDROID_FIX.reboots);
    }
    if (crashList && crashList.length) {
      add('crashes', crashList.length >= 3 ? 'warn' : 'info', 'Apps crashed ' + times(crashList.length) + inLogs(),
        'Most crashes: ' + crashApps.slice(0, 3).map(function (a) { return a.name + ' (' + plural(a.count, 'crash', 'crashes') + ')'; }).join('; ') +
        '. Android keeps only a few days of logs, so older crashes are not counted.', ANDROID_FIX.crashes);
    }
    if (anrList && anrList.length) {
      add('anrs', anrList.length >= 3 ? 'warn' : 'info', 'Apps stopped responding ' + times(anrList.length) + inLogs(),
        'Most often: ' + anrApps.slice(0, 3).map(function (a) { return a.name + ' (' + times(a.count) + ')'; }).join('; ') + '.', ANDROID_FIX.anrs);
    }
    var statusSev = status === 'dead' || status === 'failure' ? 'risk' : (status === 'overheat' || status === 'over_voltage' ? 'warn' : null);
    var estimateSev = estimate === null ? null : (estimate < 60 ? 'warn' : (estimate < 80 ? 'info' : null));
    if (statusSev || estimateSev) {
      var rank = { risk: 3, warn: 2, info: 1 };
      var sev = !statusSev ? estimateSev : (!estimateSev || rank[statusSev] >= rank[estimateSev] ? statusSev : estimateSev);
      var title = statusSev === 'risk' ? 'Android reports a battery fault' :
        status === 'overheat' && statusSev ? 'Android reports the battery as overheating' :
        status === 'over_voltage' && statusSev ? 'Android reports a battery voltage problem' :
        'Battery holds about ' + estimate + ' % of its original capacity (Android\'s estimate)';
      var parts = [];
      if (statusSev) parts.push('Battery status: ' + ANDROID_STATUS_WORD[status] + '.');
      if (estimate !== null) {
        parts.push('Android estimates the battery holds about ' + estimate + ' % of its original capacity' +
          (cycles !== null ? ' after ' + plural(cycles, 'charge cycle', 'charge cycles') : '') + '.');
      }
      if (!statusSev) parts.push('This is Android\'s own estimate and can be off by a few percent.');
      var fix = statusSev === 'risk' ? ANDROID_FIX.batteryFault : (statusSev === 'warn' ? ANDROID_FIX.batteryHeat : (estimateSev === 'warn' ? ANDROID_FIX.batteryLow : ANDROID_FIX.batteryInfo));
      if (statusSev === 'warn' && estimateSev === 'warn') fix += ' ' + ANDROID_FIX.batteryLow;
      add('battery', sev, title, parts.join(' '), fix);
    }
    if (storageFreePct !== null && storageFreePct < 10) {
      add('storage', storageFreePct < 5 ? 'risk' : 'warn', 'Only ' + storageFreePct + ' % of storage is free',
        'Android needs free space to install updates and to run smoothly.', ANDROID_FIX.storage);
    }
    if (patchAgeDays !== null && patchAgeDays > 90) {
      add('old_patch', patchAgeDays > 180 ? 'risk' : 'warn', 'The security patch is ' + patchAgeDays + ' days old',
        'Security patch level ' + securityPatch + '. Android phones should get a security update every month or two; an old patch can leave known security holes open.',
        ANDROID_FIX.old_patch);
    }
    if (reportDate) {
      var reportAge = Math.floor((at.getTime() - reportDate.getTime()) / DAY);
      if (reportAge > 30) add('old_report', 'info', 'The bug report is ' + reportAge + ' days old', 'Take a new bug report to see the current state.', '');
    }

    var risks = findings.filter(function (f) { return f.severity === 'risk'; }).length;
    var warns = findings.filter(function (f) { return f.severity === 'warn'; }).length;
    out.score = Math.max(0, 100 - 25 * risks - 10 * warns);

    var logLabel = logDays !== null ? ' (last ' + (logDays === 1 ? 'day' : logDays + ' days') + ' of logs)' : ' (in the logs)';
    if (android !== null) facts.push({ label: 'System', value: 'Android ' + android });
    if (securityPatch !== null) facts.push({ label: 'Security patch', value: securityPatch });
    if (model !== null) facts.push({ label: 'Model', value: model });
    if (estimate !== null) facts.push({ label: 'Battery capacity (Android\'s estimate)', value: estimate + ' %' });
    if (status !== null) facts.push({ label: 'Battery status', value: ANDROID_STATUS_FACT[status] });
    if (cycles !== null) facts.push({ label: 'Battery charge cycles', value: String(cycles) });
    if (storageFreePct !== null) facts.push({ label: 'Storage free', value: storageFreePct + ' %' });
    if (reboots30d !== null) facts.push({ label: 'Unexpected restarts (30 days)', value: String(reboots30d) });
    if (crashList !== null) facts.push({ label: 'App crashes' + logLabel, value: String(crashList.length) });
    if (anrList !== null) facts.push({ label: 'Apps not responding' + logLabel, value: String(anrList.length) });
    if (reportDate) facts.push({ label: 'Bug report from', value: localDate(reportDate) });

    facts.forEach(function (f) { f.value = anonymiseAndroid(f.value); });
    findings.forEach(function (f) { f.title = anonymiseAndroid(f.title); f.detail = anonymiseAndroid(f.detail); });
    out.goodNews = estimate !== null && estimate >= 80 && !findings.some(function (f) { return f.id === 'battery'; }) ?
      [{ title: 'Battery looks healthy — Android estimates it holds ' + estimate + ' % of its original capacity.' }] : [];
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

  function summaryCount(v) { return typeof v === 'number' && isFinite(v) && v >= 0 && Math.floor(v) === v ? Math.min(v, 100000) : null; }

  function summaryNumber(v, max) { return typeof v === 'number' && isFinite(v) && v >= 0 && v <= max ? v : null; }

  function buildLinuxSummary(e) {
    var names = e.names || [];
    var str = function (v) { return v === null || v === undefined ? null : cap(anonymise(v, names)); };
    var kernel = str(e.kernel);
    var list = function (items) {
      return (items || []).map(function (a) { return { name: str(a.name), count: summaryCount(a.count) }; })
        .filter(function (a) { return a.name !== null && a.count !== null; }).sort(byCountThenName).slice(0, 3);
    };
    return {
      platform: 'linux',
      distro: str(e.distro),
      kernel: kernel !== null && SUMMARY_KERNEL.test(kernel) ? kernel : null,
      score: e.score,
      findings: e.findings.slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      bootErrors: summaryCount(e.bootErrors),
      topErrorSources: list(e.topErrorSources),
      topCrashApps: list(e.topCrashApps),
      oomKills: summaryCount(e.oomKills),
      previousBootErrors: summaryCount(e.previousBootErrors),
      diskMaxUsedPct: summaryNumber(e.diskMaxUsedPct, 100),
      diskInodes: e.diskInodes === true,
      batteryHealthPct: summaryNumber(e.batteryHealthPct, 200)
    };
  }

  // Exactly what the server accepts (api/_lib.php, bsc_validate_mac_summary): a macOS version as System Information
  // writes it ("macOS 26.0.1 (25A362)", "Mac OS X 10.13.6 (17G66)", a Rapid Security Response "macOS 13.4.1 (c) (22F770820d)"),
  // and model or chip names in a plain charset. A value the server would reject is sent as null.
  var SUMMARY_MACOS = /^(?:macOS|OS X|Mac OS X) [0-9]{2}(?:\.[0-9]{1,3}){0,2}(?: \([a-z]\))?(?: \([0-9A-Za-z]{4,12}\))?$/;
  var SUMMARY_MAC_NAME = /^[A-Za-z0-9 ,.()\[\]\/_+\-\u00ae\u2122]*$/;
  var SUMMARY_MAC_CAUSES = toSet(MAC_PANIC_CAUSE_ORDER);

  function buildMacSummary(e) {
    var names = e.names || [];
    var str = function (v) { return v === null || v === undefined ? null : cap(anonymise(v, names)); };
    var macos = str(e.macos);
    var name = function (v) { var x = str(v); return x !== null && SUMMARY_MAC_NAME.test(x) ? x : null; };
    var counted = function (c) { return c.count >= 1; };
    return {
      platform: 'mac',
      macos: macos !== null && SUMMARY_MACOS.test(macos) ? macos : null,
      model: name(e.model),
      chip: name(e.chip),
      ramGb: summaryNumber(e.ramGb, 4096),
      score: e.score,
      findings: e.findings.slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      panics30d: summaryCount(e.panics30d),
      panicCauses: (e.panicCauses || []).filter(function (c) { return SUMMARY_MAC_CAUSES[c.name]; })
        .map(function (c) { return { name: c.name, count: summaryCount(c.count) || 0 }; }).filter(counted).sort(byCountThenName).slice(0, 3),
      crashes30d: summaryCount(e.crashes30d),
      topCrashApps: (e.topCrashApps || []).map(function (a) { return { name: (str(a.name) || '').trim() || UNNAMED_APP, count: summaryCount(a.count) || 0 }; })
        .filter(counted).sort(byCountThenName).slice(0, 3),
      diskMaxUsedPct: summaryNumber(e.diskMaxUsedPct, 100),
      batteryHealthPct: summaryNumber(e.batteryHealthPct, 200),
      batteryCycles: summaryCount(e.batteryCycles)
    };
  }

  // Exactly what the server accepts (api/_lib.php, bsc_validate_ios_summary): the iOS version and Apple's model
  // identifier by their own regexes, causes and finding ids from the fixed enums, counts of at least 1, and the
  // battery as a whole number from 1 to 100. A value the server would reject is sent as null or left out.
  var SUMMARY_IOS_CAUSES = toSet(IOS_PANIC_CAUSE_ORDER);
  var SUMMARY_IOS_FINDING_IDS = toSet(['panics', 'crashes', 'jetsam', 'battery', 'old_ios', 'old_report']);
  var SUMMARY_SEVERITIES = toSet(['risk', 'warn', 'info']);

  function buildIosSummary(e) {
    var names = e.names || [];
    var str = function (v) { return typeof v === 'string' ? cap(anonymise(v, names)) : null; };
    var ios = str(e.ios);
    var model = str(e.model);
    var counted = function (c) { return c.count >= 1; };
    var bp = e.batteryHealthPct;
    var score = summaryCount(e.score);
    return {
      platform: 'ios',
      ios: ios !== null && SUMMARY_IOS.test(ios) ? ios : null,
      model: model !== null && IOS_MODEL.test(model) ? model : null,
      score: score === null ? 0 : Math.min(score, 100),
      findings: (e.findings || []).filter(function (f) { return f && SUMMARY_IOS_FINDING_IDS[f.id] && SUMMARY_SEVERITIES[f.severity]; })
        .slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      panics30d: summaryCount(e.panics30d),
      panicCauses: (e.panicCauses || []).filter(function (c) { return c && SUMMARY_IOS_CAUSES[c.name]; })
        .map(function (c) { return { name: c.name, count: summaryCount(c.count) || 0 }; }).filter(counted).sort(byCountThenName).slice(0, 3),
      crashes30d: summaryCount(e.crashes30d),
      topCrashApps: (e.topCrashApps || []).filter(function (a) { return a; })
        .map(function (a) { return { name: (str(a.name) || '').trim() || UNNAMED_APP, count: summaryCount(a.count) || 0 }; })
        .filter(counted).sort(byCountThenName).slice(0, 3),
      jetsam30d: summaryCount(e.jetsam30d),
      batteryHealthPct: batteryOk(bp) ? bp : null
    };
  }

  // Exactly what the server accepts (api/_lib.php, bsc_validate_android_summary): versions, dates and the model by
  // their regexes, apps as package names (else "An unnamed app"), causes, statuses and finding ids from the fixed
  // enums, counts of at least 1 in lists, numbers in their ranges. A value the server would reject is sent as null or
  // left out.
  var SUMMARY_ANDROID_CAUSES = toSet(ANDROID_REBOOT_CAUSE_ORDER);
  var SUMMARY_ANDROID_STATUS = toSet(ANDROID_BATTERY_STATUS);
  var SUMMARY_ANDROID_FINDING_IDS = toSet(['reboots', 'crashes', 'anrs', 'battery', 'storage', 'old_patch', 'old_report']);

  function buildAndroidSummary(e) {
    var model = typeof e.model === 'string' ? cap(anonymiseAndroid(e.model)) : null;
    var score = summaryCount(e.score);
    // Counts of the same name are added up, so a list never names an entry twice
    var list = function (items, nameOf) {
      var m = Object.create(null);
      (Array.isArray(items) ? items : []).forEach(function (a) {
        if (!a) return;
        var name = nameOf(a.name);
        var n = summaryCount(a.count);
        if (name === null || !n) return;
        m[name] = Math.min(100000, (m[name] || 0) + n);
      });
      return countList(m).slice(0, 3);
    };
    return {
      platform: 'android',
      android: typeof e.android === 'string' && SUMMARY_ANDROID.test(e.android) ? e.android : null,
      securityPatch: typeof e.securityPatch === 'string' && SUMMARY_PATCH.test(e.securityPatch) ? e.securityPatch : null,
      model: model !== null && model === e.model && androidModelOk(model) ? model : null,
      score: score === null ? 0 : Math.min(score, 100),
      findings: (e.findings || []).filter(function (f) { return f && SUMMARY_ANDROID_FINDING_IDS[f.id] && SUMMARY_SEVERITIES[f.severity]; })
        .slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      reboots30d: summaryCount(e.reboots30d),
      rebootCauses: list(e.rebootCauses, function (n) { return typeof n === 'string' && SUMMARY_ANDROID_CAUSES[n] ? n : null; }),
      crashes: summaryCount(e.crashes),
      anrs: summaryCount(e.anrs),
      topCrashApps: list(e.topCrashApps, androidAppName),
      logDays: intIn(e.logDays, 1, 30),
      batteryHealthPct: batteryOk(e.batteryHealthPct) ? e.batteryHealthPct : null,
      batteryCycles: intIn(e.batteryCycles, 0, 100000),
      batteryStatus: typeof e.batteryStatus === 'string' && SUMMARY_ANDROID_STATUS[e.batteryStatus] ? e.batteryStatus : null,
      storageFreePct: intIn(e.storageFreePct, 0, 100)
    };
  }

  function buildSummary(e) {
    if (e && e.platform === 'android') return buildAndroidSummary(e);
    if (e && e.platform === 'ios') return buildIosSummary(e);
    if (e && e.platform === 'mac') return buildMacSummary(e);
    if (e && e.platform === 'linux') return buildLinuxSummary(e);
    var names = e.names || [];
    return {
      os: cap(e.os === null ? null : anonymise(e.os, names)),
      model: cap(e.model === null ? null : anonymise(e.model, names)),
      ramGb: summaryNumber(e.ramGb, 65536),
      score: e.score,
      findings: e.findings.slice(0, 20).map(function (f) { return { id: f.id, severity: f.severity }; }),
      topCrashApps: e.topCrashApps.filter(function (a) { return typeof a.count === 'number' && a.count >= 0 && Math.floor(a.count) === a.count; }).slice(0, 3)
        .map(function (a) { return { name: cap(anonymise(a.name, names)), count: Math.min(a.count, 1000000) }; }),
      batteryHealthPct: summaryNumber(e.batteryHealthPct, 200),
      shutdowns30d: summaryCount(e.shutdowns30d),
      hardwareErrors30d: summaryCount(e.hardwareErrors30d),
      stabilityNow: summaryNumber(e.stabilityNow, 10)
    };
  }

  window.PCSys = {
    decode: decode, parseReliability: parseReliability, parseBattery: parseBattery, parseMsinfo: parseMsinfo,
    evaluateWindows: evaluateWindows, evaluateLinux: evaluateLinux, anonymise: anonymise, anonymiseAndroid: anonymiseAndroid, buildSummary: buildSummary,
    LINUX_PASTE_CAP: LINUX_PASTE_CAP, LINUX_MAX_LINES: LINUX_MAX_LINES,
    parseLinuxSystem: parseLinuxSystem, parseJournal: parseJournal, parseBoots: parseBoots,
    parseUpower: parseUpower, parseDisks: parseDisks,
    MAC_REPORT_HEAD: MAC_REPORT_HEAD, MACOS_MAJORS: MACOS_MAJORS, parseSpx: parseSpx, parseMacReport: parseMacReport,
    evaluateMac: evaluateMac,
    IOS_REPORT_HEAD: IOS_REPORT_HEAD, IOS_MAJORS: IOS_MAJORS, parseIosReport: parseIosReport, uniqueIosReports: uniqueIosReports,
    evaluateIos: evaluateIos,
    ANDROID_TEXT_CAP: ANDROID_TEXT_CAP, androidScanner: androidScanner, parseAndroidBugreport: parseAndroidBugreport,
    androidBootCause: androidBootCause, evaluateAndroid: evaluateAndroid, ANDROID_REMINDER: ANDROID_REMINDER
  };
})();
