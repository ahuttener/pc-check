/*!
 * PC Check zip reader | CyberSecInfo | MIT License
 * Reads an Android bug report entirely in the browser: the zip's tail and central directory, then only the main text
 * entry (plus the tiny main_entry.txt), streamed and inflated piece by piece. Never the whole file, never another
 * entry, nothing uploaded or stored. No dependency, no worker, no eval. ES2017 on purpose, like the rest of the page.
 */
(function () {
  'use strict';

  var TAIL_MAX = 65557;          // 22-byte end record + the longest possible comment
  var MAX_CD_BYTES = 8388608;    // 8 MiB of central directory
  var MAX_ENTRIES = 30000;
  var MAIN_ENTRY_MAX = 4096;     // main_entry.txt holds one file name
  var MAX_NAME = 1024;
  var DEFAULT_TEXT_CAP = 31457280; // PCSys.ANDROID_TEXT_CAP when sysreport.js is missing
  var MIB = 1048576;
  var INFLATE_STEP = 4096;       // compressed bytes handed to the inflater at a time: bounds what one step can produce
  var INPUT_SLACK = 16777216;    // compressed bytes the inflater may take beyond the text it gave (empty blocks give none)
  var TEXT_PROBE = 65536;        // a plain bug report says "== dumpstate:" in its first bytes
  var MAIN_NAME = /^bugreport-[A-Za-z0-9._-]{1,200}\.txt$/;

  var SIG_LOCAL = 0x04034b50;
  var SIG_CENTRAL = 0x02014b50;
  var SIG_END = 0x06054b50;
  var SIG_ZIP64_LOCATOR = 0x07064b50;

  function fail(code) {
    var e = new Error(code);
    e.zipCode = code;
    throw e;
  }
  function codeOf(e) { return e && typeof e.zipCode === 'string' ? e.zipCode : 'damaged'; }

  // An error thrown by the caller's onText/onProgress: carried out unchanged, never reported as a damaged file
  function CallbackError(error) { this.error = error; }
  function callback(fn, value) {
    try {
      fn(value);
    } catch (e) {
      throw new CallbackError(e);
    }
  }
  function isSize(n) { return typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= Number.MAX_SAFE_INTEGER; }

  // Little-endian reads with an explicit bounds check before each one
  function u16(dv, p) {
    if (p < 0 || p + 2 > dv.byteLength) fail('damaged');
    return dv.getUint16(p, true);
  }
  function u32(dv, p) {
    if (p < 0 || p + 4 > dv.byteLength) fail('damaged');
    return dv.getUint32(p, true);
  }

  // A small, bounded range of the file (the tail, the central directory, a 30-byte local header, a text probe)
  function readRange(blob, start, end) {
    return blob.slice(start, end).arrayBuffer().then(function (b) { return new DataView(b); }, function () { fail('damaged'); });
  }

  function textCap() {
    var S = window.PCSys;
    return S && typeof S.ANDROID_TEXT_CAP === 'number' ? S.ANDROID_TEXT_CAP : DEFAULT_TEXT_CAP;
  }

  function yieldNow() { return new Promise(function (resolve) { setTimeout(resolve, 0); }); }
  function now() { return typeof performance !== 'undefined' && performance.now ? performance.now() : Date.now(); }

  function supportsDeflate() {
    if (typeof DecompressionStream !== 'function' || typeof TransformStream !== 'function') return false;
    try {
      new DecompressionStream('deflate-raw'); // eslint-disable-line no-new
      return true;
    } catch (e) {
      return false;
    }
  }

  function isZipStart(dv) {
    if (dv.byteLength < 4) return false;
    var sig = dv.getUint32(0, true);
    return sig === SIG_LOCAL || sig === SIG_END;
  }

  function isMainName(name) { return MAIN_NAME.test(name) && name.indexOf('..') < 0; }

  // ---------------------------------------------------------------------------
  // Central directory
  // ---------------------------------------------------------------------------
  async function entriesOf(blob) {
    var size = blob.size;
    var tailStart = Math.max(0, size - TAIL_MAX);
    var tail = await readRange(blob, tailStart, size);
    var n = tail.byteLength;
    var at = -1;
    // The end record is trusted only where its comment reaches exactly the end of the file: a signature inside a
    // comment is not an end record.
    for (var p = n - 22; p >= 0; p--) {
      if (tail.getUint32(p, true) === SIG_END && p + 22 + tail.getUint16(p + 20, true) === n) { at = p; break; }
    }
    if (at < 0) {
      var head = await readRange(blob, 0, Math.min(4, size));
      fail(head.byteLength >= 4 && head.getUint32(0, true) === SIG_LOCAL ? 'damaged' : 'not_zip');
    }
    var endAbs = tailStart + at;
    if (endAbs >= 20) {
      var loc = at >= 20 ? tail : await readRange(blob, endAbs - 20, endAbs);
      if (u32(loc, at >= 20 ? at - 20 : 0) === SIG_ZIP64_LOCATOR) fail('zip64');
    }
    var disk = u16(tail, at + 4);
    var cdDisk = u16(tail, at + 6);
    var onDisk = u16(tail, at + 8);
    var total = u16(tail, at + 10);
    var cdSize = u32(tail, at + 12);
    var cdOffset = u32(tail, at + 16);
    if (disk === 0xFFFF || cdDisk === 0xFFFF || onDisk === 0xFFFF || total === 0xFFFF || cdSize === 0xFFFFFFFF || cdOffset === 0xFFFFFFFF) fail('zip64');
    if (total > MAX_ENTRIES || onDisk > MAX_ENTRIES || cdSize > MAX_CD_BYTES) fail('damaged');
    if (disk !== 0 || cdDisk !== 0 || onDisk !== total) fail('multi_disk');
    if (cdOffset + cdSize > endAbs) fail('damaged');
    if (total === 0) return [];
    var cd = await readRange(blob, cdOffset, cdOffset + cdSize);
    var names = new TextDecoder('utf-8');
    var bytes = new Uint8Array(cd.buffer, cd.byteOffset, cd.byteLength);
    var entries = [];
    var q = 0;
    for (var i = 0; i < total; i++) {
      if (u32(cd, q) !== SIG_CENTRAL) fail('damaged');
      var flags = u16(cd, q + 8);
      var method = u16(cd, q + 10);
      var compSize = u32(cd, q + 20);
      var usize = u32(cd, q + 24);
      var nameLen = u16(cd, q + 28);
      var extraLen = u16(cd, q + 30);
      var commentLen = u16(cd, q + 32);
      var diskStart = u16(cd, q + 34);
      var offset = u32(cd, q + 42);
      if (compSize === 0xFFFFFFFF || usize === 0xFFFFFFFF || offset === 0xFFFFFFFF || diskStart === 0xFFFF) fail('zip64');
      if (diskStart !== 0) fail('multi_disk');
      if (nameLen > MAX_NAME) fail('damaged');
      var next = q + 46 + nameLen + extraLen + commentLen;
      if (next > cd.byteLength) fail('damaged');
      if (offset >= endAbs) fail('damaged');
      entries.push({
        name: names.decode(bytes.subarray(q + 46, q + 46 + nameLen)),
        method: method, flags: flags, compSize: compSize, size: usize, offset: offset
      });
      q = next;
    }
    return entries;
  }

  async function listEntries(blob) {
    try {
      return { entries: await entriesOf(blob) };
    } catch (e) {
      return { error: codeOf(e) };
    }
  }

  // ---------------------------------------------------------------------------
  // Streaming one range: stored or deflated, decoded as UTF-8, capped
  // ---------------------------------------------------------------------------
  function rechunk(step, count) {
    return new TransformStream({
      transform: function (chunk, controller) {
        count.input += chunk.length;
        if (count.input > count.output + INPUT_SLACK) throw new Error('too much input for the text it gives');
        for (var i = 0; i < chunk.length; i += step) controller.enqueue(chunk.subarray(i, Math.min(i + step, chunk.length)));
      }
    });
  }

  // A stream over a Blob range. Blob.stream() where it exists; otherwise 1 MiB slices, one at a time.
  function sourceStream(part) {
    if (typeof part.stream === 'function') return part.stream();
    var pos = 0;
    return new ReadableStream({
      pull: function (controller) {
        if (pos >= part.size) { controller.close(); return undefined; }
        var end = Math.min(pos + MIB, part.size);
        var piece = part.slice(pos, end);
        pos = end;
        return piece.arrayBuffer().then(function (b) { controller.enqueue(new Uint8Array(b)); });
      }
    });
  }

  async function pump(part, inflate, declared, opts) {
    var cap = typeof opts.maxBytes === 'number' && opts.maxBytes >= 0 ? Math.floor(opts.maxBytes) : textCap();
    var limit = Math.min(declared, cap);
    var count = { input: 0, output: 0 };
    var stream = sourceStream(part);
    if (inflate) stream = stream.pipeThrough(rechunk(INFLATE_STEP, count)).pipeThrough(new DecompressionStream('deflate-raw'));
    var reader = stream.getReader();
    var decoder = new TextDecoder('utf-8'); // not fatal: a broken byte becomes U+FFFD, the scanner is defensive anyway
    var out = 0;
    var nextYield = MIB;
    var lastProgress = -Infinity;
    try {
      while (out < limit) {
        var step = await reader.read();
        if (step.done) break;
        var chunk = step.value;
        if (!(chunk instanceof Uint8Array)) chunk = new Uint8Array(chunk);
        if (chunk.length > limit - out) chunk = chunk.subarray(0, limit - out);
        out += chunk.length;
        count.output = out;
        if (chunk.length && opts.onText) {
          var s = decoder.decode(chunk, { stream: true });
          if (s) callback(opts.onText, s);
        }
        if (out >= nextYield) {
          nextYield = (Math.floor(out / MIB) + 1) * MIB;
          var t = now();
          if (opts.onProgress && t - lastProgress >= 1000) {
            lastProgress = t;
            callback(opts.onProgress, out);
          }
          await yieldNow();
        }
      }
      var hit = out >= limit;
      if (hit) {
        // Stops the inflater and the file read: a bomb or a lying size costs no more than the cap
        try { await reader.cancel(); } catch (e) { /* already closed */ }
      }
      var rest = decoder.decode();
      if (rest && opts.onText) callback(opts.onText, rest);
      return { bytes: out, truncated: hit && cap < declared };
    } catch (e) {
      try { await reader.cancel(); } catch (e2) { /* already errored */ }
      if (e instanceof CallbackError) throw e;
      return { error: 'damaged' };
    } finally {
      try { reader.releaseLock(); } catch (e) { /* nothing pending */ }
    }
  }

  // Throws CallbackError when onText/onProgress throws; streamEntry and readBugreport unwrap it
  async function streamEntryInner(blob, entry, opts) {
    opts = opts || {};
    if (!entry || !isSize(entry.offset) || !isSize(entry.compSize) || !isSize(entry.size) ||
      entry.offset + 30 > blob.size || entry.offset + entry.compSize > blob.size) return { error: 'damaged' };
    if (entry.flags & 0x41) return { error: 'encrypted' };
    if (entry.method !== 0 && entry.method !== 8) return { error: 'unsupported_method' };
    if (entry.method === 8 && !supportsDeflate()) return { error: 'no_deflate' };
    try {
      var lh = await readRange(blob, entry.offset, Math.min(blob.size, entry.offset + 30));
      if (u32(lh, 0) !== SIG_LOCAL) fail('damaged');
      // Sizes come from the central directory; the local header gives only where the data starts
      var start = entry.offset + 30 + u16(lh, 26) + u16(lh, 28);
      var end = start + entry.compSize;
      if (end > blob.size) fail('damaged');
      var declared = entry.method === 0 ? Math.min(entry.size, entry.compSize) : entry.size;
      return await pump(blob.slice(start, end), entry.method === 8, declared, opts);
    } catch (e) {
      if (e instanceof CallbackError) throw e;
      return { error: codeOf(e) };
    }
  }

  async function streamEntry(blob, entry, opts) {
    try {
      return await streamEntryInner(blob, entry, opts);
    } catch (e) {
      if (e instanceof CallbackError) throw e.error;
      return { error: codeOf(e) };
    }
  }

  // ---------------------------------------------------------------------------
  // Choosing the bug report's main text
  // ---------------------------------------------------------------------------
  async function findMainEntry(blob, entries) {
    var list = Array.isArray(entries) ? entries : [];
    var byName = Object.create(null);
    list.forEach(function (e) { if (e && typeof e.name === 'string' && !(e.name in byName)) byName[e.name] = e; });
    var opened = [];
    var me = byName['main_entry.txt'];
    if (me && (me.method === 0 || me.method === 8) && !(me.flags & 0x41) && me.size <= MAIN_ENTRY_MAX && me.compSize <= MAIN_ENTRY_MAX * 2) {
      opened.push(me.name);
      var text = '';
      var r = await streamEntry(blob, me, { maxBytes: MAIN_ENTRY_MAX, onText: function (s) { text += s; } });
      if (!r.error) {
        var want = text.trim();
        if (isMainName(want) && byName[want]) return { entry: byName[want], opened: opened };
      }
    }
    var best = null;
    list.forEach(function (e) {
      if (e && typeof e.name === 'string' && isMainName(e.name) && (best === null || e.size > best.size)) best = e;
    });
    return best ? { entry: best, opened: opened } : { error: 'no_main' };
  }

  // ---------------------------------------------------------------------------
  // A chosen file: a bug report zip, or its main text already unzipped
  // ---------------------------------------------------------------------------
  async function readBugreport(file, opts) {
    opts = opts || {};
    var o = {
      maxBytes: typeof opts.maxBytes === 'number' && opts.maxBytes >= 0 ? opts.maxBytes : textCap(),
      onText: opts.onText, onProgress: opts.onProgress
    };
    try {
      if (!file || typeof file.size !== 'number' || typeof file.slice !== 'function') return { error: 'not_bugreport' };
      if (file.size === 0) return { error: 'empty' };
      var head = await readRange(file, 0, Math.min(file.size, 4));
      if (isZipStart(head)) {
        var list = await listEntries(file);
        if (list.error) return { error: list.error === 'not_zip' ? 'damaged' : list.error }; // it does start like a zip
        var main = await findMainEntry(file, list.entries);
        if (main.error) return { error: main.error };
        var r = await streamEntryInner(file, main.entry, o);
        if (r.error) return { error: r.error };
        return { source: 'zip', bytes: r.bytes, truncated: r.truncated, opened: main.opened.concat([main.entry.name]) };
      }
      var probe = await readRange(file, 0, Math.min(file.size, TEXT_PROBE));
      var start = new TextDecoder('utf-8').decode(new Uint8Array(probe.buffer, probe.byteOffset, probe.byteLength));
      if (start.indexOf('== dumpstate:') < 0) return { error: 'not_bugreport' };
      var t = await pump(file, false, file.size, o);
      if (t.error) return { error: t.error };
      return { source: 'text', bytes: t.bytes, truncated: t.truncated, opened: [] };
    } catch (e) {
      if (e instanceof CallbackError) throw e.error;
      return { error: codeOf(e) };
    }
  }

  window.PCZip = {
    TAIL_MAX: TAIL_MAX, MAX_CD_BYTES: MAX_CD_BYTES, MAX_ENTRIES: MAX_ENTRIES, MAIN_ENTRY_MAX: MAIN_ENTRY_MAX,
    supportsDeflate: supportsDeflate, listEntries: listEntries, findMainEntry: findMainEntry,
    streamEntry: streamEntry, readBugreport: readBugreport
  };
})();
