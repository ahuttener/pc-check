#!/usr/bin/env node
// Deterministic ZIP generator for the Android bug-report tests (Node built-ins only).
// No clock, no randomness: the same input always gives the same bytes.
//   node tests/tools/make-android-zips.mjs <outdir>     write every zip (manual tests; never inside the repo)
//   node tests/tools/make-android-zips.mjs --self-check build twice, compare, verify CRCs and inflate
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const DOS_TIME = 43458; // 21:14:04
const DOS_DATE = 23889; // 2026-10-17

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}

function toBuf(d) {
  return Buffer.isBuffer(d) ? d : Buffer.from(d, 'utf8');
}

/**
 * entries: [{name, data, method (0|8), descriptor?, localExtra?, flags?, declaredSize?}] in the given order.
 * opts: {comment?, eocd?: {diskNumber, cdDisk, entriesOnDisk, totalEntries, cdSize, cdOffset}, zip64Locator?, truncateAt?, level?}
 */
export function buildZip(entries, opts = {}) {
  const level = opts.level === undefined ? 9 : opts.level;
  const parts = [];
  const central = [];
  let offset = 0;
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const raw = toBuf(e.data);
    const crc = crc32(raw);
    const stored = e.method === 8 ? zlib.deflateRawSync(raw, { level }) : raw;
    const flags = ((e.flags || 0) | (e.descriptor ? 8 : 0)) & 0xFFFF;
    const extra = e.localExtra || Buffer.alloc(0);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034B50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(flags, 6);
    lh.writeUInt16LE(e.method, 8);
    lh.writeUInt16LE(DOS_TIME, 10);
    lh.writeUInt16LE(DOS_DATE, 12);
    lh.writeUInt32LE(e.descriptor ? 0 : crc, 14);
    lh.writeUInt32LE(e.descriptor ? 0 : stored.length, 18);
    lh.writeUInt32LE(e.descriptor ? 0 : raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(extra.length, 28);
    parts.push(lh, name, extra, stored);
    let written = lh.length + name.length + extra.length + stored.length;
    if (e.descriptor) {
      const dd = Buffer.alloc(16);
      dd.writeUInt32LE(0x08074B50, 0);
      dd.writeUInt32LE(crc, 4);
      dd.writeUInt32LE(stored.length, 8);
      dd.writeUInt32LE(raw.length, 12);
      parts.push(dd);
      written += dd.length;
    }
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014B50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(flags, 8);
    ch.writeUInt16LE(e.method, 10);
    ch.writeUInt16LE(DOS_TIME, 12);
    ch.writeUInt16LE(DOS_DATE, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(stored.length, 20);
    ch.writeUInt32LE(e.declaredSize === undefined ? raw.length : e.declaredSize, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, name);
    offset += written;
  }
  const cd = Buffer.concat(central);
  const comment = Buffer.from(opts.comment || '', 'latin1');
  const o = opts.eocd || {};
  const pick = (v, d) => (v === undefined ? d : v);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054B50, 0);
  eocd.writeUInt16LE(pick(o.diskNumber, 0), 4);
  eocd.writeUInt16LE(pick(o.cdDisk, 0), 6);
  eocd.writeUInt16LE(pick(o.entriesOnDisk, entries.length), 8);
  eocd.writeUInt16LE(pick(o.totalEntries, entries.length), 10);
  eocd.writeUInt32LE(pick(o.cdSize, cd.length), 12);
  eocd.writeUInt32LE(pick(o.cdOffset, offset), 16);
  eocd.writeUInt16LE(comment.length, 20);
  const out = [...parts, cd];
  if (opts.zip64Locator) {
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064B50, 0);
    loc.writeUInt32LE(0, 4);
    loc.writeUInt32LE(offset + cd.length, 8);
    loc.writeUInt32LE(1, 16);
    out.push(loc);
  }
  out.push(eocd, comment);
  const all = Buffer.concat(out);
  return opts.truncateAt === undefined ? all : all.subarray(0, opts.truncateAt);
}

// The 1x1 PNG used elsewhere in the tests (67 bytes).
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');

export const MAIN_A = 'bugreport-shiba-BP3A.250905.014-2026-10-17-21-14-05.txt';
export const MAIN_B = 'bugreport-a51nsxx-TP1A.220624.014-2026-10-16-19-40-12.txt';
export const MAIN_C = 'bugreport-examplex1-AP4A.250105.002-2026-10-17-07-00-00.txt';

export function androidZips(fixturesDir, level = 9) {
  const rd = (n) => fs.readFileSync(path.join(fixturesDir, n));
  const textA = rd('bugreport-a.txt');
  const textB = rd('bugreport-b.txt');
  const textC = rd('bugreport-c.txt');
  const anrA = rd('anr-a.txt');
  const o = { level };
  const entriesC = () => [
    { name: 'main_entry.txt', data: MAIN_C, method: 8 },
    { name: MAIN_C, data: textC, method: 8 },
  ];
  const setA = buildZip([
    { name: 'main_entry.txt', data: MAIN_A, method: 0 },
    { name: 'version.txt', data: '2.0', method: 0 },
    { name: MAIN_A, data: textA, method: 8, descriptor: true },
    { name: 'FS/data/anr/anr_2026-10-16-12-30-44-019', data: anrA, method: 8 },
    { name: 'screenshot.png', data: PNG, method: 0 },
  ], o);
  // Bomb: A's lines up to and including the Dumpstate info line, then 64 MiB of newlines.
  const lines = textA.toString('utf8').split('\n');
  const upTo = lines.findIndex((l) => l.startsWith('Dumpstate info:'));
  const head = Buffer.from(lines.slice(0, upTo + 1).join('\n') + '\n', 'utf8');
  const bombText = Buffer.concat([head, Buffer.alloc(67108864, 10)]);
  const fakeEocd = Buffer.alloc(22);
  fakeEocd.writeUInt32LE(0x06054B50, 0);
  fakeEocd.writeUInt16LE(1, 8);
  fakeEocd.writeUInt16LE(1, 10);
  fakeEocd.writeUInt32LE(46, 12);
  fakeEocd.writeUInt32LE(0, 16);
  const comment = Buffer.concat([fakeEocd, Buffer.alloc(18, 0x41)]).toString('latin1');
  return {
    'set-a.zip': setA,
    'set-b.zip': buildZip([
      { name: 'version.txt', data: '2.0', method: 0 },
      { name: 'FS/bugreport-decoy.txt', data: 'decoy', method: 0 },
      { name: MAIN_B, data: textB, method: 0, localExtra: Buffer.alloc(6) },
    ], o),
    'set-c.zip': buildZip(entriesC(), o),
    'encrypted.zip': buildZip([{ name: MAIN_A, data: textA, method: 8, flags: 1 }], o),
    'bzip2.zip': buildZip([{ name: MAIN_A, data: textA, method: 12 }], o),
    'zip64.zip': buildZip(entriesC(), { ...o, eocd: { totalEntries: 0xFFFF, entriesOnDisk: 0xFFFF }, zip64Locator: true }),
    'multidisk.zip': buildZip(entriesC(), { ...o, eocd: { diskNumber: 1 } }),
    'truncated.zip': setA.subarray(0, Math.floor(setA.length / 2)),
    'cd-too-big.zip': buildZip(entriesC(), { ...o, eocd: { cdSize: 9437184, totalEntries: 60000 } }),
    'eocd-in-comment.zip': buildZip(entriesC(), { ...o, comment }),
    'no-main.zip': buildZip([
      { name: 'version.txt', data: '2.0', method: 0 },
      { name: 'screenshot.png', data: PNG, method: 0 },
    ], o),
    'traversal.zip': buildZip([
      { name: '../bugreport-evil.txt', data: textA, method: 8 },
      { name: 'FS/../bugreport-x.txt', data: textA, method: 8 },
    ], o),
    'empty.zip': buildZip([], o),
    'liar.zip': buildZip([
      { name: 'main_entry.txt', data: MAIN_A, method: 8 },
      { name: MAIN_A, data: textA, method: 8, declaredSize: 1000 },
    ], o),
    'bomb.zip': buildZip([
      { name: 'main_entry.txt', data: MAIN_A, method: 8 },
      { name: MAIN_A, data: bombText, method: 8, descriptor: true },
    ], o),
  };
}

// Reads a plain zip (no comment, no ZIP64) back for the self-check: [{name, method, crc, csize, data}].
function readBack(buf) {
  const e = buf.length - 22;
  if (e < 0 || buf.readUInt32LE(e) !== 0x06054B50) return null;
  const total = buf.readUInt16LE(e + 10);
  if (total === 0xFFFF || buf.readUInt32LE(e + 12) > buf.length) return null;
  let p = buf.readUInt32LE(e + 16);
  const out = [];
  for (let i = 0; i < total; i++) {
    if (buf.readUInt32LE(p) !== 0x02014B50) return null;
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const nlen = buf.readUInt16LE(p + 28);
    const lho = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    out.push({ name, method, crc, data: buf.subarray(start, start + csize) });
    p += 46 + nlen;
  }
  return out;
}

function selfCheck(fixturesDir) {
  let bad = 0;
  const fail = (m) => { bad++; console.error('FAIL: ' + m); };
  const first = androidZips(fixturesDir);
  const second = androidZips(fixturesDir, 9);
  const names = Object.keys(first);
  for (const n of names) {
    if (!second[n] || !first[n].equals(second[n])) fail(n + ' differs between two builds');
  }
  const zcrc = typeof zlib.crc32 === 'function' ? (b) => zlib.crc32(b) >>> 0 : crc32;
  const textA = fs.readFileSync(path.join(fixturesDir, 'bugreport-a.txt'));
  const textC = fs.readFileSync(path.join(fixturesDir, 'bugreport-c.txt'));
  let checked = 0;
  for (const n of names) {
    const entries = readBack(first[n]);
    if (!entries) continue;
    for (const en of entries) {
      let plain = en.data;
      if (en.method === 8) plain = zlib.inflateRawSync(en.data);
      if (zcrc(plain) !== en.crc) fail(n + ' ' + en.name + ' CRC mismatch');
      checked++;
      if (n === 'set-a.zip' && en.name === MAIN_A && !plain.equals(textA)) fail('set-a main text differs from the fixture');
      if (n === 'set-c.zip' && en.name === MAIN_C && !plain.equals(textC)) fail('set-c main text differs from the fixture');
    }
  }
  if (!bad) console.log('make-android-zips self-check: ' + names.length + ' zips identical on rebuild, ' + checked + ' entries verified');
  return bad ? 1 : 0;
}

const here = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === here) {
  const fixturesDir = path.join(path.dirname(here), '..', 'fixtures', 'sys', 'android');
  const arg = process.argv[2];
  if (arg === '--self-check') {
    process.exit(selfCheck(fixturesDir));
  } else if (arg) {
    fs.mkdirSync(arg, { recursive: true });
    const zips = androidZips(fixturesDir);
    for (const n of Object.keys(zips)) fs.writeFileSync(path.join(arg, n), zips[n]);
    console.log('wrote ' + Object.keys(zips).length + ' zips to ' + arg);
  } else {
    console.error('usage: make-android-zips.mjs <outdir> | --self-check');
    process.exit(2);
  }
}
