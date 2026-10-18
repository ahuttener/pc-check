// End-to-end tests with Playwright. Every outside service is simulated with page.route.
// Run from tests/: node e2e/run.mjs   (starts php -S on 127.0.0.1:$BSC_PORT, default 8765, serving the project folder)
import { chromium, webkit, devices } from 'playwright';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');
const shots = path.join(here, 'screenshots');
fs.mkdirSync(shots, { recursive: true });
const PORT = process.env.BSC_PORT || '8765';
const BASE = 'http://127.0.0.1:' + PORT + '/';

let passed = 0;
let failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('  ok  ' + name); }
  else { failed++; console.log('  FAIL ' + name + (extra !== undefined ? '  -> ' + JSON.stringify(extra) : '')); }
}

// explain.php must never reach the paid upstream from tests (BSC_EXPLAIN_CONFIG is honoured by php -S only).
const NO_CONFIG = path.join(root, 'tests', 'no-such-grcaudit-config.php');
if (fs.existsSync(NO_CONFIG)) throw new Error('Refusing to run: ' + NO_CONFIG + ' exists');
const php = spawn('php', ['-S', '127.0.0.1:' + PORT + '', '-t', root], { stdio: 'ignore', env: Object.assign({}, process.env, { BSC_EXPLAIN_CONFIG: NO_CONFIG }) });
await new Promise((r) => setTimeout(r, 800));

const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64');
const TRACE = 'fl=1\nh=one.one.one.one\nip=203.0.113.7\nts=1\nvisit_scheme=https\nuag=x\ncolo=DUB\nsliver=none\nhttp=http/2\nloc=IE\ntls=TLSv1.3\nsni=encrypted\nwarp=off\ngateway=off\nrbi=off\nkex=X25519MLKEM768\n';
// "password" = SHA-1 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8; padding lines end in :0
const RANGE = '003D68EB55068C33ACE09247EE4C639306B:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:12345\r\n0123456789ABCDEF0123456789ABCDEF012:0\r\n';

const browser = await chromium.launch();
const major = parseInt(browser.version(), 10);
const fullVersion = browser.version();
const VERSIONS = {
  chrome: Object.fromEntries(['win', 'mac', 'linux', 'android'].map((p) => [p, { version: fullVersion, major }])),
  firefox: { latest: '158.0', latest_major: 158, esr: '153.5.0', esr_major: 153 },
  updated: '2026-10-17T18:00:00Z'
};
const DNS = { servers: [{ ip: '8.8.8.8', country: 'US', country_name: 'United States', asn: 'Google LLC' }], conclusion: 'DNS is not leaking.', conclusion_code: 'no_leak' };

// mode: 'ok' | 'fail' | 'rate'
// WebRTC is stubbed in every page: real STUN traffic would leave the machine during tests.
// window.__rtcCandidates (set by an extra init script) overrides the candidates; null = WebRTC unavailable.
const RTC_STUB = `(() => {
  const list = () => (window.__rtcCandidates !== undefined ? window.__rtcCandidates : ['candidate:1 1 udp 1 203.0.113.7 5000 typ srflx raddr 0.0.0.0 rport 0']);
  if (list() === null) { delete window.RTCPeerConnection; window.RTCPeerConnection = undefined; return; }
  window.RTCPeerConnection = function () {
    const self = this;
    this.onicecandidate = null;
    this.createDataChannel = () => ({ close() {} });
    this.createOffer = () => Promise.resolve({ type: 'offer', sdp: 'v=0' });
    this.setLocalDescription = () => {
      setTimeout(() => {
        (list() || []).forEach((c) => self.onicecandidate && self.onicecandidate({ candidate: { candidate: c } }));
        if (self.onicecandidate) self.onicecandidate({ candidate: null });
      }, 50);
      return Promise.resolve();
    };
    this.close = () => {};
  };
})();`;

async function newPage(mode, opts = {}, engine = browser) {
  const { initScript, speed = 'ok', colo = 'DUB', ...contextOpts } = opts;
  const context = await engine.newContext(Object.assign({ locale: 'en-IE' }, contextOpts));
  if (initScript) await context.addInitScript(initScript);
  await context.addInitScript(RTC_STUB);
  const page = await context.newPage();
  const seen = { external: [], hibp: [], errors: [], consoleErrors: [], speed: [] };
  page.on('pageerror', (e) => seen.errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') seen.consoleErrors.push(m.text()); });

  // Registered first: Playwright tries the most recent route first, so the mocks below win.
  // Anything else that tries to leave the machine is recorded and blocked.
  await page.route((url) => !url.href.startsWith(BASE), (r) => { seen.external.push(r.request().url()); return r.abort(); });

  await page.route(/one\.one\.one\.one\/cdn-cgi\/trace|www\.cloudflare\.com\/cdn-cgi\/trace/, (r) =>
    mode === 'ok' ? r.fulfill({ status: 200, contentType: 'text/plain', body: TRACE }) : r.fulfill({ status: 503, body: 'down' }));
  await page.route(/bash\.ws\//, (r) => r.fulfill({ status: 200, contentType: 'image/png', body: PNG }));
  await page.route(/api\.pwnedpasswords\.com\/range\//, (r) => {
    seen.hibp.push({ url: r.request().url(), headers: r.request().headers() });
    return mode === 'ok' ? r.fulfill({ status: 200, contentType: 'text/plain', headers: { 'Access-Control-Allow-Origin': '*' }, body: RANGE })
      : r.fulfill({ status: 500, body: 'x' });
  });
  await page.route(/\/api\/versions\.php/, (r) =>
    mode === 'ok' ? r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(VERSIONS) })
      : r.fulfill({ status: 502, contentType: 'application/json', body: '{"error":"upstream"}' }));
  await page.route(/\/api\/dnsleak\.php/, (r) => {
    if (mode === 'ok') return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(DNS) });
    if (mode === 'rate') return r.fulfill({ status: 429, contentType: 'application/json', headers: { 'Retry-After': '60' }, body: '{"error":"rate_limited"}' });
    return r.fulfill({ status: 502, contentType: 'application/json', body: '{"error":"upstream"}' });
  });

  // Cloudflare speed test: zero-filled bodies after a short delay. Downloads are capped at 1 MB per response to keep the
  // suite fast (the page counts the bytes it actually receives). In-flight __down/__up requests are tracked so tests can
  // prove the streams really run in parallel.
  // speed: 'stall' answers the first 6 big downloads, then never answers again (the window must end the phase);
  // 'down' answers 503; 'slowping' delays pings; 'slow' holds every download/upload for 3 s.
  seen.inflight = { down: 0, up: 0 }; seen.maxDown = 0; seen.maxUp = 0; seen.downReq = 0; seen.upReq = 0; seen.upBytes = 0;
  let bigAnswered = 0;
  await page.route(/speed\.cloudflare\.com\//, async (r) => {
    const url = r.request().url();
    seen.speed.push(url);
    const headers = { 'Access-Control-Allow-Origin': '*' };
    if (url.includes('/cdn-cgi/trace')) {
      seen.trace = (seen.trace || 0) + 1;
      if (colo === 'fail') return r.fulfill({ status: 503, headers, body: 'down' });
      const c = colo === 'bad' ? '<b>x</b>' : colo;
      return r.fulfill({ status: 200, contentType: 'text/plain', headers, body: 'fl=1\nh=speed.cloudflare.com\nip=203.0.113.9\ncolo=' + c + '\nloc=IE\n' });
    }
    if (r.request().method() === 'OPTIONS') return r.fulfill({ status: 204, headers: Object.assign({ 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'content-type' }, headers) });
    const bytes = parseInt((url.match(/bytes=(\d+)/) || [])[1] || '0', 10);
    const kind = url.includes('__up') ? 'up' : (bytes > 0 ? 'down' : null);
    if (kind) {
      seen[kind + 'Req']++;
      if (kind === 'up') seen.upBytes += (r.request().postDataBuffer() || Buffer.alloc(0)).length;
      seen.inflight[kind]++;
      if (kind === 'down') seen.maxDown = Math.max(seen.maxDown, seen.inflight.down);
      else seen.maxUp = Math.max(seen.maxUp, seen.inflight.up);
    }
    try {
      if (speed === 'stall' && bytes >= 1000000 && ++bigAnswered > 6) return await new Promise(() => {}); // never answered
      if (speed === 'down') return await r.fulfill({ status: 503, headers, body: 'down' });
      // Cloudflare answers 429 (one-hour Retry-After) to big downloads after heavy use from one IP; small ones still work.
      if (speed === 'limit' && bytes >= 10000000) return await r.fulfill({ status: 429, headers: { 'Retry-After': '3574' }, body: 'x' }); // no CORS header, like the real one
      if (speed === 'slowping' && bytes === 0) await new Promise((res) => setTimeout(res, 1500));
      if (speed === 'slow' && kind) await new Promise((res) => setTimeout(res, 3000));
      if (speed === 'empty' && kind === 'down') return await r.fulfill({ status: 200, contentType: 'application/octet-stream', headers, body: '' });
      await new Promise((res) => setTimeout(res, kind ? 60 : 20)); // long enough for every stream to be in flight at once
      return await r.fulfill({ status: 200, contentType: 'application/octet-stream', headers, body: url.includes('__down') ? Buffer.alloc(Math.min(bytes, 1000000)) : '' }).catch(() => {});
    } finally {
      if (kind) seen.inflight[kind]--;
    }
  });

  await page.goto(BASE);
  return { page, context, seen };
}

const status = (page, id) => page.getAttribute('#check-' + id, 'data-status');
async function runChecks(page) {
  await page.click('#run');
  await page.waitForFunction(() => ['browser', 'connection', 'dns'].every((id) => {
    const s = document.getElementById('check-' + id).getAttribute('data-status');
    return s && s !== 'running' && s !== 'idle';
  }), null, { timeout: 30000 });
}

try {
  // 1. Nothing leaves before the click; happy path afterwards
  console.log('Happy path');
  {
    const { page, context, seen } = await newPage('ok');
    await page.waitForTimeout(500);
    check('nothing in ledger before the click', (await page.locator('#ledger-list li').count()) === 0);
    check('no outbound request before the click', seen.hibp.length === 0 && seen.external.length === 0, seen.external);
    await runChecks(page);
    check('browser = ok', (await status(page, 'browser')) === 'ok', await status(page, 'browser'));
    check('connection = ok (TLS 1.3)', (await status(page, 'connection')) === 'ok', await status(page, 'connection'));
    check('dns = ok', (await status(page, 'dns')) === 'ok', await status(page, 'dns'));
    const ledger = await page.locator('#ledger-list').innerText();
    check('ledger lists the trace request', ledger.includes('one.one.one.one'), ledger);
    check('ledger lists the bash.ws probes', ledger.includes('bash.ws'));
    check('ledger lists the local API calls', ledger.includes('127.0.0.1:' + PORT + ''));
    check('no unexpected outbound hosts', seen.external.length === 0, seen.external);
    check('no page errors', seen.errors.length === 0, seen.errors);
    check('no console errors', seen.consoleErrors.length === 0, seen.consoleErrors);

    // 2. Password: k-anonymity
    console.log('Password');
    const before = await page.locator('#ledger-list li').count();
    await page.fill('#pw', 'password');
    await page.click('#pw-submit');
    await page.waitForFunction(() => {
      const s = document.getElementById('check-password').getAttribute('data-status');
      return s === 'risk' || s === 'ok' || s === 'error';
    });
    check('only /range/5BAA6 was requested', seen.hibp.length >= 1 && seen.hibp.every((h) => h.url.endsWith('/range/5BAA6')), seen.hibp.map((h) => h.url));
    check('Add-Padding header sent', seen.hibp[0] && seen.hibp[0].headers['add-padding'] === 'true');
    check('password = risk', (await status(page, 'password')) === 'risk', await status(page, 'password'));
    const verdict = await page.locator('#check-password [data-role="verdict"]').innerText();
    check('verdict shows the breach count', verdict.includes('12,345'), verdict);
    check('input cleared after submit', (await page.inputValue('#pw')) === '');
    const html = await page.content();
    check('full hash never in the page', !html.includes('1E4C9B93F3F0682250B6CF8331B7EE68FD8'));
    check('plain password never in the page', !/value="password"/.test(html));
    check('prefix shown', (await page.locator('[data-role="hash-out"]').innerText()).includes('5BAA6'));
    check('ledger got one more entry for HIBP', (await page.locator('#ledger-list li').count()) === before + 1);
    check('ledger shows the 5-char prefix only', (await page.locator('#ledger-list').innerText()).includes('5BAA6'));

    // 3. English only: no language switch, no Portuguese left in the page
    console.log('Language');
    check('html lang = en', (await page.getAttribute('html', 'lang')) === 'en');
    check('no PT/EN switch', (await page.locator('.lang').count()) === 0);
    for (const f of ['assets/app.js', 'assets/sysreport.js', 'index.html']) {
      const src = fs.readFileSync(path.join(here, '..', '..', f), 'utf8');
      const hit = src.match(/.{0,40}(?:[\u00e3\u00f5\u00e7\u00c3\u00d5\u00c7]|Portugu|pt-BR|CAPACIDADE|Resumo do Sistema|Dispositivo|\bpt:).{0,40}/);
      check('no Portuguese left in ' + f, !hit, hit && hit[0]);
    }
    check('ledger in English', (await page.locator('#ledger').innerText()).includes('Sent'));
    const text = await page.locator('body').innerText();
    check('no Portuguese text on screen', !/[\u00e3\u00f5\u00e7\u00e2\u00ea\u00f4]|N\u00e3o |Verificar|senha|aparelho/i.test(text), (text.match(/.{0,30}(?:[\u00e3\u00f5\u00e7\u00e2\u00ea\u00f4]|N\u00e3o |Verificar|senha|aparelho).{0,30}/i) || [])[0]);
    await context.close();
  }

  // 3b. Fairer browser verdict while an update is still rolling out (pure function, fixed clock)
  console.log('Browser verdict');
  {
    const { page, context } = await newPage('ok');
    const cases = await page.evaluate(() => {
      const now = new Date('2026-10-17T12:00:00Z');
      const daysAgo = (d) => new Date(now.getTime() - d * 86400000).toISOString().replace(/\.\d+Z$/, 'Z');
      const chrome = (version) => ({ family: 'chromium', name: 'Chrome', version, engineMajor: parseInt(version, 10), platform: 'win' });
      const v = (released) => ({ chrome: { win: { version: '156.0.8078.36', major: 156, released } } });
      const ev = window.__bsc.evaluateBrowser;
      const pick = (r) => r.status + ':' + r.verdict[0];
      const ff = { family: 'firefox', name: 'Firefox', version: '157.0', engineMajor: 157 };
      return {
        oneBehindFresh: pick(ev(chrome('155.0.8059.82'), v(daysAgo(3)), now)),
        oneBehindOld: pick(ev(chrome('155.0.8059.82'), v(daysAgo(20)), now)),
        twoBehindFresh: pick(ev(chrome('154.0.8037.100'), v(daysAgo(3)), now)),
        noDate: pick(ev(chrome('155.0.8059.82'), v(undefined), now)),
        patchFresh: pick(ev(chrome('156.0.8078.20'), v(daysAgo(3)), now)),
        firefoxFresh: pick(ev(ff, { firefox: { latest: '158.0', latest_major: 158, esr: '153.5.0', esr_major: 153, released: daysAgo(3).slice(0, 10) } }, now))
      };
    });
    check('one major behind stays warn even if the release is fresh (rollout dates are unreliable for majors)', cases.oneBehindFresh === 'warn:browserBehind', cases.oneBehindFresh);
    check('one major behind, released 20 days ago -> warn', cases.oneBehindOld === 'warn:browserBehind', cases.oneBehindOld);
    check('two majors behind stays risk even if fresh', cases.twoBehindFresh === 'risk:browserOld', cases.twoBehindFresh);
    check('no release date -> old verdict (warn)', cases.noDate === 'warn:browserBehind', cases.noDate);
    check('pending patch, fresh -> info rolling', cases.patchFresh === 'info:browserRolling', cases.patchFresh);
    check('Firefox one major behind stays warn even if a dot release is fresh', cases.firefoxFresh === 'warn:browserBehind', cases.firefoxFresh);
    await context.close();
  }

  // 3c. WebRTC leak: pure verdicts, then the flow with the stub
  console.log('WebRTC leak');
  {
    const { page, context, seen } = await newPage('ok');
    const r = await page.evaluate(() => {
      const ev = window.__bsc.evaluateWebRtc;
      const pick = (x) => x.status + ':' + x.verdict[0];
      return {
        unsupported: pick(ev({ supported: false, srflx: [], host: [] }, '203.0.113.7')),
        same: pick(ev({ supported: true, srflx: ['203.0.113.7'], host: [] }, '203.0.113.7')),
        leak: pick(ev({ supported: true, srflx: ['198.51.100.9'], host: [] }, '203.0.113.7')),
        families: pick(ev({ supported: true, srflx: ['203.0.113.7'], host: [] }, '2001:db8::1')),
        dual: pick(ev({ supported: true, srflx: ['198.51.100.9', '2001:db8::1'], host: [] }, '2001:db8::1')),
        local: pick(ev({ supported: true, srflx: ['203.0.113.7'], host: ['192.168.1.20'] }, '203.0.113.7')),
        noTrace: ev({ supported: true, srflx: ['198.51.100.9'], host: [] }, null)
      };
    });
    check('webrtc unsupported -> ok', r.unsupported.startsWith('ok:'), r.unsupported);
    check('webrtc same IP -> ok', r.same.startsWith('ok:'), r.same);
    check('webrtc different IP same family -> risk', r.leak.startsWith('risk:'), r.leak);
    check('webrtc different families -> ok, but says they were not compared', r.families === 'ok:webrtcOtherFamily', r.families);
    check('webrtc dual-stack, matching v6 -> ok', r.dual.startsWith('ok:'), r.dual);
    check('webrtc private host address -> warn', r.local.startsWith('warn:'), r.local);
    check('webrtc no trace -> info webrtcNoCompare', r.noTrace.status === 'info' && r.noTrace.verdict[0] === 'webrtcNoCompare', r.noTrace);
    check('webrtc no trace still lists the addresses', JSON.stringify(r.noTrace.facts).includes('198.51.100.9'));

    await runChecks(page);
    check('webrtc card = ok in the flow', (await status(page, 'webrtc')) === 'ok', await status(page, 'webrtc'));
    check('ledger lists stun.cloudflare.com', (await page.locator('#ledger-list').innerText()).includes('stun.cloudflare.com'));
    check('webrtc: no page errors', seen.errors.length === 0, seen.errors);
    await context.close();
  }
  {
    const { page, context } = await newPage('ok', { initScript: 'window.__rtcCandidates = ["candidate:1 1 udp 1 198.51.100.9 5000 typ srflx raddr 0.0.0.0 rport 0"];' });
    await runChecks(page);
    check('webrtc leak flow -> risk', (await status(page, 'webrtc')) === 'risk', await status(page, 'webrtc'));
    await context.close();
  }

  // 3d. Trackability (local only)
  console.log('Trackability');
  {
    const { page, context, seen } = await newPage('ok');
    const r = await page.evaluate(() => {
      const ev = window.__bsc.evaluateTracking;
      const none = { gpc: false, dnt: false, blocker: false, canvasRandomised: false, webkitItp: false };
      const st = (p) => ev({}, Object.assign({}, none, p)).status;
      return {
        zero: st({}), gpc: st({ gpc: true }), two: st({ gpc: true, blocker: true }),
        dntOnly: st({ dnt: true }), itpBlocker: st({ webkitItp: true, blocker: true }),
        saysEstimate: JSON.stringify(ev({}, none))
      };
    });
    check('tracking: 0 protections -> warn', r.zero === 'warn', r.zero);
    check('tracking: GPC only -> info', r.gpc === 'info', r.gpc);
    check('tracking: GPC + blocker -> ok', r.two === 'ok', r.two);
    check('tracking: DNT alone does not count -> warn', r.dntOnly === 'warn', r.dntOnly);
    check('tracking: WebKit ITP + blocker -> ok', r.itpBlocker === 'ok', r.itpBlocker);

    await runChecks(page);
    const s1 = await status(page, 'tracking');
    check('tracking card has a result', ['ok', 'info', 'warn'].includes(s1), s1);
    const facts = await page.locator('#check-tracking [data-role="facts"]').innerText();
    const tv = await page.locator('#check-tracking [data-role="verdict"]').innerText();
    check('tracking: verdict on screen says it is an estimate', /estimate/i.test(tv), tv);
    check('tracking facts show CPU cores and time zone', facts.includes('CPU cores') && facts.includes('Time zone'), facts);
    const ledger1 = await page.locator('#ledger-list li').count();
    check('tracking: no page errors', seen.errors.length === 0, seen.errors);
    await context.close();

    const g = await newPage('ok', { initScript: 'Object.defineProperty(Navigator.prototype, "globalPrivacyControl", { get: () => true });' });
    await runChecks(g.page);
    const gFacts = await g.page.locator('#check-tracking [data-role="facts"]').innerText();
    check('tracking: GPC on is reported', /Global Privacy Control\s*On/i.test(gFacts), gFacts);
    check('tracking sends nothing (same ledger size with or without GPC)', (await g.page.locator('#ledger-list li').count()) === ledger1);
    await g.context.close();
  }

  // 3e. Speed test (own GO button, Cloudflare mocked)
  console.log('Speed test');
  {
    const { page, context } = await newPage('ok');
    const r = await page.evaluate(() => {
      const ev = window.__bsc.evaluateSpeed;
      return {
        fast: ev({ downMbps: 120, upMbps: 20, pingMs: 15, jitterMs: 2, colo: 'DUB', partial: false }),
        mid: ev({ downMbps: 15, upMbps: 5, pingMs: 20, jitterMs: 2, colo: 'DUB', partial: false }).status,
        slow: ev({ downMbps: 4, upMbps: 1, pingMs: 20, jitterMs: 2, colo: 'DUB', partial: false }).status,
        lag: ev({ downMbps: 120, upMbps: 20, pingMs: 180, jitterMs: 9, colo: 'DUB', partial: false }),
        none: ev({ downMbps: null, upMbps: null, pingMs: null, jitterMs: null, colo: null, partial: true }).status
      };
    });
    check('speed: 120 Mbps -> ok', r.fast.status === 'ok', r.fast.status);
    check('speed: 15 Mbps -> info', r.mid === 'info', r.mid);
    check('speed: 4 Mbps -> warn', r.slow === 'warn', r.slow);
    check('speed: ping 180 ms adds a note', !!r.lag.note && r.lag.note[0] === 'speedPingHigh', r.lag.note);
    check('speed: no samples -> error', r.none === 'error', r.none);

    // Result maths: p90 of 1-second window rates (Cloudflare/Ookla style), with sane fallbacks.
    const m = await page.evaluate(() => {
      const R = window.__bsc.speedRates;
      const steady = [];
      let b = 0;
      for (let t = 0; t <= 8000; t += 200) { steady.push({ t, b }); b += (t < 4000 ? 50e6 : 100e6) / 8 * 0.2; }
      const capped = [{ t: 0, b: 0 }, { t: 200, b: 10e6 }, { t: 400, b: 30e6 }, { t: 600, b: 50e6 }];
      const stall = [{ t: 0, b: 0 }];
      for (let t = 200; t <= 8000; t += 200) stall.push({ t, b: 6e6 });
      const reqs = [];
      for (let k = 0; k < 4; k++) for (let s0 = k * 200; s0 + 800 <= 6000; s0 += 800) reqs.push({ s: s0, e: s0 + 800, b: 2e6 });
      return {
        steady: R.down(steady, 100),
        capped: R.down(capped, 150),
        stall: R.down(stall, 100),
        none: R.down([{ t: 0, b: 0 }, { t: 8000, b: 0 }], null),
        up: R.up(reqs, 6000),
        upFew: R.up([{ s: 0, e: 400, b: 250000 }, { s: 0, e: 500, b: 250000 }], 600),
        upNone: R.up([], 6000)
      };
    });
    check('speed maths: download is the p90 of 1 s windows (50 then 100 Mbps -> ~100)', m.steady.mbps > 95 && m.steady.mbps <= 101 && !m.steady.partial, m.steady);
    check('speed maths: cap-shortened run uses bytes / time after the first byte', Math.abs(m.capped.mbps - 50e6 * 8 / 0.45 / 1e6) < 1 && !m.capped.partial, m.capped);
    check('speed maths: stalled run uses everything and is partial', Math.abs(m.stall.mbps - 6e6 * 8 / 7.9 / 1e6) < 0.5 && m.stall.partial, m.stall);
    check('speed maths: no bytes -> no number', m.none.mbps === null, m.none);
    check('speed maths: upload spreads each request over its own time (4 x 2 MB / 0.8 s -> ~80 Mbps)', m.up > 76 && m.up < 84, m.up);
    check('speed maths: upload with too few windows uses all completions', Math.abs(m.upFew - 500000 * 8 / 0.5 / 1e6) < 0.01, m.upFew);
    check('speed maths: upload with nothing finished -> no number', m.upNone === null, m.upNone);

    await context.close();
  }
  {
    const { page, context, seen } = await newPage('ok');
    await runChecks(page);
    check('Check now never requests speed.cloudflare.com', seen.speed.length === 0, seen.speed);
    check('speed card is idle until GO', (await status(page, 'speed')) === 'idle');
    check('data warning shown', (await page.locator('#check-speed').innerText()).includes('250 MB'));
    await page.click('#speed-go');
    check('speed: GO is disabled while running', await page.locator('#speed-go').isDisabled());
    await page.click('#run'); // Check now still works during the speed test
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
    check('speed: Check now unaffected (DNS done)', (await status(page, 'dns')) === 'ok', await status(page, 'dns'));
    check('speed: result ok with mocked fast link', (await status(page, 'speed')) === 'ok', await status(page, 'speed'));
    const facts = await page.locator('#check-speed [data-role="facts"]').innerText();
    check('speed facts show Mbps, ping and the data centre', facts.includes('Mbps') && facts.includes(' ms') && facts.includes('DUB'), facts);
    check('ledger lists speed.cloudflare.com', (await page.locator('#ledger-list').innerText()).includes('speed.cloudflare.com'));
    check('speed: GO is enabled again', !(await page.locator('#speed-go').isDisabled()));
    check('speed: data centre read once from /cdn-cgi/trace', seen.trace === 1, seen.trace);
    check('speed: download runs 6 parallel streams', seen.maxDown >= 6 && seen.maxDown <= 6, seen.maxDown);
    check('speed: upload runs 4 parallel streams', seen.maxUp >= 4 && seen.maxUp <= 4, seen.maxUp);
    check('speed facts show the connection count', facts.includes('6 down / 4 up'), facts);
    await context.close();
  }
  {
    const { page, context, seen } = await newPage('ok');
    const caps = await page.evaluate(() => ({ down: window.__bsc.speed.downCapBytes, up: window.__bsc.speed.upCapBytes }));
    check('speed: production data caps are 200 MB down / 50 MB up', caps.down === 200e6 && caps.up === 50e6, caps);
    // Lowered caps (test hook): 1 MB mock bodies, so about 12 downloads (+ up to 6 in flight); uploads stop starting
    // new requests once 6 MB are under way (the last one may overshoot by at most one 2 MB body).
    await page.evaluate(() => { window.__bsc.speed.downCapBytes = 12e6; window.__bsc.speed.upCapBytes = 6e6; });
    const t0 = Date.now();
    await page.click('#speed-go');
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
    const took = Date.now() - t0;
    const n = seen.downReq, u = seen.upReq, ub = seen.upBytes;
    await page.waitForTimeout(600);
    check('speed cap: download stops requesting once the cap is reached', n >= 12 && n <= 18 && seen.downReq === n, [n, seen.downReq]);
    check('speed cap: upload stops once the cap is sent', ub >= 6e6 && ub <= 8e6 && seen.upReq === u, [ub, u, seen.upReq]);
    check('speed cap: test ends early instead of running the full windows', took < 8000, took);
    await context.close();
  }
  {
    const { page, context } = await newPage('ok', { speed: 'stall' });
    const t0 = Date.now();
    await page.click('#speed-go');
    await page.waitForFunction(() => document.getElementById('check-speed').getAttribute('data-status') !== 'running' &&
      document.getElementById('check-speed').getAttribute('data-status') !== 'idle', null, { timeout: 25000 });
    const facts = await page.locator('#check-speed [data-role="facts"]').innerText();
    check('speed: stalled download ends with partial result', Date.now() - t0 < 25000 && /Download/.test(facts) && /Mbps/.test(facts), facts);
    await context.close();
  }
  {
    for (const colo of ['bad', 'fail']) {
      const { page, context } = await newPage('ok', { colo });
      await page.click('#speed-go');
      await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
      const facts = await page.locator('#check-speed [data-role="facts"]').innerText();
      check('speed: data centre ' + colo + ' -> no data-centre fact, result still ok', (await status(page, 'speed')) === 'ok' && !/data centre/i.test(facts) && !facts.includes('<b>'), facts);
      await context.close();
    }
  }
  {
    const { page, context, seen } = await newPage('ok', { speed: 'limit' });
    await page.click('#speed-go');
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
    const big = seen.speed.filter((u) => /bytes=25000000/.test(u)).length;
    check('speed: 429 on big downloads -> smaller requests still give a result', (await status(page, 'speed')) === 'ok' && seen.speed.some((u) => /__down\?bytes=1000000\b/.test(u)), await status(page, 'speed'));
    check('speed: after a 429 the big size is not retried per stream', big <= 6, big);
    await context.close();
  }
  {
    const { page, context } = await newPage('ok', { speed: 'down' });
    await page.click('#speed-go');
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 25000 });
    check('speed: failed requests are still in the outbound log', (await page.locator('#ledger-list').innerText()).includes('speed.cloudflare.com'));
    check('speed: all requests failing -> error', (await status(page, 'speed')) === 'error', await status(page, 'speed'));
    await context.close();
  }
  {
    const { page, context, seen } = await newPage('ok');
    await page.click('#speed-go');
    await page.waitForTimeout(150);
    await page.click('#speed-cancel');
    await page.waitForFunction(() => document.getElementById('check-speed').getAttribute('data-status') !== 'running', null, { timeout: 5000 });
    const n = seen.speed.length;
    await page.waitForTimeout(800);
    check('speed: Cancel stops the test', seen.speed.length === n, [n, seen.speed.length]);
    await context.close();
  }
  for (const engineName of ['chromium', 'webkit']) {
    const eng = engineName === 'webkit' ? await webkit.launch() : browser;
    try {
      const { page, context, seen } = await newPage('ok', { speed: 'slow' }, eng);
      await page.click('#speed-go');
      for (let i = 0; i < 100 && seen.downReq < 6; i++) await page.waitForTimeout(100);
      const t0 = Date.now();
      await page.click('#speed-cancel');
      await page.waitForFunction(() => document.getElementById('check-speed').getAttribute('data-status') !== 'running', null, { timeout: 5000 });
      const took = Date.now() - t0;
      const n = seen.speed.length;
      await page.waitForTimeout(1500);
      check('speed (' + engineName + '): Cancel during the parallel download stops at once', took < 1000 && (await status(page, 'speed')) === 'info', [took, await status(page, 'speed')]);
      check('speed (' + engineName + '): Cancel during the parallel download sends nothing more', seen.speed.length === n && seen.downReq >= 6, [n, seen.speed.length, seen.downReq]);
      await context.close();
    } finally {
      if (eng !== browser) await eng.close();
    }
  }
  {
    // A proxy answering 200 with empty bodies must not make the streams spin: empty counts as a failure.
    const { page, context, seen } = await newPage('ok', { speed: 'empty' });
    await page.click('#speed-go');
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
    check('speed: empty 200 bodies are failures, not a fetch storm', seen.downReq <= 30 && (await status(page, 'speed')) === 'error', [seen.downReq, await status(page, 'speed')]);
    await context.close();
  }
  {
    // No streamed body (old engines): small 1 MB requests instead of waiting for 25 MB in one piece.
    const { page, context, seen } = await newPage('ok', { initScript: 'Object.defineProperty(Response.prototype, "body", { configurable: true, get() { return null; } });' });
    await page.click('#speed-go');
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
    const big = seen.speed.filter((u) => /bytes=25000000/.test(u)).length;
    const small = seen.speed.filter((u) => /__down\?bytes=1000000\b/.test(u)).length;
    check('speed: no readable body -> 1 MB requests, still a result', big <= 6 && small > 0 && (await status(page, 'speed')) === 'ok', [big, small, await status(page, 'speed')]);
    await context.close();
  }

  // 4. Every outside service fails: each check shows "Couldn't check", page keeps working
  console.log('Errors');
  {
    const { page, context, seen } = await newPage('fail');
    await runChecks(page);
    for (const id of ['browser', 'connection', 'dns']) {
      check(id + ' = error', (await status(page, id)) === 'error', await status(page, id));
      const pill = await page.locator('#check-' + id + ' [data-role="pill"]').innerText();
      check(id + ' pill says Couldn\'t check', /couldn.t check/i.test(pill), pill);
    }
    await page.fill('#pw', 'password');
    await page.click('#pw-submit');
    await page.waitForFunction(() => document.getElementById('check-password').getAttribute('data-status') === 'error');
    check('password = error', (await status(page, 'password')) === 'error');
    check('no page errors on failure', seen.errors.length === 0, seen.errors);
    await page.click('#run');
    await page.waitForFunction(() => document.getElementById('check-dns').getAttribute('data-status') === 'error', null, { timeout: 30000 });
    check('can run again after failure', true);
    await context.close();
  }

  // 4b. A Portuguese browser still gets English
  {
    const { page, context } = await newPage('ok', { locale: 'pt-BR' });
    check('pt-BR browser gets English', (await page.locator('#run').innerText()) === 'Check now', await page.locator('#run').innerText());
    check('pt-BR browser: html lang en', (await page.getAttribute('html', 'lang')) === 'en');
    await context.close();
  }

  // 5. Rate limit message
  console.log('Rate limit');
  {
    const { page, context } = await newPage('rate');
    await runChecks(page);
    check('dns = error on 429', (await status(page, 'dns')) === 'error');
    const v = await page.locator('#check-dns [data-role="verdict"]').innerText();
    const generic = "The DNS test didn't respond right now. Try again in a moment.";
    check('429 uses its own message', v.length > 0 && v !== generic, v);
    await context.close();
  }

  // 6. Screenshots: light, dark, 375 px; no horizontal scroll; visible keyboard focus
  console.log('Layout');
  for (const v of [
    { name: 'light-1280', scheme: 'light', width: 1280, height: 900 },
    { name: 'dark-1280', scheme: 'dark', width: 1280, height: 900 },
    { name: 'light-375', scheme: 'light', width: 375, height: 812 },
    { name: 'dark-375', scheme: 'dark', width: 375, height: 812 }
  ]) {
    const { page, context } = await newPage('ok', { colorScheme: v.scheme, viewport: { width: v.width, height: v.height } });
    await runChecks(page);
    await page.fill('#pw', 'password');
    await page.click('#pw-submit');
    await page.waitForFunction(() => document.getElementById('check-password').getAttribute('data-status') === 'risk');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(v.name + ': no horizontal scroll', overflow <= 0, overflow);
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    if (v.name === 'dark-1280') check('dark theme applies a dark background', /rgb\((\d+), (\d+), (\d+)\)/.test(bg) && bg.match(/\d+/g).slice(0, 3).every((n) => +n < 80), bg);
    await page.screenshot({ path: path.join(shots, v.name + '.png'), fullPage: true });
    await context.close();
  }
  {
    const { page, context } = await newPage('ok');
    let found = false;
    let detail = null;
    for (let i = 0; i < 20 && !found; i++) {
      await page.keyboard.press('Tab');
      detail = await page.evaluate(() => {
        const el = document.activeElement;
        const cs = getComputedStyle(el);
        return { id: el.id, tag: el.tagName, outline: cs.outlineStyle + ' ' + cs.outlineWidth, shadow: cs.boxShadow };
      });
      if (detail.id === 'run') found = true;
    }
    check('Tab reaches the run button', found, detail);
    check('focus ring visible on the run button', detail && ((detail.outline && !detail.outline.startsWith('none')) || (detail.shadow && detail.shadow !== 'none')), detail);
    await page.screenshot({ path: path.join(shots, 'focus-run.png') });
    await context.close();
  }

  // 6b. Animated gauge
  console.log('Gauge');
  {
    const { page, context } = await newPage('ok');
    const f = await page.evaluate(() => {
      const fr = window.PCGauge && window.PCGauge.fraction;
      return fr ? [fr(0), fr(100), fr(1000), fr(5000), fr(-1), fr(7.5)] : null;
    });
    check('gauge.fraction scale', f && f[0] === 0 && f[1] === 0.5 && f[2] === 1 && f[3] === 1 && f[4] === 0, f);
    check('gauge.fraction is piecewise linear between ticks (7.5 -> 1.5/8)', f && Math.abs(f[5] - 1.5 / 8) < 1e-9, f && f[5]);
    check('gauge SVG is drawn', (await page.locator('#gauge svg').count()) === 1);
    await page.click('#speed-go');
    await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
    const shown = await page.locator('#gauge [data-role="gauge-value"]').textContent();
    check('gauge shows the final download number', /^\d+(\.\d)?$/.test(shown.trim()) && parseFloat(shown) > 0, shown);
    await page.locator('#check-speed').screenshot({ path: path.join(shots, 'speed-desktop.png') });
    await context.close();
  }
  for (const [label, opts, engineName] of [['375 px', { viewport: { width: 375, height: 812 } }, 'chromium'], ['iPhone', devices['iPhone 14'], 'webkit']]) {
    const eng = engineName === 'webkit' ? await webkit.launch() : browser;
    try {
      const { page, context } = await newPage('ok', opts, eng);
      const box = await page.locator('#speed-go').boundingBox();
      check('gauge: fits ' + label + ' — GO is tappable (>= 44 px)', box && box.height >= 44 && box.width >= 44, box);
      await page.click('#speed-go');
      await page.waitForFunction(() => !['running', 'idle'].includes(document.getElementById('check-speed').getAttribute('data-status')), null, { timeout: 40000 });
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      check('gauge: fits ' + label + ' — no horizontal scroll', overflow <= 0, overflow);
      await page.locator('#check-speed').screenshot({ path: path.join(shots, engineName === 'webkit' ? 'speed-iphone.png' : 'speed-375.png') });
      await context.close();
    } finally {
      if (eng !== browser) await eng.close();
    }
  }

  // 6c. PDF report, built in the browser and printed
  console.log('PDF report');
  {
    const { page, context } = await newPage('ok', { initScript: 'window.print = () => { window.__printed = (window.__printed || 0) + 1; };' });
    check('pdf: button hidden before any check', !(await page.locator('#pdf').isVisible()));
    check('pdf: report empty before any click', (await page.locator('#report').innerHTML()).trim() === '');
    await runChecks(page);
    await page.fill('#pw', 'hunter2pc');
    await page.click('#pw-submit');
    await page.waitForFunction(() => ['ok', 'risk'].includes(document.getElementById('check-password').getAttribute('data-status')));
    check('pdf: button shown after the checks', await page.locator('#pdf').isVisible());
    check('pdf: hint about Save as PDF', /Save as PDF/.test(await page.locator('#check-tools, .run').first().innerText()));
    await page.click('#pdf');
    check('pdf: print dialog opened once', (await page.evaluate(() => window.__printed)) === 1);
    const text = await page.locator('#report').innerText();
    for (const name of ['PC Check report', 'Browser', 'Connection', 'DNS', 'WebRTC leak', 'Trackability', 'Password', 'What left your device', 'Generated locally in your browser']) {
      check('pdf: report includes ' + name, text.includes(name));
    }
    check('pdf: report shows the 5-character prefix', text.includes('A4F1D'), text.slice(0, 200));
    const html = await page.locator('#report').innerHTML();
    check('pdf: never contains password or full hash', !html.includes('hunter2pc') && !html.includes('A4F1D4784D162648E82B5F1FA8C66C3A1257A68F') && !html.includes('4784D162648E82B5F1FA8C66C3A1257A68F'));
    check('pdf: report has the CyberSecInfo emblem', (await page.locator('#report img[src*="emblem.png"]').count()) === 1);
    await page.emulateMedia({ media: 'print' });
    check('pdf: print shows the report', await page.locator('#report').isVisible());
    check('pdf: print hides the app', !(await page.locator('.layout').isVisible()) && !(await page.locator('.site-head').isVisible()));
    await page.pdf({ path: path.join(shots, 'report.pdf'), format: 'A4', printBackground: true });
    await page.emulateMedia({ media: 'screen' });
    check('pdf: report hidden again on screen', !(await page.locator('#report').isVisible()));
    await context.close();
  }

  // 8a. System report parsers (Windows), on anonymised real reports
  console.log('System report parsers');
  {
    const fx = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', f)).toString('base64');
    const files = { rel: fx('reliability.xml'), relDe: fx('reliability-de.xml'), bat: fx('battery-report.html'), msi: fx('msinfo32-head.txt'), de: fx('msinfo32-de.txt') };
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((files) => {
      const S = window.PCSys;
      if (!S) return null;
      const buf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
      const text = {}; Object.keys(files).forEach((k) => { text[k] = S.decode(buf(files[k])); });
      const rel = S.parseReliability(text.rel);
      const bat = S.parseBattery(text.bat);
      const msi = S.parseMsinfo(text.msi);
      const big = text.msi + '\r\n[Software Environment]\r\n' + 'x'.repeat(27000000);
      const t0 = performance.now();
      const bigParsed = S.parseMsinfo(big);
      return {
        relGenerated: rel.generated && rel.generated.toISOString().slice(0, 10), relNow: rel.stabilityNow,
        relShutdowns: rel.events ? rel.events.filter((e) => e.problem === 'Shut down unexpectedly').length : -1,
        relMiracast: rel.events ? rel.events.filter((e) => /Miracast/.test(e.source)).length : -1,
        relUnsupported: rel.unsupportedLanguage === true, relDe: S.parseReliability(text.relDe),
        relNoEvents: S.parseReliability('<?xml version="1.0"?><RelMonReport TimeGenerated="2026-10-17T10:00:00"><Events/></RelMonReport>'),
        relDeEval: (() => { const e = S.evaluateWindows({ reliability: S.parseReliability(text.relDe) }, new Date('2026-10-18T09:00:00Z')); return { findings: e.findings.length, reportDate: e.reportDate, shutdowns: e.shutdowns30d }; })(),
        bat, msi, de: S.parseMsinfo(text.de),
        // Spanish reports (small synthetic snippets): English is the only language PC Check reads.
        es: S.parseMsinfo(text.msi.replace('[System Summary]', '[Resumen del sistema]').replace('Item\tValue', 'Elemento\tValor')
          .replace('OS Name', 'Nombre del SO').replace('Installed Physical Memory (RAM)', 'Memoria f\u00edsica instalada (RAM)')),
        esBat: S.parseBattery('<html><head><title>Informe de la bater\u00eda</title></head><body><!-- schemas.microsoft.com/battery -->' +
          '<table><tr><td><span class="label">CAPACIDAD DE DISE\u00d1O</span></td><td>76.316 mWh</td></tr>' +
          '<tr><td><span class="label">CAPACIDAD DE CARGA COMPLETA</span></td><td>68.979 mWh</td></tr>' +
          '<tr><td><span class="label">RECUENTO DE CICLOS</span></td><td>96</td></tr></table></body></html>'),
        wrong: S.parseReliability(text.bat), wrongBat: S.parseBattery(text.rel), wrongMsi: S.parseMsinfo('hello'),
        bigMs: performance.now() - t0, bigOs: bigParsed.os
      };
    }, files);
    check('PCSys is loaded', r !== null);
    if (r) {
      check('reliability: generated date', r.relGenerated === '2026-10-17', r.relGenerated);
      check('reliability: stability now ~1.97', Math.abs(r.relNow - 1.97) < 0.01, r.relNow);
      check('reliability: unexpected shutdowns parsed', r.relShutdowns > 0, r.relShutdowns);
      check('reliability: MiracastPowerManager crashes parsed', r.relMiracast > 0, r.relMiracast);
      check('reliability: English report is read (not flagged as another language)', !r.relUnsupported);
      check('reliability: German report (localised Problem text) -> unsupported language, not a healthy verdict', r.relDe.unsupportedLanguage === true && !r.relDe.events, r.relDe);
      check('reliability: an unsupported report adds no findings and no date in evaluateWindows', r.relDeEval.findings === 0 && r.relDeEval.reportDate === null && r.relDeEval.shutdowns === null, r.relDeEval);
      check('reliability: a report with no events at all is still read', Array.isArray(r.relNoEvents.events) && r.relNoEvents.events.length === 0 && !r.relNoEvents.unsupportedLanguage, r.relNoEvents);
      check('battery: health between 0 and 100 and cycles', r.bat.healthPct > 80 && r.bat.healthPct < 100 && r.bat.cycles === 96, r.bat);
      check('battery: design and full capacity in mWh', r.bat.designMWh === 76316 && r.bat.fullMWh === 68979, r.bat);
      check('msinfo: OS, model, CPU, RAM', /Windows 11/.test(r.msi.os) && /Predator/.test(r.msi.model) && /Ultra 7/.test(r.msi.cpu) && r.msi.ramGb === 32, r.msi);
      check('msinfo: no problem devices on this PC', Array.isArray(r.msi.problemDevices) && r.msi.problemDevices.length === 0, r.msi.problemDevices);
      check('msinfo: Spanish report -> unsupported language (English only)', r.es.unsupportedLanguage === true && !r.es.os, r.es);
      check('battery: Spanish report -> unsupported language (English only)', r.esBat.unsupportedLanguage === true && r.esBat.healthPct === undefined, r.esBat);
      check('msinfo: German reports unsupported language', r.de.unsupportedLanguage === true, r.de);
      check('wrong file: battery report is not a reliability file', r.wrong.error === 'not_reliability', r.wrong);
      check('wrong file: reliability is not a battery report', r.wrongBat.error === 'not_battery', r.wrongBat);
      check('wrong file: random text is not msinfo', r.wrongMsi.error === 'not_msinfo', r.wrongMsi);
      check('msinfo: 27 MB file parses in < 2 s and only the head is read', r.bigMs < 2000 && /Windows 11/.test(r.bigOs), [Math.round(r.bigMs), r.bigOs]);
    }
    await context.close();
  }

  // 8a-linux. Linux report parsers, on synthetic outputs that follow the real formats
  console.log('Linux report parsers');
  {
    const lx = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', f), 'utf8');
    const t = {};
    ['ubuntu-system', 'fedora-system', 'ubuntu-journal-boot', 'fedora-journal-disk', 'journal-no-entries', 'journal-hint', 'journal-de',
      'boots-ubuntu', 'boots-old-format', 'upower-laptop', 'upower-empty', 'df-ubuntu', 'df-fedora-full', 'df-de'].forEach((k) => { t[k] = lx(k + '.txt'); });
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((t) => {
      const S = window.PCSys;
      if (!S || !S.parseJournal) return null;
      const ymd = (d) => d ? [d.getFullYear(), d.getMonth() + 1, d.getDate()].join('-') : null;
      const ub = S.parseLinuxSystem(t['ubuntu-system']);
      const fe = S.parseLinuxSystem(t['fedora-system']);
      const plain = S.parseLinuxSystem('Linux ubuntu 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n');
      const j = S.parseJournal(t['ubuntu-journal-boot'], 2026);
      const bySrc = (res, s) => res.lines.filter((l) => l.source === s).length;
      const iso = S.parseJournal('2026-10-18T09:00:03+0100 tuxbox-jdoe systemd[1]: Failed to start x.service.');
      const bootsUb = S.parseBoots(t['boots-ubuntu']);
      const bootsOld = S.parseBoots(t['boots-old-format']);
      const up = S.parseUpower(t['upower-laptop']);
      const dU = S.parseDisks(t['df-ubuntu']);
      const dF = S.parseDisks(t['df-fedora-full']);
      const big = t['ubuntu-journal-boot'].repeat(Math.ceil(2500000 / t['ubuntu-journal-boot'].length));
      const t0 = performance.now();
      const bigJ = S.parseJournal(big, 2026);
      const bigMs = performance.now() - t0;
      return {
        caps: [S.LINUX_PASTE_CAP, S.LINUX_MAX_LINES],
        ub: { kernel: ub.kernel, distro: ub.distro, names: ub.names, id: ub.id, versionId: ub.versionId, supportEnd: ub.supportEnd },
        fe: { supportEnd: ymd(fe.supportEnd), names: fe.names, distro: fe.distro },
        plainNames: plain.names, plainDistro: plain.distro, notSystem: S.parseLinuxSystem('hello world'),
        j: { total: j.total, gnome: bySrc(j, 'gnome-shell'), kernel: bySrc(j, 'kernel'), gdm: bySrc(j, 'gdm-password'), names: j.names,
          firstTime: j.lines[0].time && j.lines[0].time.getTime(), expFirst: new Date(2026, 9, 18, 8, 59, 58).getTime(), truncated: j.truncated, partial: j.partial },
        fedoraJ: (() => { const f = S.parseJournal(t['fedora-journal-disk'], 2026); return { total: f.total, names: f.names }; })(),
        noEntries: S.parseJournal(t['journal-no-entries']), hint: S.parseJournal(t['journal-hint']),
        oldPerm: S.parseJournal('No journal files were opened due to insufficient permissions.'),
        de: S.parseJournal(t['journal-de']), dfAsJournal: S.parseJournal(t['df-ubuntu']),
        iso: { total: iso.total, time: iso.lines[0] && iso.lines[0].time && iso.lines[0].time.getTime(), exp: Date.parse('2026-10-18T09:00:03+01:00'), source: iso.lines[0] && iso.lines[0].source },
        bootsUb: { n: bootsUb.boots && bootsUb.boots.length, report: bootsUb.reportDate && bootsUb.reportDate.getTime(), exp: new Date(2026, 9, 18, 10, 6, 1).getTime(),
          prevTotal: bootsUb.previous && bootsUb.previous.total, prevYear: bootsUb.previous && bootsUb.previous.lines[0] && bootsUb.previous.lines[0].time.getFullYear() },
        bootsOld: { n: bootsOld.boots && bootsOld.boots.length, noEntries: bootsOld.previous && bootsOld.previous.noEntries },
        bootsSa: S.parseBoots(t['boots-ubuntu'].replace(/Sat /g, 'Sa ')), notBoots: S.parseBoots('hello'),
        up, upJson: JSON.stringify(up), upEmpty: S.parseUpower(t['upower-empty']), upBlank: S.parseUpower('   \n'),
        upComma: S.parseUpower('  native-path: BAT0\n    energy-full:         41,22 Wh\n    energy-full-design:  57,02 Wh\n    charge-cycles:       N/A\n'),
        upUsage: S.parseUpower('Usage:\n  upower [OPTION…]\n\nUPower tool\n'), upWrong: S.parseUpower('hello'),
        dU: { worst: dU.worstPct, devices: dU.filesystems.map((f) => f.device), disks: dU.disks.map((d) => d.name), backup: (dU.filesystems.filter((f) => f.device === '/dev/sdb1')[0] || {}).mount },
        dF: { worst: dF.worstPct, sda3: dF.filesystems.filter((f) => f.device === '/dev/sda3').map((f) => f.mounts), disks: dF.disks.map((d) => d.name) },
        dDe: S.parseDisks(t['df-de']), notDisks: S.parseDisks('hello'),
        bigMs, bigJ: { cut: bigJ.cut, truncated: bigJ.truncated, total: bigJ.total },
        manyJ: (() => { const m = S.parseJournal('Oct 18 09:00:00 host kernel: x\n'.repeat(30000), 2026); return { truncated: m.truncated, total: m.total }; })(),
        // Exactly 20,000 journal lines followed only by a hint: the cap was reached but nothing was left unread
        capExact: (() => { const m = S.parseJournal('Oct 18 09:00:00 host kernel: x\n'.repeat(20000) + '-- No entries --\n', 2026); return { truncated: m.truncated, total: m.total }; })(),
        // Year rollover: December lines in a January report belong to the year before, whatever the hint
        rollDate: (() => { const m = S.parseJournal('Dec 31 23:59:00 host kernel: a\nJan 02 08:00:00 host kernel: b', new Date(2027, 0, 5, 12, 0, 0)); return m.lines.map((l) => l.time.getFullYear()); })(),
        rollPastYear: (() => { const m = S.parseJournal('Dec 31 23:59:00 host kernel: a', 2025); return m.lines[0].time.getFullYear(); })(),
        rollNone: (() => { const now = new Date(); const later = (now.getMonth() + 1) % 12; const name = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][later];
          const m = S.parseJournal(name + ' 01 08:00:00 host kernel: a'); return { notFuture: m.lines[0].time.getTime() <= now.getTime(), year: m.lines[0].time.getFullYear(), now: now.getFullYear(), wrap: later === 0 }; })(),
        // Disks: the user name in /media/<user>/ and /run/media/<user>/ mounts is collected for the anonymiser
        dUnames: dU.names,
        runMedia: S.parseDisks('Filesystem      Size  Used Avail Use% Mounted on\n/dev/sdc1        30G   12G   18G  40% /run/media/jdoe/USB STICK\n').names,
        dfT: S.parseDisks('Filesystem     Type      Size  Used Avail Use% Mounted on\ntmpfs          tmpfs     1.6G  2.4M  1.6G   1% /run\n/dev/nvme0n1p2 ext4      468G  410G   35G  93% /\n/dev/sr0       iso9660   5.7G  5.7G     0 100% /media/jdoe/Ubuntu 24.04 LTS amd64\n'),
        dfI: S.parseDisks('Filesystem       Inodes   IUsed    IFree IUse% Mounted on\n/dev/nvme0n1p2 31227904 1052311 30175593    4% /\n'),
        dfPrompt: S.parseDisks('jdoe@tuxbox:~% LC_ALL=C df -h\nScanning 5% done here\nFilesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   20G   30G  40% /\n'),
        dfPromptOnly: S.parseDisks('jdoe@tuxbox:~% df -h\n'),
        // One 2 MB line full of spaces must not stall any parser (no quadratic regex on a whole line)
        oneLine: (() => { const line = 'x '.repeat(1000000); const out = {}; const t1 = performance.now();
          out.system = S.parseLinuxSystem(line).error; out.journal = S.parseJournal(line).error; out.boots = S.parseBoots(' 0 ' + 'f'.repeat(32) + ' ' + line).error;
          out.upower = S.parseUpower(' native-path ' + ' \n'.repeat(1000000)).present; out.disks = S.parseDisks(line).error;
          out.ms = performance.now() - t1; return out; })()
      };
    }, t);
    check('linux: parsers are loaded', r !== null);
    if (r) {
      check('linux: caps are 2,000,000 chars and 20,000 lines', r.caps[0] === 2000000 && r.caps[1] === 20000, r.caps);
      check('linux system: Ubuntu kernel and distro', r.ub.kernel === '6.8.0-45-generic' && r.ub.distro === 'Ubuntu 24.04.1 LTS' && r.ub.id === 'ubuntu' && r.ub.versionId === '24.04' && r.ub.supportEnd === null, r.ub);
      check('linux system: Ubuntu hostname is a name', r.ub.names.includes('tuxbox-jdoe'), r.ub.names);
      check('linux system: Fedora SUPPORT_END 2025-05-13', r.fe.supportEnd === '2025-5-13', r.fe);
      check('linux system: Fedora hostname and its first label are names', r.fe.names.includes('fedora-ws01.home.lan') && r.fe.names.includes('fedora-ws01'), r.fe.names);
      check('linux system: default hostname "ubuntu" is not a name', !r.plainNames.includes('ubuntu') && r.plainDistro === 'Ubuntu 24.04.1 LTS', r.plainNames);
      check('linux system: random text -> not_system', r.notSystem.error === 'not_system', r.notSystem);
      check('linux journal: Ubuntu has 25 lines', r.j.total === 25, r.j.total);
      check('linux journal: gnome-shell 5 lines, kernel 10', r.j.gnome === 5 && r.j.kernel === 10, r.j);
      check('linux journal: "gdm-password]" source is gdm-password', r.j.gdm === 1, r.j.gdm);
      check('linux journal: names include the user jdoe and the hostname', r.j.names.includes('jdoe') && r.j.names.includes('tuxbox-jdoe'), r.j.names);
      check('linux journal: short time parsed in local time with the year hint', r.j.firstTime === r.j.expFirst, r.j);
      check('linux journal: Fedora hostnames are names', r.fedoraJ.total === 15 && r.fedoraJ.names.includes('fedora-ws01.home.lan'), r.fedoraJ);
      check('linux journal: -- No entries -- -> noEntries, total 0', r.noEntries.noEntries === true && r.noEntries.total === 0, r.noEntries);
      check('linux journal: permission hint -> partial', r.hint.partial === true && r.hint.total === 0, r.hint);
      check('linux journal: old "insufficient permissions" line -> partial', r.oldPerm.partial === true, r.oldPerm);
      check('linux journal: German month names -> unsupported language', r.de.unsupportedLanguage === true && !r.de.lines, r.de);
      check('linux journal: df output -> not_journal', r.dfAsJournal.error === 'not_journal', r.dfAsJournal);
      check('linux journal: -o short-iso line parses with the right time', r.iso.total === 1 && r.iso.time === r.iso.exp && r.iso.source === 'systemd', r.iso);
      check('linux boots: Ubuntu has 5 boots, report date is the last entry (local)', r.bootsUb.n === 5 && r.bootsUb.report === r.bootsUb.exp, r.bootsUb);
      check('linux boots: previous boot has 3 error lines dated 2026', r.bootsUb.prevTotal === 3 && r.bootsUb.prevYear === 2026, r.bootsUb);
      check('linux boots: old format (em dash) has 5 boots and no previous entries', r.bootsOld.n === 5 && r.bootsOld.noEntries === true, r.bootsOld);
      check('linux boots: localised weekday -> unsupported language', r.bootsSa.unsupportedLanguage === true, r.bootsSa);
      check('linux boots: random text -> not_boots', r.notBoots.error === 'not_boots', r.notBoots);
      check('linux upower: health 72.3 % and 412 cycles', r.up.present === true && r.up.healthPct === 72.3 && r.up.cycles === 412 && r.up.fullWh === 41.22 && r.up.designWh === 57.02, r.up);
      check('linux upower: model and serial are not kept', !r.upJson.includes('5B10W13930') && !r.upJson.includes('4521'), r.upJson);
      check('linux upower: empty box -> no battery reported', r.upEmpty.present === false && r.upBlank.present === false, [r.upEmpty, r.upBlank]);
      check('linux upower: decimal comma also gives 72.3, N/A cycles -> null', r.upComma.healthPct === 72.3 && r.upComma.cycles === null, r.upComma);
      check('linux upower: usage text -> no battery reported', r.upUsage.present === false, r.upUsage);
      check('linux upower: random text -> not_battery', r.upWrong.error === 'not_battery', r.upWrong);
      check('linux disks: Ubuntu worst 93 %, no loop device, 2 disks', r.dU.worst === 93 && !r.dU.devices.some((d) => /loop/.test(d)) && r.dU.disks.join(',') === 'sdb,nvme0n1', r.dU);
      check('linux disks: mount point with a space is kept whole', r.dU.backup === '/media/jdoe/Backup Disk', r.dU.backup);
      check('linux disks: Fedora worst 96 %, /dev/sda3 once with / and /home, 1 disk', r.dF.worst === 96 && r.dF.sda3.length === 1 && r.dF.sda3[0].join(',') === '/,/home' && r.dF.disks.join(',') === 'sda', r.dF);
      check('linux disks: German df header -> unsupported language', r.dDe.unsupportedLanguage === true, r.dDe);
      check('linux disks: random text -> not_disks', r.notDisks.error === 'not_disks', r.notDisks);
      check('journal: 2 MB parses in < 1 s and reads <= 20,000 lines', r.bigJ.cut === true && r.bigJ.total > 0 && r.bigJ.total <= 20000 && r.bigMs < 1000, [Math.round(r.bigMs), r.bigJ]);
      check('linux journal: 30,000 short lines -> exactly 20,000 read, truncated', r.manyJ.truncated === true && r.manyJ.total === 20000, r.manyJ);
      check('linux journal: exactly 20,000 lines and nothing left -> not truncated', r.capExact.truncated === false && r.capExact.total === 20000, r.capExact);
      check('linux journal: December lines in a January report -> previous year', r.rollDate.join(',') === '2026,2027', r.rollDate);
      check('linux journal: past-year number hint keeps December in that year', r.rollPastYear === 2025, r.rollPastYear);
      check('linux journal: no hint -> a month after today is dated last year, never in the future', r.rollNone.notFuture && r.rollNone.year === r.rollNone.now - (r.rollNone.wrap ? 0 : 1), r.rollNone);
      check('linux disks: user from /media/<user>/ mount is a name', Array.isArray(r.dUnames) && r.dUnames.includes('jdoe'), r.dUnames);
      check('linux disks: user from /run/media/<user>/ mount is a name', Array.isArray(r.runMedia) && r.runMedia.includes('jdoe'), r.runMedia);
      check('linux disks: df -hT is English, optical /dev/sr0 ignored', !r.dfT.unsupportedLanguage && r.dfT.worstPct === 93 && r.dfT.filesystems.length === 1 && r.dfT.filesystems[0].sizeText === '468G' && r.dfT.names.includes('jdoe'), r.dfT);
      check('linux disks: df -i is English (inode use)', !r.dfI.unsupportedLanguage && r.dfI.inodes === true && r.dfI.worstPct === 4, r.dfI);
      check('linux disks: prompt and progress lines before the header are not a foreign header', !r.dfPrompt.unsupportedLanguage && r.dfPrompt.worstPct === 40, r.dfPrompt);
      check('linux disks: a prompt line alone -> not_disks', r.dfPromptOnly.error === 'not_disks', r.dfPromptOnly);
      check('linux: one 2 MB line of spaces is handled fast by every parser', r.oneLine.ms < 1000 && r.oneLine.system === 'not_system' && r.oneLine.journal === 'not_journal' && r.oneLine.disks === 'not_disks', [Math.round(r.oneLine.ms), r.oneLine]);
    }
    await context.close();
  }

  // 8a-mac. Mac report parsers, on synthetic files that follow the real formats
  console.log('Mac report parsers');
  {
    const macDir = path.join(here, '..', 'fixtures', 'sys', 'mac');
    const mx = (f) => fs.readFileSync(path.join(macDir, f), 'utf8');
    const reportFiles = fs.readdirSync(macDir).filter((f) => /\.(ips|panic|crash)$/.test(f)).sort();
    const reports = {};
    reportFiles.forEach((f) => { reports[f] = mx(f); });
    const input = {
      silicon: mx('silicon.spx'), intel: mx('intel.spx'), text: mx('sysinfo-text.txt'), reports,
      rel: fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'reliability.xml')).toString('base64'),
      df: fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', 'df-ubuntu.txt'), 'utf8')
    };
    const planted = JSON.parse(mx('PLANTED.json'));
    const plantedValues = [].concat(...Object.keys(planted).map((k) => planted[k])).concat(['Doe Family WiFi']).map((v) => v.toLowerCase());
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((t) => {
      const S = window.PCSys;
      if (!S || !S.parseSpx || !S.parseMacReport) return null;
      const buf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
      const iso = (d) => (d instanceof Date ? d.toISOString() : d);
      const noNames = (o) => { const c = Object.assign({}, o); delete c.names; return JSON.stringify(c); };
      const si = S.parseSpx(t.silicon);
      const it = S.parseSpx(t.intel);
      const rep = {};
      Object.keys(t.reports).forEach((f) => { const x = S.parseMacReport(t.reports[f]); rep[f] = { r: x, time: iso(x.time), json: JSON.stringify(x) }; });
      const caterr = t.reports['Kernel-2026-10-09-213301.panic'];
      const padded = caterr.replace('"processByPid" : {', '"processByPid" : {"pad" : "' + 'x'.repeat(3000000) + '",');
      const t0 = performance.now();
      const paddedR = S.parseMacReport(padded);
      const paddedMs = performance.now() - t0;
      return {
        head: S.MAC_REPORT_HEAD, majors: S.MACOS_MAJORS,
        si: Object.assign({}, si, { reportDate: iso(si.reportDate), names: undefined }), siNames: si.names,
        siJson: noNames(si), itJson: noNames(it),
        it: { chip: it.chip, chipKind: it.chipKind, osMajor: it.osMajor, battery: it.battery, volumes: it.volumes },
        text: S.parseSpx(t.text), rel: S.parseSpx(S.decode(buf(t.rel))),
        tiny: S.parseSpx('<?xml version="1.0"?><plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>'),
        service: S.parseSpx(t.silicon.replace('<string>Good</string>', '<string>Service Recommended</string>')).battery,
        worn: S.parseSpx(t.silicon.replace('78%', '55%')).battery,
        rep, padded: { cause: paddedR.cause, kind: paddedR.kind, ms: paddedMs },
        spxAsReport: S.parseMacReport(t.silicon), dfAsReport: S.parseMacReport(t.df),
        badHeader: S.parseMacReport('{"bug_type":\n{\n  "panicString" : "panic(cpu 0 caller 0x1): watchdog"\n}\n')
      };
    }, input);
    check('mac: parsers are loaded', r !== null);
    if (r) {
      const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      check('mac: report head is 1 MB and the macOS majors end with 15, 26, 27', r.head === 1048576 && r.majors.slice(-3).join(',') === '15,26,27' && r.majors.indexOf(13) !== -1, [r.head, r.majors]);
      const si = r.si;
      check('mac spx: Apple silicon macOS, model, chip, memory', si.macos === 'macOS 26.0.1 (25A362)' && si.osMajor === 26 && si.modelName === 'MacBook Air' && si.modelId === 'Mac14,2' &&
        si.chip === 'Apple M2' && si.chipKind === 'chip' && si.ramGb === 16, si);
      check('mac spx: battery health, cycles, condition', same(si.battery, { present: true, healthPct: 78, cycles: 412, condition: 'Good', service: false }), si.battery);
      check('mac spx: report date is the newest _timeStamp', si.reportDate === '2026-10-18T08:12:44.000Z', si.reportDate);
      check('mac spx: counted volumes (no /System/Volumes/Data, volume name hidden)', same(si.volumes, [{ where: 'startup', mount: '/', usedPct: 91.9, smart: 'Verified' }, { where: 'external', mount: '/Volumes/[volume]', usedPct: 40, smart: null }]), si.volumes);
      const has = (v) => r.siNames.some((n) => same(n, v));
      const want = ['Jane’s MacBook Air', "Jane's MacBook Air", 'Janes-MacBook-Air', 'Jane Doe', 'jdoe', { word: 'Jane' }, 'K7Q2W9X4RT', '4B7C1D2E-3F40-5A6B-7C8D-9E0F1A2B3C4D',
        '00008112-001A2B3C4D5E801E', 'F8Y2251Z9NKQ7LGAS', { word: 'Jane’s Backup' }, '8D2C1B0A-9F8E-4D7C-B6A5-948372615A0B', '6F5E4D3C-2B1A-4098-8F7E-6D5C4B3A2918'];
      check('mac spx: names for the anonymiser', want.every(has), [want.filter((w) => !has(w)), r.siNames]);
      check('mac spx: Macintosh HD and short words are not names', !has('Macintosh HD') && !has({ word: 'Macintosh HD' }) && !has({ word: 'Doe' }) && !has({ word: 'Data' }), r.siNames);
      const leaks = (s) => plantedValues.filter((v) => s.toLowerCase().indexOf(v) !== -1);
      const repLeaks = Object.keys(r.rep).map((f) => leaks(r.rep[f].json)).reduce((a, b) => a.concat(b), []);
      check('mac: parsers keep no identifiers', !leaks(r.siJson).length && !leaks(r.itJson).length && !repLeaks.length, [leaks(r.siJson), leaks(r.itJson), repLeaks]);
      check('mac spx: Intel chip, macOS 13, no battery', r.it.chip === '6-Core Intel Core i5' && r.it.chipKind === 'cpu' && r.it.osMajor === 13 && same(r.it.battery, { present: false }), r.it);
      check('mac spx: Intel startup disk 96 % and Failing, external 30 %', r.it.volumes.length === 2 && r.it.volumes[0].where === 'startup' && r.it.volumes[0].usedPct === 96 &&
        r.it.volumes[0].smart === 'Failing' && r.it.volumes[1].usedPct === 30 && r.it.volumes[1].mount === '/Volumes/[volume]', r.it.volumes);
      check('mac spx: text export -> spx_text', same(r.text, { error: 'spx_text' }), r.text);
      check('mac spx: Windows reliability XML -> not_spx', same(r.rel, { error: 'not_spx' }), r.rel);
      check('mac spx: plist without System Information data -> not_spx', same(r.tiny, { error: 'not_spx' }), r.tiny);
      check('mac spx: Service Recommended -> service', r.service.service === true && r.service.condition === 'Service Recommended', r.service);
      check('mac spx: 55% maximum capacity -> healthPct 55', r.worn.healthPct === 55, r.worn);
      const R = (prefix) => r.rep[Object.keys(r.rep).filter((f) => f.indexOf(prefix) === 0)[0]];
      const w = R('panic-full-2026-10-14');
      check('mac panic: watchdog, time, cause line', w.r.kind === 'panic' && w.r.cause === 'watchdog' && w.time === '2026-10-14T21:41:07.000Z' &&
        /^watchdog timeout: no checkins from watchdogd/.test(w.r.causeLine) && w.r.causeLine.length <= 4096 && same(w.r.extensions, []), w);
      check('mac panic: Kernel data abort -> data_abort', R('panic-full-2026-10-02').r.cause === 'data_abort', R('panic-full-2026-10-02'));
      const ca = R('Kernel-2026-10-09');
      check('mac panic: CATERR -> cpu_error with the third-party extension', ca.r.cause === 'cpu_error' && same(ca.r.extensions, ['com.paragon-software.filesystems.ntfs']), ca);
      const tx = R('Kernel-2026-08-20');
      check('mac panic: text body -> data_abort, time', tx.r.kind === 'panic' && tx.r.cause === 'data_abort' && tx.time === '2026-08-20T09:15:00.000Z', tx);
      const chrome = Object.keys(r.rep).filter((f) => /^Google Chrome/.test(f)).map((f) => r.rep[f].r);
      check('mac crash: both Chrome helper crashes', chrome.length === 2 && chrome.every((c) => c.kind === 'crash' && c.app === 'Google Chrome Helper (Renderer)' && c.exception === 'EXC_BAD_ACCESS'), chrome);
      const word = Object.keys(r.rep).filter((f) => /^Microsoft Word/.test(f)).map((f) => r.rep[f].r);
      check('mac crash: Word -> EXC_CRASH', word.length === 2 && word.every((c) => c.kind === 'crash' && c.app === 'Microsoft Word' && c.exception === 'EXC_CRASH'), word);
      const sa = R('Safari_');
      check('mac crash: legacy .crash -> Safari, EXC_BAD_ACCESS, time', sa.r.kind === 'crash' && sa.r.app === 'Safari' && sa.r.exception === 'EXC_BAD_ACCESS' && sa.time === '2026-10-01T08:09:09.123Z', sa);
      check('mac report: Jetsam -> other', same(R('JetsamEvent').r, { kind: 'other' }), R('JetsamEvent'));
      check('mac report: .spx, df output and a broken header -> not_mac_report', r.spxAsReport.error === 'not_mac_report' && r.dfAsReport.error === 'not_mac_report' && r.badHeader.error === 'not_mac_report', [r.spxAsReport, r.dfAsReport, r.badHeader]);
      check('mac panic: 3 MB of padding after panicString -> still cpu_error, fast', r.padded.kind === 'panic' && r.padded.cause === 'cpu_error' && r.padded.ms < 200, [Math.round(r.padded.ms), r.padded]);
    }
    await context.close();

    // A full System Information report holds dozens of data types: 25 MB must parse quickly in both engines
    for (const engineName of ['chromium', 'webkit']) {
      const eng = engineName === 'webkit' ? await webkit.launch() : browser;
      try {
        const made = await newPage('ok', {}, eng);
        const b = await made.page.evaluate((spx) => {
          const S = window.PCSys;
          if (!S || !S.parseSpx) return null;
          const entry = (i) => '<dict><key>_name</key><string>App ' + i + '</string><key>path</key><string>/Applications/App ' + i + '.app</string><key>version</key><string>1.0</string></dict>';
          const parts = [];
          let size = spx.length; // the wrapper below adds more, so the total is over 25,000,000
          for (let i = 0; size < 25000000; i++) { const e = entry(i); parts.push(e); size += e.length; }
          const apps = '\n\t<dict><key>_dataType</key><string>SPApplicationsDataType</string><key>_items</key><array>' + parts.join('') +
            '</array><key>_timeStamp</key><date>2026-10-01T08:00:00Z</date></dict>';
          const at = spx.indexOf('<array>') + '<array>'.length;
          const big = spx.slice(0, at) + apps + spx.slice(at);
          const t0 = performance.now();
          const res = S.parseSpx(big);
          const ms = performance.now() - t0;
          return { ms, len: big.length, same: JSON.stringify(res) === JSON.stringify(S.parseSpx(spx)) };
        }, input.silicon);
        check('spx: 25 MB parses in < 4 s (' + engineName + ')', b !== null && b.len >= 25000000 && b.same && b.ms < 4000, b && [Math.round(b.ms), b.len, b.same]);
        await made.context.close();
      } finally {
        if (eng !== browser) await eng.close();
      }
    }
  }

  // 8a-mac-rules. Mac rules, score, facts, anonymiser additions and the AI summary
  console.log('Mac report rules');
  {
    const macDir = path.join(here, '..', 'fixtures', 'sys', 'mac');
    const mx = (f) => fs.readFileSync(path.join(macDir, f), 'utf8');
    const all = fs.readdirSync(macDir);
    const pick = (re) => all.filter((f) => re.test(f)).sort().map(mx);
    const input = {
      silicon: mx('silicon.spx'), intel: mx('intel.spx'),
      setA: pick(/^(panic-full-|Google Chrome Helper|JetsamEvent-)/),
      setB: pick(/^(Kernel-|Microsoft Word-|Safari_)/),
      oldPanic: pick(/^Kernel-2026-08-20/), jetsam: pick(/^JetsamEvent-/)
    };
    const planted = JSON.parse(mx('PLANTED.json'));
    const plantedValues = [].concat(...Object.keys(planted).map((k) => planted[k])).map((v) => v.toLowerCase());
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((t) => {
      const S = window.PCSys;
      if (!S || !S.evaluateMac) return null;
      const now = new Date('2026-10-18T12:00:00');
      const reps = (list) => list.map((x) => S.parseMacReport(x));
      const brief = (e) => ({
        score: e.score, ids: e.findings.map((f) => f.id + ':' + f.severity), findings: e.findings, facts: e.facts,
        summary: JSON.stringify(S.buildSummary(e)), panics30d: e.panics30d, crashes30d: e.crashes30d, panicCauses: e.panicCauses,
        macos: e.macos, platform: e.platform,
        reportDate: e.reportDate instanceof Date ? e.reportDate.getFullYear() + '-' + String(e.reportDate.getMonth() + 1).padStart(2, '0') + '-' + String(e.reportDate.getDate()).padStart(2, '0') : null,
        shown: JSON.stringify(S.buildSummary(e)) + '\n' + e.facts.map((f) => f.value).join('\n') + '\n' + e.findings.map((f) => f.title + '\n' + f.detail + '\n' + f.fix).join('\n')
      });
      const si = S.parseSpx(t.silicon);
      const it = S.parseSpx(t.intel);
      return {
        A: brief(S.evaluateMac({ spx: si, reports: reps(t.setA) }, now)),
        B: brief(S.evaluateMac({ spx: it, reports: reps(t.setB) }, now)),
        siOnly: brief(S.evaluateMac({ spx: si }, now)),
        aReports: brief(S.evaluateMac({ reports: reps(t.setA) }, now)),
        oldPanic: brief(S.evaluateMac({ spx: si, reports: reps(t.oldPanic) }, now)),
        jetsam: brief(S.evaluateMac({ reports: reps(t.jetsam) }, now)),
        worn: brief(S.evaluateMac({ spx: S.parseSpx(t.silicon.replace('78%', '55%')) }, now)),
        service: brief(S.evaluateMac({ spx: S.parseSpx(t.silicon.replace('78%', '85%').replace('<string>Good</string>', '<string>Service Recommended</string>')) }, now)),
        stale: brief(S.evaluateMac({ spx: si }, new Date('2026-12-01T12:00:00Z'))),
        mac15: brief(S.evaluateMac({ spx: S.parseSpx(t.silicon.replace('macOS 26.0.1 (25A362)', 'macOS 15.7 (24G222)')) }, now)),
        ram8192: S.parseSpx(t.silicon.replace('<string>16 GB</string>', '<string>8,192 MB</string>')).ramGb,
        straddle: (() => {
          // The host name starts at character 106 of the cause line and ends after the 120-character cut
          const rest = 'watchdog timeout: ' + 'x'.repeat(82) + ' host Janes-MacBook-Air stopped responding';
          const rep = S.parseMacReport('{"bug_type":"210","timestamp":"2026-10-17 10:00:00.00 +0100"}\n{\n  "panicString" : "panic(cpu 0 caller 0xfffffe0012345678): ' + rest + '"\n}\n');
          const e = S.evaluateMac({ spx: si, reports: [rep] }, now);
          return { causeLen: rep.causeLine.length, shown: brief(e).shown, detail: e.findings.filter((f) => f.id === 'panics').map((f) => f.detail)[0] || '' };
        })(),
        blankApp: JSON.stringify(S.buildSummary(S.evaluateMac({ reports: [{ kind: 'crash', time: new Date('2026-10-17T10:00:00Z'), app: String.fromCharCode(0x200B, 0x200B, 0xAD), exception: null }] }, now)).topCrashApps),
        blankSummary: JSON.stringify(S.buildSummary({ platform: 'mac', score: 100, findings: [], names: [], topCrashApps: [{ name: String.fromCharCode(0x200B), count: 1 }] }).topCrashApps),
        future: brief(S.evaluateMac({ reports: reps(t.setA).concat([{ kind: 'crash', time: new Date('2099-01-01T00:00:00Z'), app: 'Future App', exception: null }]) }, now)),
        empty: brief(S.evaluateMac({}, now)),
        anon: {
          volume: S.anonymise('Opening /Volumes/Jane\u2019s Backup/x'),
          udid: S.anonymise('id 00008112-001A2B3C4D5E801E'),
          word: S.anonymise('Jane said hi', [{ word: 'Jane' }]),
          wordInside: S.anonymise('Janet', [{ word: 'Jane' }]),
          wordCase: S.anonymise('JANE and jane, Jane.', [{ word: 'Jane' }]),
          plain: S.anonymise('Sam\u2019s iMac and Samsung', ['Sam\u2019s iMac']),
          mixed: S.anonymise('Jane\u2019s MacBook Air: Jane', ['Jane\u2019s MacBook Air', { word: 'Jane' }]),
          noObjectText: S.anonymise('[object Object] stays', [{ word: 'Jane' }]),
          volumePrefixed: S.anonymise('/Volumes/[volume]Jane/x'),
          volumeKept: S.anonymise('x (/Volumes/[volume]) 92 % /Volumes/[volume]')
        },
        volumeWords: S.parseSpx(t.silicon.replace('<string>Jane\u2019s Backup</string>', '<string>Backup</string>')).names
      };
    }, input);
    check('mac rules: evaluateMac is loaded', r !== null);
    if (r) {
      const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
      const fact = (facts, label) => (facts.filter((f) => f.label === label)[0] || {}).value;
      const A = r.A;
      check('mac set A: platform mac, score 55', A.platform === 'mac' && A.score === 55, A.score);
      check('mac set A: panics risk, crashes info, disk_full warn, battery warn (in that order)', A.ids.join(',') === 'panics:risk,crashes:info,disk_full:warn,battery:warn', A.ids);
      check('mac set A: summary JSON is exact', A.summary === '{"platform":"mac","macos":"macOS 26.0.1 (25A362)","model":"MacBook Air (Mac14,2)","chip":"Apple M2","ramGb":16,"score":55,"findings":[{"id":"panics","severity":"risk"},{"id":"crashes","severity":"info"},{"id":"disk_full","severity":"warn"},{"id":"battery","severity":"warn"}],"panics30d":2,"panicCauses":[{"name":"data_abort","count":1},{"name":"watchdog","count":1}],"crashes30d":2,"topCrashApps":[{"name":"Google Chrome Helper (Renderer)","count":2}],"diskMaxUsedPct":91.9,"batteryHealthPct":78,"batteryCycles":412}', A.summary);
      const aPan = A.findings[0];
      check('mac set A: panics title, most recent watchdog, both cause sentences', aPan.title === 'Your Mac restarted after a kernel panic 2 times in 30 days' &&
        /^Most recent: 2026-10-14: watchdog timeout: no checkins from watchdogd/.test(aPan.detail) && /The system stopped responding/.test(aPan.detail) &&
        /A memory access fault inside macOS/.test(aPan.detail) && !/kernel extension was involved/.test(aPan.detail), aPan);
      check('mac set A: crashes detail names the app and its count', A.findings[1].title === 'Apps crashed 2 times in 30 days' && /Google Chrome Helper \(Renderer\) \(2 crashes\)/.test(A.findings[1].detail), A.findings[1]);
      check('mac set A: disk_full title and detail', A.findings[2].title === 'Startup disk is 91.9 % full' && /startup disk \(\/\) 91\.9 %/.test(A.findings[2].detail) && !/40 %/.test(A.findings[2].detail), A.findings[2]);
      check('mac set A: battery title and detail', A.findings[3].title === 'Battery holds 78 % of its original charge' && /^412 charge cycles so far\. macOS rates it: Good\.$/.test(A.findings[3].detail) &&
        /^Normal wear\./.test(A.findings[3].fix), A.findings[3]);
      check('mac set A: facts in order', same(A.facts.map((f) => f.label), ['System', 'Model', 'Chip', 'Memory', 'Startup disk', 'Battery health', 'Kernel panics (30 days)', 'App crashes (30 days)', 'Report from']), A.facts);
      check('mac set A: fact values', fact(A.facts, 'System') === 'macOS 26.0.1 (25A362)' && fact(A.facts, 'Model') === 'MacBook Air (Mac14,2)' && fact(A.facts, 'Chip') === 'Apple M2' &&
        fact(A.facts, 'Memory') === '16 GB' && fact(A.facts, 'Startup disk') === '91.9 % used' && fact(A.facts, 'Battery health') === '78 % (412 cycles)' &&
        fact(A.facts, 'Kernel panics (30 days)') === '2' && fact(A.facts, 'App crashes (30 days)') === '2' && fact(A.facts, 'Report from') === '2026-10-18', A.facts);
      const B = r.B;
      check('mac set B: score 20', B.score === 20, B.score);
      check('mac set B: panics warn, crashes warn, disk_smart risk, disk_full risk, old_macos warn', B.ids.join(',') === 'panics:warn,crashes:warn,disk_smart:risk,disk_full:risk,old_macos:warn', B.ids);
      check('mac set B: summary JSON is exact', B.summary === '{"platform":"mac","macos":"macOS 13.7.1 (22H221)","model":"iMac (iMac19,1)","chip":"6-Core Intel Core i5","ramGb":16,"score":20,"findings":[{"id":"panics","severity":"warn"},{"id":"crashes","severity":"warn"},{"id":"disk_smart","severity":"risk"},{"id":"disk_full","severity":"risk"},{"id":"old_macos","severity":"warn"}],"panics30d":1,"panicCauses":[{"name":"cpu_error","count":1}],"crashes30d":3,"topCrashApps":[{"name":"Microsoft Word","count":2},{"name":"Safari","count":1}],"diskMaxUsedPct":96,"batteryHealthPct":null,"batteryCycles":null}', B.summary);
      check('mac set B: panics detail names the third-party extension and the CPU cause', B.findings[0].title === 'Your Mac restarted after a kernel panic 1 time in 30 days' &&
        /A non-Apple kernel extension was involved: com\.paragon-software\.filesystems\.ntfs\./.test(B.findings[0].detail) && /The processor reported a hardware error/.test(B.findings[0].detail), B.findings[0]);
      check('mac set B: battery fact reads "No battery reported", Processor label', fact(B.facts, 'Battery health') === 'No battery reported' && fact(B.facts, 'Processor') === '6-Core Intel Core i5' && fact(B.facts, 'Chip') === undefined, B.facts);
      check('mac set B: disk_smart and disk_full texts', B.findings[2].title === 'A disk reports that it is failing' && B.findings[2].detail === 'Startup disk: SMART status Failing.' &&
        B.findings[3].title === 'Startup disk is 96 % full', [B.findings[2], B.findings[3]]);
      check('mac set B: old_macos title', B.findings[4].title === 'macOS 13 is not one of the three latest versions', B.findings[4]);
      check('mac rules: silicon.spx alone -> no report counts, disk_full + battery, score 80', r.siOnly.panics30d === null && r.siOnly.crashes30d === null &&
        r.siOnly.ids.join(',') === 'disk_full:warn,battery:warn' && r.siOnly.score === 80 && fact(r.siOnly.facts, 'Kernel panics (30 days)') === undefined, r.siOnly);
      check('mac rules: Set A reports alone -> report date 2026-10-16, no macOS, panics + crashes', r.aReports.reportDate === '2026-10-16' && r.aReports.macos === null &&
        r.aReports.ids.join(',') === 'panics:risk,crashes:info', r.aReports);
      check('mac rules: an August panic is outside the window -> panics30d 0, no finding', r.oldPanic.panics30d === 0 && !r.oldPanic.ids.some((i) => /^panics/.test(i)) && same(r.oldPanic.panicCauses, []), r.oldPanic);
      check('mac rules: Jetsam only -> 0 panics, 0 crashes, no findings, score 100', r.jetsam.panics30d === 0 && r.jetsam.crashes30d === 0 && r.jetsam.ids.length === 0 && r.jetsam.score === 100, r.jetsam);
      check('mac rules: battery 55 % -> risk with a replacement fix', r.worn.ids.includes('battery:risk') && /^Plan a battery replacement/.test(r.worn.findings.filter((f) => f.id === 'battery')[0].fix), r.worn.ids);
      const sv = r.service.findings.filter((f) => f.id === 'battery')[0];
      check('mac rules: Service Recommended at 85 % -> battery warn, condition named', sv && sv.severity === 'warn' && /^Battery holds 85 % /.test(sv.title) && /Service Recommended/.test(sv.detail) &&
        /^Plan a battery replacement/.test(sv.fix) && fact(r.service.facts, 'Battery health') === '85 % (412 cycles), Service Recommended', [sv, r.service.facts]);
      const st = r.stale.findings.filter((f) => f.id === 'old_report')[0];
      check('mac rules: a 44-day-old report -> old_report info', st && st.severity === 'info' && st.title === 'This report is 44 days old' && st.fix === '', st);
      check('mac rules: macOS 15 is still supported', !r.mac15.ids.some((i) => /^old_macos/.test(i)), r.mac15.ids);
      check('mac rules: no input -> score 100, no facts but the report date', r.empty.score === 100 && r.empty.ids.length === 0 && r.empty.panics30d === null, r.empty);
      check('mac spx: "8,192 MB" of memory -> 8 GB', r.ram8192 === 8, r.ram8192);
      const leaks = (s) => plantedValues.filter((v) => s.toLowerCase().indexOf(v) !== -1);
      const badPath = (s) => /\/Users\//.test(s) || /\/Volumes\/(?!\[volume\])/.test(s);
      check('mac anonymiser: no planted identifier in summary, facts, findings or PDF text', !leaks(A.shown).length && !leaks(B.shown).length && !badPath(A.shown) && !badPath(B.shown),
        [leaks(A.shown), leaks(B.shown)]);
      const fixes = A.findings.concat(B.findings, r.worn.findings, r.service.findings, r.stale.findings).map((f) => f.title + ' ' + f.detail + ' ' + f.fix).join('\n');
      check('mac rules: no Terminal or shell command in any title, detail or fix', !/Terminal|sudo|csrutil|diskutil|pmset|defaults |system_profiler/.test(fixes), (fixes.match(/.{0,40}(?:Terminal|sudo|csrutil|diskutil|pmset|defaults |system_profiler).{0,20}/) || [])[0]);
      const x = r.anon;
      check('mac anonymiser: /Volumes/<name> -> /Volumes/[volume]', x.volume === 'Opening /Volumes/[volume]/x', x.volume);
      check('mac anonymiser: provisioning UDID -> [id]', /\[id\]/.test(x.udid) && !/[0-9A-F]{6,}/i.test(x.udid), x.udid);
      check('mac anonymiser: {word} names are whole words, any case', x.word === '[name] said hi' && x.wordInside === 'Janet' && x.wordCase === '[name] and [name], [name].', [x.word, x.wordInside, x.wordCase]);
      check('mac anonymiser: plain names stay substrings, mixed lists work', x.plain === '[name] and Samsung' && x.mixed === '[name]: [name]' && x.noObjectText === '[object Object] stays', [x.plain, x.mixed, x.noObjectText]);
      check('mac spx: a generic volume name ("Backup") is not a name', !r.volumeWords.some((n) => typeof n === 'object' && /^backup$/i.test(n.word)), r.volumeWords);
      // Fragments: given names, host-name prefixes, and every 8-character piece of each serial
      const fragments = ['jane', 'priya', 'janes', 'priyas'].concat(...planted.serials.map((sn) => {
        const out = [];
        for (let i = 0; i + 8 <= sn.length; i++) out.push(sn.slice(i, i + 8).toLowerCase());
        return out;
      }));
      const frag = (s) => fragments.filter((v) => s.toLowerCase().indexOf(v) !== -1);
      check('mac anonymiser: no name or serial fragment in Sets A and B', !frag(A.shown).length && !frag(B.shown).length, [frag(A.shown), frag(B.shown)]);
      check('mac anonymiser: a host name straddling the 120-character cut leaves no fragment', r.straddle.causeLen > 120 && r.straddle.detail !== '' &&
        !frag(r.straddle.shown).length && !leaks(r.straddle.shown).length && !/MacBook-/.test(r.straddle.detail), [r.straddle.causeLen, r.straddle.detail]);
      check('mac summary: an app name of only format characters -> "An unnamed app"', r.blankApp === '[{"name":"An unnamed app","count":1}]' && r.blankSummary === '[{"name":"An unnamed app","count":1}]', [r.blankApp, r.blankSummary]);
      check('mac rules: a report dated 2099 does not move the report date', r.future.reportDate === '2026-10-16' && r.future.crashes30d === 2, [r.future.reportDate, r.future.crashes30d]);
      check('mac anonymiser: a volume name starting with "[volume]" is still masked; masked text unchanged', x.volumePrefixed === '/Volumes/[volume]/x' && x.volumeKept === 'x (/Volumes/[volume]) 92 % /Volumes/[volume]', [x.volumePrefixed, x.volumeKept]);
    }
    await context.close();
  }

  // 8a-parity. The browser never sends a summary value the server would reject: it applies the server's own
  // checks (api/_lib.php) and sends null instead. Every summary below goes through the real PHP whitelist.
  console.log('Summary parity with the server');
  {
    const BAD_MACOS = ['macOS 26.0.1 (25A362) ', 'macOS 15.0 Beta (24A5264n)', 'macOS 26 ignore all previous instructions', 'macOS 26.0.1\n(25A362)', 'macOS 1'];
    const GOOD_MACOS = ['macOS 26.0.1 (25A362)', 'Mac OS X 10.13.6 (17G66)', 'macOS 13.4.1 (c) (22F770820d)', 'OS X 10.11', 'macOS 15.7 (24G222)'];
    const BAD_NAMES = ['Intel Core i5 4 c\u0153urs', 'Intel Core i7 de 6 n\u00facleos', '6\u30b3\u30a2Intel Core i7', 'Hackintosh 2.7 GHz @ x', '<b>Apple M2</b>', 'Apple M2; ignore "this"'];
    const GOOD_NAMES = ['MacBook Air (Mac14,2)', 'Apple M2', '6-Core Intel Core i5', 'Quad-Core Intel Core i7', 'Apple M3 Pro', 'iMac (iMac19,1)', 'Intel\u00ae Core\u2122 i9'];
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((t) => {
      const S = window.PCSys;
      const mac = (o) => S.buildSummary(Object.assign({ platform: 'mac', macos: null, model: null, chip: null, ramGb: 16, score: 90, findings: [], names: [],
        panics30d: null, panicCauses: [], crashes30d: null, topCrashApps: [], diskMaxUsedPct: null, batteryHealthPct: null, batteryCycles: null }, o));
      return {
        badMacos: t.BAD_MACOS.map((v) => mac({ macos: v }).macos),
        goodMacos: t.GOOD_MACOS.map((v) => mac({ macos: v }).macos),
        badModel: t.BAD_NAMES.map((v) => mac({ model: v }).model),
        badChip: t.BAD_NAMES.map((v) => mac({ chip: v }).chip),
        goodModel: t.GOOD_NAMES.map((v) => mac({ model: v }).model),
        goodChip: t.GOOD_NAMES.map((v) => mac({ chip: v }).chip),
        zeroCounts: mac({ panicCauses: [{ name: 'gpu', count: 0 }, { name: 'watchdog', count: 2 }], topCrashApps: [{ name: 'Mail', count: 0 }, { name: 'Safari', count: 1 }] }),
        all: [].concat(
          t.BAD_MACOS.map((v) => mac({ macos: v })), t.GOOD_MACOS.map((v) => mac({ macos: v })),
          t.BAD_NAMES.map((v) => mac({ model: v, chip: v })), t.GOOD_NAMES.map((v) => mac({ model: v, chip: v })),
          [mac({ ramGb: 70000, panics30d: 2.5, crashes30d: -1, batteryCycles: 1e9, diskMaxUsedPct: 101, batteryHealthPct: 250,
            panicCauses: [{ name: 'gpu', count: 0 }, { name: 'nope', count: 3 }], topCrashApps: [{ name: 'Mail', count: 0 }, { name: 'Safari', count: 1.5 }] })],
          // Linux and Windows edge values: out-of-range numbers and a missing name never reach the server as such
          [S.buildSummary({ platform: 'linux', distro: 'Ubuntu 24.04.1 LTS', kernel: '6.8.0-45-generic', score: 70, findings: [], names: [],
            bootErrors: 1.5, topErrorSources: [{ name: null, count: 2 }, { name: 'kernel', count: 3 }], topCrashApps: [{ name: 'gedit', count: 2.5 }],
            oomKills: -2, previousBootErrors: 4, diskMaxUsedPct: 120, diskInodes: false, batteryHealthPct: 300 })],
          [S.buildSummary({ os: 'Windows 11 Home', model: 'Predator PTN16-51', ramGb: 70000, score: 50, findings: [], names: [],
            topCrashApps: [{ name: 'Teams', count: 2000000 }, { name: 'Edge', count: 1.5 }], batteryHealthPct: 250, shutdowns30d: 1.5,
            hardwareErrors30d: 200000, stabilityNow: 11 })])
      };
    }, { BAD_MACOS, GOOD_MACOS, BAD_NAMES, GOOD_NAMES });
    check('parity mac: macos values the server rejects -> null', r.badMacos.every((v) => v === null), r.badMacos);
    check('parity mac: real macOS versions kept (incl. a Rapid Security Response)', JSON.stringify(r.goodMacos) === JSON.stringify(GOOD_MACOS), r.goodMacos);
    check('parity mac: model and chip outside the server charset -> null', r.badModel.every((v) => v === null) && r.badChip.every((v) => v === null), [r.badModel, r.badChip]);
    check('parity mac: real model and chip names kept', JSON.stringify(r.goodModel) === JSON.stringify(GOOD_NAMES) && JSON.stringify(r.goodChip) === JSON.stringify(GOOD_NAMES), [r.goodModel, r.goodChip]);
    check('parity mac: zero counts are left out of panicCauses and topCrashApps', JSON.stringify(r.zeroCounts.panicCauses) === '[{"name":"watchdog","count":2}]' &&
      JSON.stringify(r.zeroCounts.topCrashApps) === '[{"name":"Safari","count":1}]', [r.zeroCounts.panicCauses, r.zeroCounts.topCrashApps]);
    let verdicts = null;
    try {
      verdicts = JSON.parse(execFileSync('php', [path.join(here, '..', 'tools', 'validate-summaries.php')], { input: JSON.stringify(r.all), encoding: 'utf8' }));
    } catch (e) { verdicts = String(e); }
    check('parity: the server accepts every summary the browser builds (Mac, Linux, Windows edge values)', Array.isArray(verdicts) && verdicts.length === r.all.length && verdicts.every(Boolean),
      Array.isArray(verdicts) ? r.all.filter((s, i) => !verdicts[i]) : verdicts);
    await context.close();
  }

  // 8b. System report rules, score, anonymiser and AI summary
  console.log('System report rules');
  {
    const fx = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', f)).toString('base64');
    const files = { rel: fx('reliability.xml'), bat: fx('battery-report.html'), msi: fx('msinfo32-head.txt') };
    // The server's own verdict, character by character (PHP's PCRE tables), for the cap() filter test
    const rejected = JSON.parse(execFileSync('php', [path.join(here, '..', 'tools', 'rejected-codepoints.php')], { encoding: 'utf8' }));
    // Every range of CONTROL_FORMAT_RE in assets/sysreport.js, as code points
    files.ranges = [[0x0, 0x1F], [0x7F, 0x9F], [0xAD, 0xAD], [0x600, 0x605], [0x61C, 0x61C], [0x6DD, 0x6DD], [0x70F, 0x70F], [0x890, 0x891],
      [0x8E2, 0x8E2], [0x180E, 0x180E], [0x200B, 0x200F], [0x202A, 0x202E], [0x2060, 0x2064], [0x2066, 0x206F], [0xFEFF, 0xFEFF],
      [0xFFF9, 0xFFFB], [0x110BD, 0x110BD], [0x110CD, 0x110CD], [0x13430, 0x1343F], [0x1BCA0, 0x1BCA3], [0x1D173, 0x1D17A],
      [0xE0001, 0xE0001], [0xE0020, 0xE007F]];
    // Characters just outside those ranges that the server accepts: they must survive
    files.neighbours = [0x20, 0x7E, 0xA0, 0xAC, 0xAE, 0x5FF, 0x606, 0x61B, 0x61D, 0x6DC, 0x6DE, 0x70E, 0x710, 0x88F, 0x892, 0x8E1, 0x8E3,
      0x180D, 0x180F, 0x200A, 0x2010, 0x2029, 0x202F, 0x205F, 0x2065, 0x2070, 0xFEFE, 0xFF00, 0xFFF8, 0xFFFC, 0x110BC, 0x110BE,
      0x110CC, 0x110CE, 0x1342F, 0x13440, 0x1BC9F, 0x1BCA4, 0x1D172, 0x1D17B, 0xE0000, 0xE0002, 0xE001F, 0xE0080, 0x1F600]
      .filter((cp) => !rejected.includes(cp));
    files.rejected = rejected;
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((files) => {
      const S = window.PCSys;
      if (!S || !S.evaluateWindows) return null;
      const buf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
      const now = new Date('2026-10-18T09:00:00Z');
      const real = S.evaluateWindows({ reliability: S.parseReliability(S.decode(buf(files.rel))), battery: S.parseBattery(S.decode(buf(files.bat))), msinfo: S.parseMsinfo(S.decode(buf(files.msi))) }, now);
      const gen = new Date('2026-10-17T12:00:00Z');
      const ev = (days, problem, source) => ({ time: new Date(gen.getTime() - days * 86400000), impact: 'Critical', source: source || 'Windows', problem });
      const rel = (events, now2) => ({ generated: gen, stabilityNow: 8, stabilityMin30d: 8, events });
      const ids = (e) => e.findings.map((f) => f.id + ':' + f.severity);
      const planted = S.buildSummary(S.evaluateWindows({
        reliability: rel([ev(1, 'Stopped working', 'C:\\Users\\JohnDoe\\AppData\\app.exe'), ev(2, 'Stopped working', 'john@x.com tool'),
          ev(3, 'Stopped working', 'AA:BB:CC:DD:EE:FF'), ev(4, 'Stopped working', 'PF3ABC1234XY helper'), ev(5, 'Stopped working', 'DESKTOP-JD123 svc')]),
        msinfo: { os: 'Microsoft Windows 11 Pro', model: 'DESKTOP-JD123 Model', cpu: 'x', ramGb: 16, problemDevices: [] },
        names: ['DESKTOP-JD123', 'JohnDoe']
      }, now));
      return {
        real: { score: real.score, ids: ids(real), text: JSON.stringify(real.findings), formula: 100 - 25 * real.findings.filter((f) => f.severity === 'risk').length - 10 * real.findings.filter((f) => f.severity === 'warn').length },
        three: ids(S.evaluateWindows({ reliability: rel([ev(1, 'Shut down unexpectedly'), ev(5, 'Shut down unexpectedly'), ev(9, 'Shut down unexpectedly'), ev(40, 'Shut down unexpectedly')]) }, now)),
        one: ids(S.evaluateWindows({ reliability: rel([ev(3, 'Shut down unexpectedly')]) }, now)),
        old: ids(S.evaluateWindows({ reliability: rel([ev(3, 'Shut down unexpectedly')]) }, new Date('2026-12-30T00:00:00Z'))),
        bat70: ids(S.evaluateWindows({ battery: { designMWh: 100, fullMWh: 70, cycles: 300, healthPct: 70 } }, now)),
        bat55: ids(S.evaluateWindows({ battery: { designMWh: 100, fullMWh: 55, cycles: 900, healthPct: 55 } }, now)),
        win10: ids(S.evaluateWindows({ msinfo: { os: 'Microsoft Windows 10 Home', ramGb: 8, problemDevices: [] } }, now)),
        devices: ids(S.evaluateWindows({ msinfo: { os: 'Microsoft Windows 11 Home', ramGb: 8, problemDevices: ['Unknown device'] } }, now)),
        planted: JSON.stringify(planted),
        keys: Object.keys(S.buildSummary(real)).sort(),
        // An emoji straddling the 80-character cut, plus control and format characters the server rejects
        capped: (() => {
          const base = S.evaluateWindows({ msinfo: { os: 'Microsoft Windows 11 Home', ramGb: 8, problemDevices: [] } }, now);
          base.model = 'M'.repeat(79) + '\u{1F600}tail';
          base.os = 'Win' + String.fromCharCode(7) + 'dows' + String.fromCharCode(0x200B) + ' 11' + String.fromCharCode(0x202E) + ' Home' + String.fromCharCode(0xFEFF);
          const sm = S.buildSummary(base);
          base.model = 'x'.repeat(78) + '\u{1F600}\u{1F600}\u{1F600}';
          const sm2 = S.buildSummary(base);
          // Every code point the server rejects (from PHP) and the start, middle and end of every range in
          // the browser's filter must be removed; the neighbours just outside the ranges must be kept.
          const strip = (cp) => { base.os = 'A' + String.fromCodePoint(cp) + 'B'; return S.buildSummary(base).os; };
          const notRemoved = (cps) => cps.filter((cp) => strip(cp) !== 'AB').map((cp) => cp.toString(16));
          const notKept = (cps) => cps.filter((cp) => strip(cp) !== 'A' + String.fromCodePoint(cp) + 'B').map((cp) => cp.toString(16));
          const samples = [];
          files.ranges.forEach(([a, z]) => { samples.push(a, Math.floor((a + z) / 2), z); });
          return { model: sm.model, os: sm.os, model2: sm2.model,
            phpMissed: notRemoved(files.rejected), rangeMissed: notRemoved(samples), neighboursLost: notKept(files.neighbours) };
        })()
      };
    }, files);
    check('PCSys.evaluateWindows exists', r !== null);
    if (r) {
      check('real PC: crashing background helpers flagged (MiracastPowerManager)', r.real.ids.includes('crashes:warn') && /MiracastPowerManager/.test(r.real.text), r.real.ids);
      check('real PC: hardware errors flagged', r.real.ids.includes('hardware:warn'), r.real.ids);
      check('real PC: low stability flagged', r.real.ids.includes('stability:warn'), r.real.ids);
      check('real PC: healthy battery (90 %) not flagged', !r.real.ids.some((i) => i.startsWith('battery')), r.real.ids);
      check('score follows the formula', r.real.score === Math.max(0, r.real.formula) && r.real.score < 80, [r.real.score, r.real.formula]);
      check('3 unexpected shutdowns in 30 days -> risk', r.three.includes('shutdowns:risk'), r.three);
      check('1 unexpected shutdown -> warn', r.one.includes('shutdowns:warn'), r.one);
      check('report older than 30 days adds an info note', r.old.includes('old_report:info'), r.old);
      check('battery 70 % -> warn, 55 % -> risk', r.bat70.includes('battery:warn') && r.bat55.includes('battery:risk'), [r.bat70, r.bat55]);
      check('Windows 10 -> warn', r.win10.includes('windows10:warn'), r.win10);
      check('problem devices -> warn', r.devices.includes('devices:warn'), r.devices);
      check('anonymiser: planted name/path/serial/MAC/email never appear in summary JSON',
        !/JohnDoe|john@x\.com|AA:BB:CC:DD:EE:FF|PF3ABC1234XY|DESKTOP-JD123/i.test(r.planted), r.planted);
      const lone = (s) => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
      const cps = (s) => Array.from(s).length;
      check('summary cap: emoji at the cut leaves no lone surrogate', !lone(r.capped.model) && cps(r.capped.model) <= 80 && r.capped.model.startsWith('M'.repeat(79)), [r.capped.model.length, r.capped.model.slice(-3)]);
      check('summary cap: counts code points like the server (80 max), keeps whole emoji', !lone(r.capped.model2) && cps(r.capped.model2) === 80 && r.capped.model2.endsWith('\u{1F600}\u{1F600}'), [r.capped.model2.length, cps(r.capped.model2)]);
      check('summary cap: control and format characters removed', r.capped.os === 'Windows 11 Home', JSON.stringify(r.capped.os));
      check('summary cap: removes every code point the server rejects (PHP Cc/Cf, ' + files.rejected.length + ' code points)', files.rejected.length > 100 && r.capped.phpMissed.length === 0, r.capped.phpMissed);
      check('summary cap: removes start, middle and end of every filter range', r.capped.rangeMissed.length === 0, r.capped.rangeMissed);
      check('summary cap: keeps the characters just outside the ranges (' + files.neighbours.length + ')', files.neighbours.length > 30 && r.capped.neighboursLost.length === 0, r.capped.neighboursLost);
      check('summary has only whitelisted fields',JSON.stringify(r.keys) === JSON.stringify(['batteryHealthPct', 'findings', 'hardwareErrors30d', 'model', 'os', 'ramGb', 'score', 'shutdowns30d', 'stabilityNow', 'topCrashApps']), r.keys);
    }
    await context.close();
  }

  // 8b-linux. Linux rules, score, facts, anonymiser additions and the Linux summary
  console.log('Linux report rules');
  {
    const lx = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', f), 'utf8');
    const t = {};
    ['ubuntu-system', 'ubuntu-journal-boot', 'boots-ubuntu', 'upower-laptop', 'df-ubuntu', 'fedora-system', 'fedora-journal-disk',
      'boots-old-format', 'upower-empty', 'df-fedora-full', 'journal-no-entries', 'journal-hint'].forEach((k) => { t[k] = lx(k + '.txt'); });
    t.planted = JSON.parse(lx('PLANTED.json'));
    const fx = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', f)).toString('base64');
    t.win = { rel: fx('reliability.xml'), bat: fx('battery-report.html'), msi: fx('msinfo32-head.txt') };
    const { page, context } = await newPage('ok');
    const r = await page.evaluate((t) => {
      const S = window.PCSys;
      if (!S || !S.evaluateLinux) return null;
      const now = new Date('2026-10-18T12:00:00');
      // The report date comes from the boot list; the journal takes its year from it, as the page does.
      const run = (sys, journal, boots, upower, df) => {
        const b = boots ? S.parseBoots(t[boots]) : undefined;
        const when = b && b.reportDate ? b.reportDate : now;
        return S.evaluateLinux({
          system: sys ? S.parseLinuxSystem(t[sys]) : undefined,
          journal: journal ? S.parseJournal(t[journal], when) : undefined,
          boots: b, battery: upower ? S.parseUpower(t[upower]) : undefined, disks: df ? S.parseDisks(t[df]) : undefined
        }, now);
      };
      const ids = (e) => e.findings.map((f) => f.id + ':' + f.severity);
      const text = (e) => JSON.stringify(S.buildSummary(e)) + '\n' + e.facts.map((f) => f.label + ': ' + f.value).join('\n') + '\n' +
        e.findings.map((f) => f.title + '\n' + f.detail + '\n' + f.fix).join('\n');
      const ub = run('ubuntu-system', 'ubuntu-journal-boot', 'boots-ubuntu', 'upower-laptop', 'df-ubuntu');
      const fe = run('fedora-system', 'fedora-journal-disk', 'boots-old-format', 'upower-empty', 'df-fedora-full');
      const line = (src, msg) => 'Oct 18 09:00:00 host ' + src + ': ' + msg;
      const jr = (lines) => S.evaluateLinux({ journal: S.parseJournal(lines.join('\n'), now) }, now);
      const acpi = [];
      for (let i = 0; i < 20; i++) acpi.push(line('kernel', i % 2 ? 'ACPI Error: AE_NOT_FOUND, During name lookup/catalog (20230628/psobject-220)' : 'ACPI BIOS Error (bug): Could not resolve symbol [\\_SB.PC00], AE_NOT_FOUND'));
      const planted = [].concat(t.planted.hostnames, t.planted.users, t.planted.emails, t.planted.macs, t.planted.ips, t.planted.serials,
        t.planted.uuids, t.planted.ssids, t.planted.labels, t.planted.bootIds);
      const leaks = (s) => planted.filter((p) => s.toLowerCase().indexOf(String(p).toLowerCase()) !== -1).concat(/\/home\//.test(s) ? ['/home/'] : []);
      const buf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer;
      const win = S.evaluateWindows({ reliability: S.parseReliability(S.decode(buf(t.win.rel))), battery: S.parseBattery(S.decode(buf(t.win.bat))),
        msinfo: S.parseMsinfo(S.decode(buf(t.win.msi))) }, new Date('2026-10-18T09:00:00Z'));
      const hostUbuntu = S.evaluateLinux({ system: S.parseLinuxSystem('Linux ubuntu 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n') }, now);
      return {
        ub: { score: ub.score, ids: ids(ub), summary: JSON.stringify(S.buildSummary(ub)), facts: ub.facts, platform: ub.platform, leaks: leaks(text(ub)),
          fixes: ub.findings.map((f) => f.fix) },
        fe: { score: fe.score, ids: ids(fe), facts: fe.facts, leaks: leaks(text(fe)), summary: JSON.stringify(S.buildSummary(fe)),
          crashDetail: (fe.findings.filter((f) => f.id === 'crashes')[0] || {}).detail, diskDetail: (fe.findings.filter((f) => f.id === 'disk_errors')[0] || {}).detail,
          fixes: fe.findings.map((f) => f.fix) },
        none: (() => { const e = S.evaluateLinux({ journal: S.parseJournal(t['journal-no-entries'], now) }, now); return { ids: ids(e), score: e.score, boot: e.bootErrors }; })(),
        hint: ids(S.evaluateLinux({ journal: S.parseJournal(t['journal-hint'], now) }, now)),
        acpi: ids(jr(acpi)),
        segv: ids(jr([line('kernel', 'totem[4242]: segfault at 0 ip 00007f sp 00007ffd error 4 in libgtk-4.so'),
          line('systemd-coredump[1]', 'Process 4242 (totem) of user 1000 dumped core.'), line('systemd-coredump[2]', 'Process 4300 (totem) of user 1000 dumped core.')])),
        anon: {
          uuid: S.anonymise('dev-disk-by\\x2duuid-3f1c2a9e\\x2d8b7d\\x2d4e6f\\x2d9a0b\\x2d1c2d3e4f5a6b'),
          ssid: S.anonymise('wlp2s0: CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid="JDoe-Home-5G" auth_failures=1'),
          ssid2: S.anonymise("Trying to associate with SSID 'JDoe-Home-5G'"),
          v6: S.anonymise('could not renew lease 2001:db8::1f'),
          cpp: S.anonymise('terminate called: std::vector::_M_range_check'),
          hex: S.anonymise('boot f1e2d3c4b5a697887766554433221100 usb 0123456789ABCDEF'),
          distro: hostUbuntu.facts.filter((f) => f.label === 'System').map((f) => f.value)[0],
          distroSummary: S.buildSummary(hostUbuntu).distro
        },
        fix1: (() => {
          const jl = ['Oct 18 09:00:00 tuxbox-jdoe jdoe-sync.sh[77]: sync failed', 'Oct 18 09:00:01 tuxbox-jdoe jdoe-sync.sh[77]: sync failed',
            'Oct 18 09:00:02 tuxbox-jdoe jdoe-sync.sh[77]: sync failed', 'Oct 18 09:00:03 tuxbox-jdoe jdoe-sync.sh[77]: sync failed',
            'Oct 18 09:00:04 tuxbox-jdoe jdoe-sync.sh[77]: sync failed', 'Oct 18 09:00:05 tuxbox-jdoe mailsync[9]: login failed for asmith@example.org',
            'Oct 18 09:00:06 tuxbox-jdoe asmith-backup[9]: x', 'Oct 18 09:00:07 tuxbox-jdoe kernel: totem[42]: segfault at 0 ip 0 sp 0 error 4'];
          const e = S.evaluateLinux({ journal: S.parseJournal(jl.join('\n'), now) }, now);
          const raw = JSON.stringify(Object.assign({}, e, { names: [] }));
          const inode = S.evaluateLinux({ disks: S.parseDisks('Filesystem       Inodes   IUsed    IFree IUse% Mounted on\n/dev/sda1 1000 960 40 96% /\n') }, now);
          return {
            journalOnly: text(e) + '\n' + raw,
            inodeSummary: S.buildSummary(inode).diskInodes, inodeIds: ids(inode), inodeTitle: (inode.findings[0] || {}).title,
            mapped: S.anonymise('::ffff:192.0.2.44 mapped'), v6colon: S.anonymise('lease 2001:db8::1f: failed'), v6dot: S.anonymise('lease 2001:db8::1f.'),
            ssids: [S.anonymise("SSID: 'Home Net'"), S.anonymise('SSID "Home Net" lost'), S.anonymise('ssid=HomeNet5 reason=3')],
            mixed: S.anonymise('id 0A1b2C3d4E5f60718293A4b5C6d7E8f9 x'), under: S.anonymise('unit_f1e2d3c4b5a69788_x and 0123456789ABCDEF_y'),
            win: S.anonymise('C:\\Users\\JohnDoe\\app.exe at 10.0.0.1 fe80::1ff:fe23:4567:890a', ['JohnDoe'])
          };
        })(),
        fix2: (() => {
          const sysAl = S.parseLinuxSystem('Linux al 6.8.0-45-generic #45-Ubuntu SMP x86_64 GNU/Linux\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n');
          const df = 'Filesystem      Size  Used Avail Use% Mounted on\n/dev/nvme0n1p2  468G  200G  268G  43% /\n' +
            '/dev/sdb1       1.9T  1.8T   50G  97% /media/al/Maria Garcia Backup\n/dev/sdc1       932G  890G   42G  96% /mnt/JSMITH-PASSPORT-SN8123456\n' +
            '/dev/sdd1        58G   55G    3G  95% /run/media/al/USB STICK\n/dev/nvme0n1p3  400G  380G   20G  95% /home\n';
          const e = S.evaluateLinux({ system: sysAl, disks: S.parseDisks(df) }, now);
          const sysOnly = S.evaluateLinux({ disks: S.parseDisks('Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda3 237G 226G 9.6G 96% /\n/dev/sda3 237G 226G 9.6G 96% /home\n/dev/sda2 974M 950M 24M 98% /boot\n') }, now);
          const jl = [];
          for (let i = 0; i < 6; i++) jl.push('Oct 18 09:00:0' + i + ' al al: backup failed');
          for (let i = 0; i < 6; i++) jl.push('Oct 18 09:01:0' + i + ' al mjones: sync failed');
          for (let i = 0; i < 6; i++) jl.push('Oct 18 09:02:0' + i + ' al kpat: cannot open /home/kpat/notes.txt');
          for (let i = 0; i < 6; i++) jl.push('Oct 18 09:03:0' + i + ' al NetworkManager[812]: <error> device wlp2s0 failed');
          jl.push('Oct 18 09:04:00 al login[900]: pam_unix(login:auth): authentication failure; logname= uid=0 euid=0 tty=tty1 ruser= rhost=  user=mjones');
          const ej = S.evaluateLinux({ system: sysAl, journal: S.parseJournal(jl.join('\n'), now) }, now);
          return {
            diskDetail: (e.findings.filter((f) => f.id === 'disk_full')[0] || {}).detail,
            fullest: (e.facts.filter((f) => f.label === 'Fullest disk')[0] || {}).value,
            shown: text(e) + '\n' + JSON.stringify(Object.assign({}, e, { names: [] })),
            sysDetail: (sysOnly.findings.filter((f) => f.id === 'disk_full')[0] || {}).detail,
            sysFullest: (sysOnly.facts.filter((f) => f.label === 'Fullest disk')[0] || {}).value,
            media: S.anonymise('cannot open /media/jdoe/Photos'), runMedia: S.anonymise('cannot open /run/media/jdoe/USB STICK'),
            sources: ej.topErrorSources.map((a) => a.name),
            summarySources: S.buildSummary(ej).topErrorSources.map((a) => a.name),
            repeated: (ej.findings.filter((f) => f.id === 'repeated_errors')[0] || {}).detail || ''
          };
        })(),
        perf: (() => {
          // 60,000 unique hostnames (each with two parts of 4+ characters) in a journal cut at 2 MB
          const lines = [];
          for (let i = 0; i < 60000; i++) lines.push('Oct 18 09:00:00 h' + i + '-k' + i + ' app' + (i % 7) + ': x');
          const journal = S.parseJournal(lines.join('\n'), now);
          const t0 = performance.now();
          const e = S.evaluateLinux({ journal: journal }, now);
          const sum = S.buildSummary(e);
          return { ms: performance.now() - t0, names: e.names.length, chars: lines.join('\n').length, sources: sum.topErrorSources.length };
        })(),
        winPlatform: win.platform,
        winSummary: JSON.stringify(S.buildSummary(win))
      };
    }, t);
    check('linux: PCSys.evaluateLinux exists', r !== null);
    if (r) {
      check('linux ubuntu: platform linux, score 25', r.ub.platform === 'linux' && r.ub.score === 25, [r.ub.platform, r.ub.score]);
      check('linux ubuntu: findings in order', r.ub.ids.join(',') === 'driver_errors:warn,repeated_errors:warn,crashes:info,oom:warn,prev_boot_crash:risk,disk_full:warn,battery:warn', r.ub.ids);
      check('linux ubuntu: summary JSON is exact', r.ub.summary === '{"platform":"linux","distro":"Ubuntu 24.04.1 LTS","kernel":"6.8.0-45-generic","score":25,"findings":[{"id":"driver_errors","severity":"warn"},{"id":"repeated_errors","severity":"warn"},{"id":"crashes","severity":"info"},{"id":"oom","severity":"warn"},{"id":"prev_boot_crash","severity":"risk"},{"id":"disk_full","severity":"warn"},{"id":"battery","severity":"warn"}],"bootErrors":25,"topErrorSources":[{"name":"kernel","count":10},{"name":"gnome-shell","count":5},{"name":"NetworkManager","count":2}],"topCrashApps":[{"name":"firefox","count":2}],"oomKills":1,"previousBootErrors":3,"diskMaxUsedPct":93,"diskInodes":false,"batteryHealthPct":72.3}', r.ub.summary);
      const fact = (facts, label) => (facts.filter((f) => f.label === label)[0] || {}).value;
      check('linux ubuntu: facts (system, kernel, disks, fullest, battery, errors, date)',
        fact(r.ub.facts, 'System') === 'Ubuntu 24.04.1 LTS' && fact(r.ub.facts, 'Kernel') === '6.8.0-45-generic' && fact(r.ub.facts, 'Disks') === '2 (476.9G, 1.8T)' &&
        fact(r.ub.facts, 'Fullest disk') === '93 % (/)' && fact(r.ub.facts, 'Battery health') === '72.3 % (412 cycles)' &&
        fact(r.ub.facts, 'Errors this boot') === '25' && fact(r.ub.facts, 'Logs from') === '2026-10-18', r.ub.facts);
      check('linux fedora: findings in order', r.fe.ids.join(',') === 'disk_errors:risk,readonly_fs:risk,hardware:risk,crashes:info,disk_full:risk,eol_release:warn', r.fe.ids);
      check('linux fedora: score 0', r.fe.score === 0, r.fe.score);
      check('linux fedora: nautilus counted once (abrt line not counted twice)', /nautilus \(1 crash\)/.test(r.fe.crashDetail || ''), r.fe.crashDetail);
      check('linux fedora: disk errors name the disk sda', /\bsda\b/.test(r.fe.diskDetail || ''), r.fe.diskDetail);
      check('linux fedora: no battery -> "No battery reported", no battery finding', fact(r.fe.facts, 'Battery health') === 'No battery reported' && !r.fe.ids.some((i) => i.startsWith('battery')), r.fe.facts);
      check('linux: -- No entries -- -> no findings, score 100, bootErrors 0', r.none.ids.length === 0 && r.none.score === 100 && r.none.boot === 0, r.none);
      check('linux: permission hint -> only journal_partial info', r.hint.join(',') === 'journal_partial:info', r.hint);
      check('linux: 20 ACPI lines -> no finding', r.acpi.length === 0, r.acpi);
      check('linux: a segfault plus 2 core dumps of one app -> crashes warn', r.segv.join(',') === 'crashes:warn', r.segv);
      check('linux anonymiser: no planted identifier in summary, facts, findings or PDF text', r.ub.leaks.length === 0 && r.fe.leaks.length === 0, [r.ub.leaks, r.fe.leaks]);
      const fixes = r.ub.fixes.concat(r.fe.fixes);
      check('linux: fix texts carry no command or sudo', fixes.every((f) => f && !/sudo|\bapt\b|\bdnf\b|journalctl|\$ |`|\bsystemctl\b|\brm\b/.test(f)), fixes);
      check('linux anonymiser: \\x2d UUID -> [id], no hex left', r.anon.uuid.includes('[id]') && !/[0-9a-f]{4,}/i.test(r.anon.uuid), r.anon.uuid);
      check('linux anonymiser: ssid="..." and SSID \'...\' -> ssid="[wifi]"', r.anon.ssid.includes('ssid="[wifi]"') && !/JDoe/i.test(r.anon.ssid) && r.anon.ssid2.includes('ssid="[wifi]"') && !/JDoe/i.test(r.anon.ssid2), [r.anon.ssid, r.anon.ssid2]);
      check('linux anonymiser: compressed IPv6 -> [ip]', r.anon.v6 === 'could not renew lease [ip]', r.anon.v6);
      check('linux anonymiser: std::vector unchanged', r.anon.cpp === 'terminate called: std::vector::_M_range_check', r.anon.cpp);
      check('linux anonymiser: 16+ hex runs -> [id]', r.anon.hex === 'boot [id] usb [id]', r.anon.hex);
      check('linux anonymiser: hostname "ubuntu" never replaces Ubuntu in the distro', r.anon.distro === 'Ubuntu 24.04.1 LTS' && r.anon.distroSummary === 'Ubuntu 24.04.1 LTS', r.anon);
      const x = r.fix1;
      check('linux fix: IPv4-mapped IPv6 keeps the IPv4 rule (::ffff:[ip])', x.mapped === '::ffff:[ip] mapped', x.mapped);
      check('linux fix: IPv6 followed by ":" or "." -> [ip]', x.v6colon === 'lease [ip]: failed' && x.v6dot === 'lease [ip].', [x.v6colon, x.v6dot]);
      check('linux fix: SSID: \'X\', SSID "X", ssid=X -> ssid="[wifi]"', x.ssids.every((s) => s.includes('ssid="[wifi]"') && !/Home/.test(s)), x.ssids);
      check('linux fix: mixed-case 32-hex run -> [id]', x.mixed === 'id [id] x', x.mixed);
      check('linux fix: hex runs next to an underscore -> [id]', x.under === 'unit_[id]_x and [id]_y', x.under);
      check('linux fix: Windows-style path, IPv4 and full IPv6 still masked as before', x.win === 'C:\\Users\\[user]\\app.exe at [ip] [ip]', x.win);
      check('linux fix: journal-only paste -> no user name (hostname part, e-mail local part) in summary, facts, findings or evaluation fields',
        !/jdoe|asmith/i.test(x.journalOnly), (x.journalOnly.match(/.{0,40}(?:jdoe|asmith).{0,20}/i) || [])[0]);
      check('linux fix: inode usage -> diskInodes true and an inode-worded disk_full', x.inodeSummary === true && x.inodeIds.join(',') === 'disk_full:risk' && /inodes/.test(x.inodeTitle), [x.inodeSummary, x.inodeIds, x.inodeTitle]);
      const y = r.fix2;
      check('linux mounts: removable and extra drives are not named (no label, no user, no path)',
        y.diskDetail === 'Space used: a removable or extra drive (97 %); another removable or extra drive (96 %); another removable or extra drive (95 %); /home (95 %). A full disk can stop updates and apps from saving.', y.diskDetail);
      check('linux mounts: fullest disk on an extra drive -> "a removable or extra drive"', y.fullest === '97 % (a removable or extra drive)', y.fullest);
      check('linux mounts: no volume label, user or mount path in summary, facts, findings or evaluation fields',
        !/Maria|Garcia|JSMITH|8123456|USB STICK|\/media\/|\/mnt\/|\bal\b/i.test(y.shown), (y.shown.match(/.{0,40}(?:Maria|Garcia|JSMITH|8123456|USB STICK|\/media\/|\/mnt\/|\bal\b).{0,20}/i) || [])[0]);
      check('linux mounts: system mounts are still shown (/, /home, /boot)', y.sysDetail === 'Space used: /boot (98 %); / and /home (96 %). A full disk can stop updates and apps from saving.' && y.sysFullest === '98 % (/boot)', [y.sysDetail, y.sysFullest]);
      check('linux anonymiser: /media/<user> and /run/media/<user> -> [user]', y.media === 'cannot open /media/[user]/Photos' && y.runMedia === 'cannot open /run/media/[user]/USB STICK', [y.media, y.runMedia]);
      check('linux sources: user-named log sources never reach the top sources or the summary', !y.sources.some((n) => /^(al|mjones|kpat)$/i.test(n)) && !y.summarySources.some((n) => /^(al|mjones|kpat)$/i.test(n)) && y.sources.includes('NetworkManager'), [y.sources, y.summarySources]);
      check('linux sources: repeated_errors names only the program, not the users', /NetworkManager \(6 errors\)/.test(y.repeated) && !/\b(al|mjones|kpat)\b/i.test(y.repeated), y.repeated);
      check('linux anonymiser: 60,000 unique hostnames in 2 MB -> evaluate + summary < 500 ms', r.perf.chars >= 2000000 && r.perf.names >= 50000 && r.perf.sources > 0 && r.perf.ms < 500, [Math.round(r.perf.ms), r.perf.names, r.perf.chars]);
      check('windows evaluation is marked platform windows', r.winPlatform === 'windows', r.winPlatform);
      check('windows summary unchanged after anonymiser additions', r.winSummary === '{"os":"Microsoft Windows 11 Home","model":"Predator PTN16-51","ramGb":32,"score":50,'
        + '"findings":[{"id":"shutdowns","severity":"warn"},{"id":"hardware","severity":"warn"},{"id":"crashes","severity":"warn"},'
        + '{"id":"stability","severity":"warn"},{"id":"updates","severity":"warn"}],'
        + '"topCrashApps":[{"name":"Java Update Scheduler","count":25},{"name":"AcerRegistrationBackGroundTask","count":25},'
        + '{"name":"MiracastPowerManager.exe","count":25}],"batteryHealthPct":90.4,"shutdowns30d":1,"hardwareErrors30d":1,"stabilityNow":1.97}', r.winSummary);
    }
    await context.close();
  }

  // 8c. System report panel (UI): OS banner, buttons, guide, uploads, results
  console.log('System report panel');
  {
    const FX = (f) => path.join(here, '..', 'fixtures', 'sys', f);
    const WIN_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + fullVersion + ' Safari/537.36';
    const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
    const pressed = (page, os) => page.getAttribute('#sys-os-' + os, 'aria-pressed', { timeout: 2000 }).catch(() => null);
    const waitBanner = (page) => page.waitForFunction(() => (document.getElementById('sys-banner') || {}).textContent, null, { timeout: 5000 }).catch(() => {});

    {
      const { page, context } = await newPage('ok', { userAgent: WIN_UA });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('system: Windows UA -> banner says Windows', /You.re on Windows/.test(banner), banner);
      check('system: Windows UA -> Windows button pre-selected', (await pressed(page, 'windows')) === 'true');
      check('system: banner has an inline SVG glyph', (await page.locator('#sys-banner svg').count()) === 1);
      const guide = await page.locator('#system').innerText({ timeout: 2000 }).catch(() => '');
      check('system: guide shows the three steps', /perfmon \/rel/.test(guide) && /powercfg \/batteryreport \/output "%USERPROFILE%\\Desktop\\battery-report.html"/.test(guide) && /msinfo32/.test(guide), guide.slice(0, 300));
      await page.click('#sys-os-mac', { timeout: 2000 }).catch(() => {});
      check('system: Mac button shows the Mac steps and hides the Windows steps', await page.locator('#sys-mac-steps').isVisible().catch(() => false) && !(await page.locator('#sys-steps').isVisible()));
      await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
      check('system: back to Windows hides the Mac steps', await page.locator('#sys-steps').isVisible().catch(() => false) && !(await page.locator('#sys-mac-steps').isVisible().catch(() => true)));
      await context.close();
    }
    {
      const { page, context } = await newPage('ok', { userAgent: MAC_UA });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('system: macOS UA -> Mac banner', /You.re on macOS/.test(banner), banner);
      check('system: macOS UA -> Mac pre-selected', (await pressed(page, 'mac')) === 'true');
      check('system: macOS UA -> Mac steps, no Coming soon', await page.locator('#sys-mac-steps').isVisible().catch(() => false) && (await page.locator('.sys-soon-tag').count()) === 0);
      await context.close();
    }
    {
      const { page, context, seen } = await newPage('ok', { userAgent: WIN_UA, viewport: { width: 1280, height: 900 } });
      const before = await page.locator('#ledger-list li').count();
      let ok = true;
      try {
        await page.setInputFiles('#sys-file-reliability', FX('reliability.xml'), { timeout: 3000 });
        await page.setInputFiles('#sys-file-battery', FX('battery-report.html'), { timeout: 3000 });
        await page.setInputFiles('#sys-file-msinfo', FX('msinfo32-head.txt'), { timeout: 3000 });
        await page.click('#sys-analyze', { timeout: 3000 });
        await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
      } catch (e) { ok = false; }
      check('system: fixtures upload and Analyze shows results', ok);
      const score = ok ? await page.locator('#sys-score').innerText() : '';
      check('system: a score is shown', /^\d{1,3}$/.test(score.trim()), score);
      const res = ok ? await page.locator('#sys-results').innerText() : '';
      check('system: a finding mentions MiracastPowerManager', /MiracastPowerManager/.test(res), res.slice(0, 300));
      check('system: findings come with fixes', ok && (await page.locator('#sys-results .sys-finding .sys-fix').count()) > 0);
      check('system: fact tiles shown (battery, memory)', /Battery health/.test(res) && /32 GB/.test(res), res.slice(0, 300));
      check('system: report date shown', /2026-10-17/.test(res), res.slice(0, 300));
      check('system: Analyze sends nothing (outbound log unchanged)', (await page.locator('#ledger-list li').count()) === before);
      check('system: Analyze makes no outside requests', seen.external.length === 0, seen.external);
      check('system: no page errors', seen.errors.length === 0, seen.errors);
      check('system: computer name never on screen', !/PC-NAME/.test(res), res.match(/.{0,20}PC-NAME.{0,20}/));
      await page.locator('#system').screenshot({ path: path.join(shots, 'system-desktop.png') }).catch(() => {});
      await context.close();
    }
    {
      // The report was saved at 22:38 local time on 17/10. West of UTC that is already 18/10 in UTC:
      // the dates shown must be the local ones.
      const { page, context } = await newPage('ok', { userAgent: WIN_UA, timezoneId: 'America/Los_Angeles' });
      let ok = true;
      try {
        await page.setInputFiles('#sys-file-reliability', FX('reliability.xml'), { timeout: 3000 });
        await page.click('#sys-analyze', { timeout: 3000 });
        await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
      } catch (e) { ok = false; }
      const step = await page.locator('#sys-step-reliability [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
      const res = ok ? await page.locator('#sys-results').innerText() : '';
      check('system: late-evening report keeps its local date (step message)', /saved 2026-10-17/.test(step), step);
      check('system: late-evening report keeps its local date (results)', ok && /2026-10-17/.test(res) && !/2026-10-18/.test(res), res.slice(0, 400));
      await context.close();
    }
    {
      const { page, context, seen } = await newPage('ok', { userAgent: WIN_UA });
      await page.setInputFiles('#sys-file-reliability', FX('battery-report.html'), { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const msg = await page.locator('#sys-step-reliability [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
      check('wrong file gives a clear message', /doesn.t look like a Reliability history file/i.test(msg), msg);
      await page.setInputFiles('#sys-file-msinfo', FX('msinfo32-de.txt'), { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const de = await page.locator('#sys-step-msinfo [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
      check('system: other-language report says so', /not in English\. PC Check reads English Windows reports only/i.test(de), de);
      check('system: language message does not promise the crash history works', !/crash history still works/i.test(de), de);
      await page.setInputFiles('#sys-file-reliability', FX('reliability-de.xml'), { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const relDe = await page.locator('#sys-step-reliability [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
      check('system: German crash history says only English reports are read', /not in English\. PC Check reads English Windows reports only/i.test(relDe), relDe);
      check('system: wrong file causes no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    for (const [label, opts, engineName] of [['375 px', { userAgent: WIN_UA, viewport: { width: 375, height: 812 } }, 'chromium'], ['iPhone', devices['iPhone 14'], 'webkit']]) {
      const eng = engineName === 'webkit' ? await webkit.launch() : browser;
      try {
        const { page, context, seen } = await newPage('ok', opts, eng);
        await waitBanner(page);
        if (engineName === 'webkit') {
          const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
          check('system: on a phone the banner says the steps are done on a computer', /computer/i.test(banner), banner);
          check('system: on a phone Windows is still pre-selected', (await pressed(page, 'windows')) === 'true');
        }
        let ok = true;
        try {
          await page.setInputFiles('#sys-file-reliability', FX('reliability.xml'), { timeout: 3000 });
          await page.setInputFiles('#sys-file-battery', FX('battery-report.html'), { timeout: 3000 });
          await page.click('#sys-analyze', { timeout: 3000 });
          await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
        } catch (e) { ok = false; }
        check('system: works at ' + label, ok);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        check('system: no horizontal scroll at ' + label, overflow <= 0, overflow);
        check('system: no page errors at ' + label, seen.errors.length === 0, seen.errors);
        await page.locator('#system').screenshot({ path: path.join(shots, engineName === 'webkit' ? 'system-iphone.png' : 'system-375.png') }).catch(() => {});
        await context.close();
      } finally {
        if (eng !== browser) await eng.close();
      }
    }
  }

  // 8c-linux. Linux paste steps in the System report panel: read-only commands, paste, Analyze on this device
  console.log('System report panel (Linux)');
  {
    const LX = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', f + '.txt'), 'utf8');
    const LINUX_UA = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
    const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
    const CMDS = {
      system: 'uname -a; cat /etc/os-release',
      journal: 'LC_ALL=C journalctl -b -p 3 -o short --no-pager',
      boots: 'LC_ALL=C journalctl --list-boots --no-pager | tail -5; LC_ALL=C journalctl -b -1 -p 3 -o short --no-pager',
      battery: 'upower -i $(upower -e | grep BAT)',
      disks: 'LC_ALL=C df -h; LC_ALL=C lsblk -o NAME,SIZE,TYPE,MOUNTPOINT'
    };
    const KINDS = Object.keys(CMDS);
    const UBUNTU = { system: 'ubuntu-system', journal: 'ubuntu-journal-boot', boots: 'boots-ubuntu', battery: 'upower-laptop', disks: 'df-ubuntu' };
    const planted = JSON.parse(fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', 'PLANTED.json'), 'utf8'));
    const PLANTED = [].concat(...Object.values(planted)).map((p) => String(p).toLowerCase());
    const leaks = (s) => PLANTED.filter((p) => s.toLowerCase().includes(p)).concat(/\/home\//.test(s) ? ['/home/'] : []);
    // About 2.5 MB of real journal lines: over the 2,000,000-character cap.
    const HUGE = (() => { const one = LX('ubuntu-journal-boot').replace(/\r\n/g, '\n'); let s = ''; while (s.length < 2500000) s += one; return s; })();
    const pressed = (page, os) => page.getAttribute('#sys-os-' + os, 'aria-pressed', { timeout: 2000 }).catch(() => null);
    const waitBanner = (page) => page.waitForFunction(() => (document.getElementById('sys-banner') || {}).textContent, null, { timeout: 5000 }).catch(() => {});
    const msg = (page, k) => page.locator('#sys-step-linux-' + k + ' [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
    const fill = (page, map) => page.evaluate((map) => {
      Object.keys(map).forEach((k) => { const ta = document.getElementById('sys-paste-' + k); if (ta) ta.value = map[k]; });
    }, map);
    const ubuntuTexts = () => Object.fromEntries(KINDS.map((k) => [k, LX(UBUNTU[k])]));
    const analyze = async (page) => {
      await page.click('#sys-linux-analyze', { timeout: 3000 });
      await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
    };

    {
      const { page, context, seen } = await newPage('ok', { userAgent: LINUX_UA, viewport: { width: 1280, height: 900 } });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('linux ui: Linux UA -> banner says Linux (Ubuntu) and five read-only commands', /You.re on Linux \(Ubuntu\)\. Run the five read-only commands below in a terminal and paste what they print\./.test(banner), banner);
      check('linux ui: Linux UA -> Linux button pre-selected', (await pressed(page, 'linux')) === 'true');
      check('linux ui: Linux button has no "Coming soon"', !/Coming soon/i.test(await page.locator('#sys-os-linux').innerText().catch(() => 'Coming soon')));
      check('linux ui: no button says "Coming soon"', !/Coming soon/i.test(await page.locator('.sys-os').innerText().catch(() => 'Coming soon')));
      check('linux ui: Linux steps shown, Windows and Mac steps hidden', await page.locator('#sys-linux-steps').isVisible().catch(() => false) &&
        !(await page.locator('#sys-steps').isVisible().catch(() => true)) && !(await page.locator('#sys-mac-steps').isVisible().catch(() => true)));
      const lead = await page.locator('#sys-lead').innerText().catch(() => '');
      check('linux ui: lead explains the Linux steps', /^Linux already keeps an error journal and knows your battery and disks\. Five read-only commands print it; paste their output below and PC Check reads it right here in your browser\. Nothing you paste leaves your device\.$/.test(lead.trim()), lead);
      const codes = await page.locator('#sys-linux-steps code').allInnerTexts();
      const want = KINDS.map((k) => CMDS[k]);
      check('linux ui: the five commands, exactly', codes.length === 5 && codes.every((c, i) => c === want[i]), codes);
      check('linux ui: no command writes or needs sudo', codes.every((c) => !/sudo|>|\brm\b|apt|dnf|tee|chmod/.test(c)), codes);
      check('linux ui: every locale-dependent command uses LC_ALL=C and every journalctl --no-pager',
        codes.filter((c) => /journalctl|df -h|lsblk/.test(c)).every((c) => /^LC_ALL=C /.test(c)) && codes.filter((c) => /journalctl/.test(c)).every((c) => (c.match(/journalctl/g) || []).length === (c.match(/--no-pager/g) || []).length), codes);
      let steps = true;
      for (const k of KINDS) {
        const li = page.locator('#sys-step-linux-' + k);
        const text = await li.innerText().catch(() => '');
        const ta = page.locator('#sys-paste-' + k);
        const attrs = await ta.evaluate((n) => [n.tagName, n.getAttribute('spellcheck'), n.getAttribute('autocomplete'), n.getAttribute('autocapitalize'), n.getAttribute('rows')].join(',')).catch(() => '');
        if (!/It only reads; it changes nothing\./.test(text) || attrs !== 'TEXTAREA,false,off,off,6' ||
          (await li.locator('.sys-copy[aria-controls="sys-cmd-linux-' + k + '"]').count()) !== 1 || (await li.locator('[data-role="msg"]').count()) !== 1) { steps = false; console.log('    step ' + k + ': ' + attrs); }
      }
      check('linux ui: each step says it only reads, has a copy button, a textarea and a message line', steps);
      const guide = await page.locator('#sys-linux-steps').innerText().catch(() => '');
      check('linux ui: each command is explained', /kernel version and which Linux you run/.test(guide) && /LC_ALL=C makes this one command print in English/.test(guide) &&
        /last five start-ups/.test(guide) && /On a desktop it prints nothing; leave the box empty/.test(guide) && /how full each disk is/.test(guide) &&
        /your account can only see part of the log; the results will say so/.test(guide), guide.slice(0, 300));

      await page.click('#sys-linux-analyze', { timeout: 3000 }).catch(() => {});
      const need = await page.locator('#sys-linux-status').innerText({ timeout: 2000 }).catch(() => '');
      check('linux ui: all boxes empty -> asks for a paste', /Paste at least one output first\. Step 2 tells the most\./.test(need) && !(await page.locator('#sys-results').isVisible()), need);

      const before = await page.locator('#ledger-list li').count();
      await fill(page, ubuntuTexts());
      let ok = true;
      try { await analyze(page); } catch (e) { ok = false; }
      check('linux ui: Ubuntu outputs analyzed', ok);
      const score = ok ? (await page.locator('#sys-score').innerText()).trim() : '';
      check('linux ui: Ubuntu score 25', score === '25', score);
      const res = ok ? await page.locator('#sys-results').innerText() : '';
      check('linux ui: findings mention amdgpu and 93 %', /amdgpu/.test(res) && /93 %/.test(res), res.slice(0, 400));
      check('linux ui: date line says logs, read on this device', /Logs from 2026-10-18 · read on this device, nothing uploaded/.test(res), res.slice(0, 300));
      check('linux ui: no planted identifier in the results', leaks(res).length === 0, leaks(res));
      const reads = [];
      for (const k of KINDS) reads.push(await msg(page, k));
      check('linux ui: every step says Read:', reads.every((m) => /^Read: /.test(m)), reads);
      check('linux ui: step messages carry no planted identifier', leaks(reads.join('\n')).length === 0, leaks(reads.join('\n')));
      check('linux ui: Analyze sends nothing (outbound log unchanged)', (await page.locator('#ledger-list li').count()) === before);
      check('linux ui: Analyze makes no outside requests', seen.external.length === 0, seen.external);
      check('linux ui: "Explain with AI" offered for Linux', (await page.locator('#sys-ai-open').count()) === 1);
      await page.locator('#system').screenshot({ path: path.join(shots, 'system-linux-desktop.png') }).catch(() => {});

      await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
      check('linux ui: Linux results hidden while Windows is selected', !(await page.locator('#sys-results').isVisible().catch(() => true)) && await page.locator('#sys-steps').isVisible().catch(() => false));
      const winLead = await page.locator('#sys-lead').innerText().catch(() => '');
      check('linux ui: Windows lead unchanged', /^Windows already keeps a crash history, a battery report and a system summary\./.test(winLead.trim()), winLead);
      await page.click('#sys-os-linux', { timeout: 2000 }).catch(() => {});
      check('linux ui: switching back keeps the pasted text and the results', (await page.locator('#sys-paste-journal').inputValue().catch(() => '')).length > 100 &&
        await page.locator('#sys-results').isVisible().catch(() => false));

      await page.click('#sys-linux-clear', { timeout: 2000 }).catch(() => {});
      const values = await Promise.all(KINDS.map((k) => page.locator('#sys-paste-' + k).inputValue().catch(() => 'x')));
      check('linux ui: Clear empties all five boxes and the results', values.every((v) => v === '') && !(await page.locator('#sys-results').isVisible().catch(() => true)), values.map((v) => v.length));
      const cleared = [];
      for (const k of KINDS) cleared.push(await msg(page, k));
      check('linux ui: Clear empties the step messages', cleared.every((m) => !m.trim()), cleared);
      check('linux ui: no page errors', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    {
      // Wrong box, other language, empty battery box
      const { page, context, seen } = await newPage('ok', { userAgent: LINUX_UA });
      await waitBanner(page);
      await fill(page, { system: LX('ubuntu-system'), journal: LX('df-ubuntu'), boots: '', battery: '', disks: LX('df-de') });
      await page.click('#sys-linux-analyze', { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const wrong = await msg(page, 'journal');
      check('linux ui: df output in the journal box -> wrong box, step 5', /This doesn.t look like the output of this command\. It looks like the output for step 5\./.test(wrong), wrong);
      const bat = await msg(page, 'battery');
      check('linux ui: empty battery box -> no battery reported', /No battery reported \(fine for a desktop\)\./.test(bat), bat);
      const foreign = await msg(page, 'disks');
      check('linux ui: df in another language -> not in English', /This output isn.t in English\. Run the command exactly as shown: it starts with LC_ALL=C, which makes it print in English\./.test(foreign), foreign);
      await fill(page, { journal: LX('journal-de'), disks: '' });
      await page.click('#sys-linux-analyze', { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const de = await msg(page, 'journal');
      check('linux ui: German journal -> not in English', /This output isn.t in English\./.test(de), de);
      await fill(page, { system: '', journal: LX('boots-ubuntu') });
      await page.click('#sys-linux-analyze', { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const bootsInJournal = await msg(page, 'journal');
      check('linux ui: boot list in the journal box -> step 3', /It looks like the output for step 3\./.test(bootsInJournal), bootsInJournal);
      check('linux ui: wrong pastes cause no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    {
      // A huge paste is cut at 2,000,000 characters and the page stays quick
      const { page, context, seen } = await newPage('ok', { userAgent: LINUX_UA, viewport: { width: 1280, height: 900 } });
      await waitBanner(page);
      await fill(page, { journal: HUGE });
      const t0 = Date.now();
      let ok = true;
      try { await analyze(page); } catch (e) { ok = false; }
      const ms = Date.now() - t0;
      const m = await msg(page, 'journal');
      check('linux ui: huge paste is cut and says so', ok && /Only the first 2 MB were read\./.test(m), m);
      check('linux ui: huge paste analyzed in < 3 s', ok && ms < 3000, ms);
      check('linux ui: huge paste causes no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    {
      // Copy buttons copy the exact command (Chromium clipboard)
      const { page, context, seen } = await newPage('ok', { userAgent: LINUX_UA, permissions: ['clipboard-read', 'clipboard-write'] });
      await waitBanner(page);
      const copied = [];
      for (const k of KINDS) {
        await page.click('#sys-step-linux-' + k + ' .sys-copy', { timeout: 2000 }).catch(() => {});
        await page.waitForTimeout(50);
        copied.push(await page.evaluate(() => navigator.clipboard.readText()).catch(() => null));
      }
      check('linux ui: copy buttons copy the exact commands', copied.every((c, i) => c === CMDS[KINDS[i]]), copied);
      check('linux ui: copy causes no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    for (const [label, ua, want] of [['Fedora', 'Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0', /You.re on Linux \(Fedora\)/],
      ['Android', 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + fullVersion + ' Mobile Safari/537.36', /You.re on Android/],
      ['ChromeOS', 'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + fullVersion + ' Safari/537.36', /Pick the system/]]) {
      const { page, context } = await newPage('ok', { userAgent: ua });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('linux ui: ' + label + ' UA banner', want.test(banner), banner);
      if (label !== 'Fedora') check('linux ui: ' + label + ' UA does not pre-select Linux', (await pressed(page, 'linux')) === 'false');
      await context.close();
    }
    {
      const { page, context } = await newPage('ok', { userAgent: MAC_UA });
      await waitBanner(page);
      check('linux ui: Mac UA shows the Mac steps, not the Linux ones', await page.locator('#sys-mac-steps').isVisible().catch(() => false) && !(await page.locator('#sys-linux-steps').isVisible().catch(() => true)));
      await context.close();
    }
    for (const [label, opts, engineName] of [['375 px', { userAgent: LINUX_UA, viewport: { width: 375, height: 812 } }, 'chromium'], ['iPhone', devices['iPhone 14'], 'webkit']]) {
      const eng = engineName === 'webkit' ? await webkit.launch() : browser;
      try {
        const { page, context, seen } = await newPage('ok', opts, eng);
        await waitBanner(page);
        await page.click('#sys-os-linux', { timeout: 2000 }).catch(() => {});
        if (engineName === 'webkit') {
          // The selection fallback is used where the clipboard is refused: it must not throw.
          await page.click('#sys-step-linux-journal .sys-copy', { timeout: 2000 }).catch(() => {});
          await page.waitForTimeout(100);
        }
        const texts = ubuntuTexts();
        texts.journal = HUGE;
        await fill(page, texts);
        let ok = true;
        try { await analyze(page); } catch (e) { ok = false; }
        check('linux ui: works at ' + label, ok);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        check('linux ui: no horizontal scroll at ' + label + ' with a 2.5 MB paste', overflow <= 0, overflow);
        check('linux ui: no page errors at ' + label, seen.errors.length === 0, seen.errors);
        await page.locator('#system').screenshot({ path: path.join(shots, engineName === 'webkit' ? 'system-linux-iphone.png' : 'system-linux-375.png') }).catch(() => {});
        await context.close();
      } finally {
        if (eng !== browser) await eng.close();
      }
    }
  }

  // 8c-mac. Mac file steps in the System report panel: GUI-only guide (no Terminal), files read on this device only
  console.log('System report panel (Mac)');
  {
    const MFX = (f) => path.join(here, '..', 'fixtures', 'sys', 'mac', f);
    const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15';
    const SET_A = { spx: 'silicon.spx', reports: ['panic-full-2026-10-02-081533.0001.panic', 'panic-full-2026-10-14-224107.0002.panic',
      'Google Chrome Helper (Renderer)-2026-10-15-091244.ips', 'Google Chrome Helper (Renderer)-2026-10-16-200103.ips', 'JetsamEvent-2026-10-17-130512.ips'] };
    const SET_B = { spx: 'intel.spx', reports: ['Kernel-2026-08-20-101500.panic', 'Kernel-2026-10-09-213301.panic',
      'Microsoft Word-2026-10-12-110204.ips', 'Microsoft Word-2026-10-16-153012.ips', 'Safari_2026-10-01-090909_Priyas-iMac.crash'] };
    const planted = JSON.parse(fs.readFileSync(MFX('PLANTED.json'), 'utf8'));
    const PLANTED = [].concat(...Object.values(planted)).map((p) => String(p).toLowerCase());
    const FILE_BITS = ['panic-full-', 'kernel-2026', 'google chrome helper (renderer)-', 'priyas-imac', '.ips', '.spx'];
    const leaks = (s) => { const l = String(s).toLowerCase(); return PLANTED.concat(FILE_BITS).filter((p) => l.includes(p)); };
    const FORBIDDEN = /sudo|system_profiler|csrutil|diskutil|pmset|defaults |log show|ioreg/;
    const pressed = (page, os) => page.getAttribute('#sys-os-' + os, 'aria-pressed', { timeout: 2000 }).catch(() => null);
    const waitBanner = (page) => page.waitForFunction(() => (document.getElementById('sys-banner') || {}).textContent, null, { timeout: 5000 }).catch(() => {});
    const msg = (page, k) => page.locator('#sys-step-mac-' + k + ' [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
    // A step is done reading once its state is "ok" or "error".
    const settled = (page, k) => page.waitForFunction((k) => /^(ok|error)$/.test((document.getElementById('sys-step-mac-' + k) || { getAttribute: () => '' }).getAttribute('data-state') || ''), k, { timeout: 10000 }).catch(() => {});
    const choose = async (page, set) => {
      if (set.spx) { await page.setInputFiles('#sys-file-mac-spx', MFX(set.spx), { timeout: 3000 }); await settled(page, 'spx'); }
      if (set.reports) { await page.setInputFiles('#sys-file-mac-crash', set.reports.map(MFX), { timeout: 3000 }); await settled(page, 'crash'); }
    };
    const analyze = async (page) => {
      await page.click('#sys-mac-analyze', { timeout: 3000 });
      await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
    };
    const shownText = (page) => page.evaluate(() => ['#sys-results', '#sys-banner', '#sys-status', '#sys-mac-status'].map((s) => (document.querySelector(s) || {}).innerText || '')
      .concat(Array.from(document.querySelectorAll('#system [data-role="msg"]')).map((n) => n.innerText)).join('\n'));

    {
      const { page, context, seen } = await newPage('ok', { userAgent: MAC_UA, viewport: { width: 1280, height: 900 } });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('mac ui: Mac UA -> banner says macOS, no Terminal needed', /^You.re on macOS\. Save the reports with apps already on your Mac and choose them below\. No Terminal needed\.$/.test(banner.trim()), banner);
      check('mac ui: Mac UA -> Mac button pre-selected', (await pressed(page, 'mac')) === 'true');
      check('mac ui: no "Coming soon" tag or box is left', (await page.locator('.sys-soon-tag').count()) === 0 && (await page.locator('#sys-soon').count()) === 0 &&
        !/Coming soon/i.test(await page.locator('#system').innerText().catch(() => 'Coming soon')));
      check('mac ui: Mac steps shown, Windows and Linux steps hidden', await page.locator('#sys-mac-steps').isVisible().catch(() => false) &&
        !(await page.locator('#sys-steps').isVisible().catch(() => true)) && !(await page.locator('#sys-linux-steps').isVisible().catch(() => true)));
      const lead = await page.locator('#sys-lead').innerText().catch(() => '');
      check('mac ui: lead explains the Mac steps', /^Your Mac already keeps a system profile and a record of crashes and unexpected restarts\. Save them with System Information and Finder, then choose the files below: PC Check reads them right here in your browser\. Nothing leaves your device\.$/.test(lead.trim()), lead);
      const codes = await page.locator('#sys-mac-steps code').allInnerTexts();
      check('mac ui: the only <code> elements are the two folder paths', codes.length === 2 && codes[0] === '/Library/Logs/DiagnosticReports' && codes[1] === '~/Library/Logs/DiagnosticReports', codes);
      const guide = await page.locator('#sys-mac-steps').innerText().catch(() => '');
      const all = [guide, lead, banner].join('\n');
      check('mac ui: no Terminal command anywhere in the Mac guide, lead or banner', !FORBIDDEN.test(all), all.match(FORBIDDEN));
      check('mac ui: "Terminal" appears only in "No Terminal needed"', !/Terminal/i.test(all.replace(/No Terminal needed/g, '')), (all.replace(/No Terminal needed/g, '').match(/.{0,30}Terminal.{0,30}/i) || [])[0]);
      check('mac ui: GUI-only steps (System Information, File > Save, Go to Folder, Console)', /Hold the Option key and click the Apple menu/.test(guide) && /File > Save/.test(guide) &&
        /Go > Go to Folder/.test(guide) && /Go to Folder is a Finder window, not a command line\./.test(guide) && /open the Console app \(Applications > Utilities\), choose Crash Reports/.test(guide) &&
        /An empty folder means no crashes were recorded\./.test(guide) && /keeps none of the rest/.test(guide), guide.slice(0, 400));
      const html = await page.content();
      check('mac ui: no Apple-logo character on the page', !/\uF8FF/.test(html));
      const inputs = await page.evaluate(() => {
        const a = document.getElementById('sys-file-mac-spx'); const b = document.getElementById('sys-file-mac-crash');
        return a && b ? [a.type, a.accept, a.multiple, b.type, b.accept, b.multiple] : null;
      });
      check('mac ui: .spx input and a multi-file report input', !!inputs && inputs[0] === 'file' && inputs[1] === '.spx,application/xml,text/xml' && inputs[2] === false &&
        inputs[3] === 'file' && inputs[4] === '.ips,.panic,.crash' && inputs[5] === true, inputs);
      check('mac ui: each step has one message line; two copy buttons for the two paths', (await page.locator('#sys-step-mac-spx [data-role="msg"]').count()) === 1 &&
        (await page.locator('#sys-step-mac-crash [data-role="msg"]').count()) === 1 &&
        (await page.locator('#sys-step-mac-crash .sys-copy[aria-controls="sys-path-mac-system"]').count()) === 1 &&
        (await page.locator('#sys-step-mac-crash .sys-copy[aria-controls="sys-path-mac-user"]').count()) === 1);
      const copyLabels = await page.evaluate(() => ['system', 'user'].map((k) => (document.querySelector('.sys-copy[aria-controls="sys-path-mac-' + k + '"]') || { getAttribute: () => null }).getAttribute('aria-label')));
      check('mac ui: the two Copy buttons have distinct accessible names', copyLabels[0] === 'Copy system folder path' && copyLabels[1] === 'Copy user folder path', copyLabels);
      check('mac ui: the phone line is hidden on a Mac', (await page.locator('#sys-mac-phone').count()) === 1 && !(await page.locator('#sys-mac-phone').isVisible().catch(() => true)));

      await page.click('#sys-mac-analyze', { timeout: 3000 }).catch(() => {});
      const need = await page.locator('#sys-mac-status').innerText({ timeout: 2000 }).catch(() => '');
      check('mac ui: nothing chosen -> asks for a file', /^Choose at least one file first\. Step 1 tells the most\.$/.test(need.trim()) && !(await page.locator('#sys-results').isVisible()), need);

      const before = await page.locator('#ledger-list li').count();
      let ok = true;
      try { await choose(page, SET_A); await analyze(page); } catch (e) { ok = false; }
      check('mac ui: Set A chosen and analyzed', ok);
      const m1 = await msg(page, 'spx');
      check('mac ui: step 1 says Read: System Information from <date>', /^Read: System Information from \d{4}-\d\d-\d\d\.$/.test(m1.trim()), m1);
      const m2 = await msg(page, 'crash');
      check('mac ui: step 2 counts 2 panics, 2 app crashes, 1 skipped', m2.trim() === 'Read 4 reports: 2 panics, 2 app crashes. 1 file was skipped (not a crash or panic report).', m2);
      const score = ok ? (await page.locator('#sys-score').innerText()).trim() : '';
      check('mac ui: Set A score 55', score === '55', score);
      const res = ok ? await page.locator('#sys-results').innerText() : '';
      check('mac ui: Set A findings mention kernel panic and 91.9 %', /kernel panic/i.test(res) && /91\.9 %/.test(res), res.slice(0, 400));
      check('mac ui: date line says System Information, read on this device', /System Information from \d{4}-\d\d-\d\d · read on this device, nothing uploaded/.test(res), res.slice(0, 300));
      const shownA = await shownText(page);
      check('mac ui: file names are never shown (Set A)', leaks(shownA).length === 0, leaks(shownA));
      check('mac ui: Analyze sends nothing (outbound log unchanged)', (await page.locator('#ledger-list li').count()) === before);
      check('mac ui: Analyze makes no outside requests', seen.external.length === 0, seen.external);
      check('mac ui: "Explain with AI" offered for Mac, disclosure not shown before the click', await page.locator('#sys-ai-open').isVisible().catch(() => false) &&
        !(await page.locator('#sys-ai-disclosure').isVisible().catch(() => false)));
      check('mac ui: PDF button shown for the Mac results', await page.locator('#pdf').isVisible().catch(() => false));
      await page.locator('#system').screenshot({ path: path.join(shots, 'system-mac-desktop.png') }).catch(() => {});

      await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
      check('mac ui: Mac results hidden while Windows is selected', !(await page.locator('#sys-results').isVisible().catch(() => true)) && await page.locator('#sys-steps').isVisible().catch(() => false));
      await page.click('#sys-os-linux', { timeout: 2000 }).catch(() => {});
      const lxLead = await page.locator('#sys-lead').innerText().catch(() => '');
      check('mac ui: Linux lead unchanged', /^Linux already keeps an error journal/.test(lxLead.trim()) && !(await page.locator('#sys-results').isVisible().catch(() => true)), lxLead);
      await page.click('#sys-os-mac', { timeout: 2000 }).catch(() => {});
      check('mac ui: switching back keeps the chosen files and the results', await page.locator('#sys-results').isVisible().catch(() => false) &&
        (await msg(page, 'crash')).trim() === m2.trim() && (await msg(page, 'spx')).trim() === m1.trim());

      ok = true;
      try { await choose(page, SET_B); await analyze(page); } catch (e) { ok = false; }
      check('mac ui: Set B chosen and analyzed', ok);
      const scoreB = ok ? (await page.locator('#sys-score').innerText()).trim() : '';
      check('mac ui: Set B score 20', scoreB === '20', scoreB);
      const resB = ok ? await page.locator('#sys-results').innerText() : '';
      check('mac ui: Set B: no battery, SMART, macOS 13', /No battery reported/.test(resB) && /SMART/.test(resB) && /macOS 13/.test(resB), resB.slice(0, 400));
      const shownB = await shownText(page);
      check('mac ui: file names are never shown (Set B)', leaks(shownB).length === 0, leaks(shownB));
      check('mac ui: still nothing in the outbound log', (await page.locator('#ledger-list li').count()) === before);

      await page.click('#sys-mac-clear', { timeout: 2000 }).catch(() => {});
      const c1 = await msg(page, 'spx'); const c2 = await msg(page, 'crash');
      const states = await page.evaluate(() => ['spx', 'crash'].map((k) => (document.getElementById('sys-step-mac-' + k) || { getAttribute: () => null }).getAttribute('data-state')));
      check('mac ui: Clear empties both steps and the results', !c1.trim() && !c2.trim() && states.join(',') === 'empty,empty' && !(await page.locator('#sys-results').isVisible().catch(() => true)), [c1, c2, states]);
      await page.click('#sys-mac-analyze', { timeout: 3000 }).catch(() => {});
      check('mac ui: after Clear, Analyze asks for a file again', /Choose at least one file first/.test(await page.locator('#sys-mac-status').innerText().catch(() => '')));
      check('mac ui: no page errors', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    {
      // Chromium tells the macOS version through userAgentData; the user-agent string is frozen at 10_15_7.
      const { page, context } = await newPage('ok', { userAgent: MAC_UA,
        initScript: 'Object.defineProperty(Navigator.prototype, "userAgentData", { configurable: true, get: () => ({ platform: "macOS", getHighEntropyValues: () => Promise.resolve({ platformVersion: "15.1.0" }) }) });' });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('mac ui: userAgentData 15.1.0 -> banner says macOS 15', /You.re on macOS 15\. Save the reports/.test(banner), banner);
      await context.close();
    }
    {
      // Reports only (no .spx): the date is the newest report's
      const { page, context, seen } = await newPage('ok', { userAgent: MAC_UA, timezoneId: 'Europe/Dublin' });
      await waitBanner(page);
      let ok = true;
      try { await choose(page, { reports: SET_A.reports }); await analyze(page); } catch (e) { ok = false; }
      const res = ok ? await page.locator('#sys-results').innerText() : '';
      check('mac ui: reports only -> Newest report from 2026-10-16', /Newest report from 2026-10-16 · read on this device, nothing uploaded/.test(res), res.slice(0, 300));
      check('mac ui: reports only -> no page errors', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    {
      // Wrong files, too big, too many
      const { page, context, seen } = await newPage('ok', { userAgent: MAC_UA });
      await waitBanner(page);
      await page.setInputFiles('#sys-file-mac-spx', path.join(here, '..', 'fixtures', 'sys', 'battery-report.html'), { timeout: 3000 }).catch(() => {});
      await settled(page, 'spx');
      const win = await msg(page, 'spx');
      check('mac ui: Windows battery report in step 1 -> not System Information', /doesn.t look like a System Information \(\.spx\) file\.$/.test(win.trim()), win);
      await page.setInputFiles('#sys-file-mac-spx', MFX(SET_A.reports[2]), { timeout: 3000 }).catch(() => {});
      await settled(page, 'spx');
      const ips = await msg(page, 'spx');
      check('mac ui: crash report in step 1 -> use step 2', /doesn.t look like a System Information \(\.spx\) file\. It looks like a crash report; use step 2\./.test(ips), ips);
      await page.setInputFiles('#sys-file-mac-spx', MFX('sysinfo-text.txt'), { timeout: 3000 }).catch(() => {});
      await settled(page, 'spx');
      const txt = await msg(page, 'spx');
      check('mac ui: text export in step 1 -> choose File > Save', /This is the text version\. In System Information choose File > Save… instead; it saves a \.spx file\./.test(txt), txt);
      await page.setInputFiles('#sys-file-mac-crash', MFX('silicon.spx'), { timeout: 3000 }).catch(() => {});
      await settled(page, 'crash');
      const spxIn2 = await msg(page, 'crash');
      check('mac ui: .spx in step 2 -> none is a report, use step 1', /^None of these files is a crash or panic report\. Look for names ending in \.panic, \.ips or \.crash\. One of them looks like the System Information file; use step 1\.$/.test(spxIn2.trim()), spxIn2);
      await page.click('#sys-mac-analyze', { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(200);
      check('mac ui: only unusable files -> nothing could be read, no results', /Nothing could be read/.test(await page.locator('#sys-mac-status').innerText().catch(() => '')) &&
        !(await page.locator('#sys-results').isVisible().catch(() => true)));
      await page.setInputFiles('#sys-file-mac-spx', { name: 'big.spx', mimeType: 'application/xml', buffer: Buffer.alloc(41 * 1024 * 1024, 0x20) }, { timeout: 10000 }).catch(() => {});
      await settled(page, 'spx');
      const big = await msg(page, 'spx');
      check('mac ui: 41 MB .spx -> too big', /larger than 40 MB/.test(big), big);
      const one = fs.readFileSync(MFX(SET_A.reports[2]));
      const many = Array.from({ length: 101 }, () => ({ name: 'crash.ips', mimeType: 'application/octet-stream', buffer: one }));
      await page.setInputFiles('#sys-file-mac-crash', many, { timeout: 10000 }).catch(() => {});
      await settled(page, 'crash');
      const capped = await msg(page, 'crash');
      check('mac ui: 101 files -> only the first 100 read, 100 app crashes', /100 app crashes/.test(capped) && /Only the first 100 files were read\./.test(capped), capped);
      check('mac ui: wrong files cause no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    {
      // Singular forms, unreadable files and the read concurrency limit. The spy counts reads in flight and can fail the next N reads.
      const READ_SPY = `(() => { const orig = FileReader.prototype.readAsArrayBuffer; const R = window.__reads = { now: 0, max: 0, failNext: 0 };
        FileReader.prototype.readAsArrayBuffer = function (blob) {
          R.now++; R.max = Math.max(R.max, R.now);
          if (R.failNext > 0) { R.failNext--; const self = this; setTimeout(() => { R.now--; if (self.onerror) self.onerror(new Event('error')); }, 20); return; }
          // Counted as finished just before the page's own handler runs (it may start the next read at once).
          ['onload', 'onerror'].forEach((k) => { const h = this[k]; this[k] = function () { R.now--; return h && h.apply(this, arguments); }; });
          return orig.call(this, blob);
        }; })();`;
      const { page, context, seen } = await newPage('ok', { userAgent: MAC_UA, initScript: READ_SPY });
      await waitBanner(page);
      await choose(page, { reports: [SET_A.reports[0]] });
      const onePanic = (await msg(page, 'crash')).trim();
      check('mac ui: singular -> "Read 1 report: 1 panic, 0 app crashes."', onePanic === 'Read 1 report: 1 panic, 0 app crashes.', onePanic);
      await choose(page, { reports: [SET_A.reports[2], SET_A.reports[4]] });
      const oneCrash = (await msg(page, 'crash')).trim();
      check('mac ui: singular -> "1 app crash", "1 file was skipped"', oneCrash === 'Read 1 report: 0 panics, 1 app crash. 1 file was skipped (not a crash or panic report).', oneCrash);
      await page.evaluate(() => { window.__reads.failNext = 1; });
      await choose(page, { reports: [SET_A.reports[2]] });
      const oneBad = (await msg(page, 'crash')).trim();
      check('mac ui: one unreadable file -> only the unreadable sentence (singular)', oneBad === 'macOS didn\u2019t let the browser read 1 file. Copy it to your Desktop first, then choose the copy.', oneBad);
      await page.evaluate(() => { window.__reads.failNext = 2; });
      await choose(page, { reports: [SET_A.reports[2], SET_A.reports[3]] });
      const twoBad = (await msg(page, 'crash')).trim();
      check('mac ui: every file unreadable -> only the unreadable sentence (plural)', twoBad === 'macOS didn\u2019t let the browser read 2 files. Copy them to your Desktop first, then choose the copies.', twoBad);
      await page.evaluate(() => { window.__reads.failNext = 1; });
      await choose(page, { reports: [SET_A.reports[0], SET_A.reports[2], SET_A.reports[3]] });
      const mixed = (await msg(page, 'crash')).trim();
      check('mac ui: some files unreadable -> counts plus the unreadable sentence', /^Read 2 reports: /.test(mixed) && / macOS didn\u2019t let the browser read 1 file\./.test(mixed), mixed);
      await page.evaluate(() => { window.__reads.max = 0; });
      const one = fs.readFileSync(MFX(SET_A.reports[2]));
      await page.setInputFiles('#sys-file-mac-crash', Array.from({ length: 40 }, () => ({ name: 'crash.ips', mimeType: 'application/octet-stream', buffer: one })), { timeout: 10000 }).catch(() => {});
      await settled(page, 'crash');
      const forty = (await msg(page, 'crash')).trim();
      const max = await page.evaluate(() => window.__reads.max);
      check('mac ui: 40 files are read at most 8 at a time, all of them', /^Read 40 reports: 0 panics, 40 app crashes\.$/.test(forty) && max >= 2 && max <= 8, [forty, max]);
      check('mac ui: unreadable files cause no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    for (const [label, opts, engineName] of [['375 px', { userAgent: MAC_UA, viewport: { width: 375, height: 812 } }, 'chromium'], ['iPhone', devices['iPhone 14'], 'webkit']]) {
      const eng = engineName === 'webkit' ? await webkit.launch() : browser;
      try {
        const { page, context, seen } = await newPage('ok', opts, eng);
        await waitBanner(page);
        await page.click('#sys-os-mac', { timeout: 2000 }).catch(() => {});
        if (engineName === 'webkit') {
          check('mac ui: on a phone, a line says to do the steps on the Mac', /^Do these steps on the Mac\. You can read them here and open this page on the Mac later\.$/.test((await page.locator('#sys-mac-phone').innerText({ timeout: 2000 }).catch(() => '')).trim()));
          await page.click('#sys-step-mac-crash .sys-copy', { timeout: 2000 }).catch(() => {});
          await page.waitForTimeout(100);
        }
        let ok = true;
        try { await choose(page, SET_A); await analyze(page); } catch (e) { ok = false; }
        check('mac ui: works at ' + label, ok && (await page.locator('#sys-score').innerText()).trim() === '55');
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        check('mac ui: no horizontal scroll at ' + label + ' with the Mac steps open', overflow <= 0, overflow);
        check('mac ui: no page errors at ' + label, seen.errors.length === 0, seen.errors);
        await page.locator('#system').screenshot({ path: path.join(shots, engineName === 'webkit' ? 'system-mac-iphone.png' : 'system-mac-375.png') }).catch(() => {});
        await context.close();
      } finally {
        if (eng !== browser) await eng.close();
      }
    }
  }

  // 8d. Explain with AI: disclosure first, exact summary sent, ledger entry, text-only rendering, errors, PDF
  console.log('Explain with AI');
  {
    const FX = (f) => path.join(here, '..', 'fixtures', 'sys', f);
    const WIN_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/' + fullVersion + ' Safari/537.36';
    const DISCLOSURE = 'Optional: send this anonymised summary to Claude (Anthropic) through cybersecinfo.com to get a plain-English explanation. Only the summary below is sent — not your files. Nothing is stored.';
    const DISCLOSURE_LINUX = 'Optional: send this anonymised summary to Claude (Anthropic) through cybersecinfo.com to get a plain-English explanation. Only the summary below is sent — not your files or pasted text. Nothing is stored.';
    // Planted personal data: computer and user name, plus a model name whose emoji straddles the 80-character cut.
    const LONG_MODEL = 'Predator PTN16-51 ' + 'z'.repeat(61) + '\u{1F600} edition';
    const msiPlanted = {
      name: 'msinfo.txt', mimeType: 'text/plain',
      buffer: Buffer.from(fs.readFileSync(FX('msinfo32-head.txt')).toString('utf16le')
        .split('PC-NAME\\USER').join('DESKTOP-JD123\\JohnDoe').split('PC-NAME').join('DESKTOP-JD123')
        .replace('Predator PTN16-51', LONG_MODEL), 'utf16le')
    };
    const PERSONAL = /PC-NAME|DESKTOP-JD123|JohnDoe|C:\\{1,2}Users/i;
    const lone = (s) => /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(^|[^\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
    const EXPLANATION = 'Your PC is mostly fine. <b>bold</b> <img src=x onerror="window.__xss=1">\n\nSecond paragraph: update the drivers.';

    async function analyzed(opts = {}, engine = browser) {
      const made = await newPage('ok', Object.assign({ userAgent: WIN_UA, viewport: { width: 1280, height: 900 } }, opts), engine);
      const { page } = made;
      await page.setInputFiles('#sys-file-reliability', FX('reliability.xml'), { timeout: 3000 });
      await page.setInputFiles('#sys-file-battery', FX('battery-report.html'), { timeout: 3000 });
      await page.setInputFiles('#sys-file-msinfo', msiPlanted, { timeout: 3000 });
      await page.click('#sys-analyze', { timeout: 3000 });
      await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
      return made;
    }
    // mock.mode: 'ok' | 429 | 'daily' | 503 | 502 | 500 | 'abort'
    async function mockExplain(page, mock) {
      mock.bodies = [];
      mock.headers = [];
      await page.route(/\/api\/explain\.php/, async (r) => {
        mock.bodies.push(r.request().postData());
        mock.headers.push(await r.request().allHeaders());
        await new Promise((res) => setTimeout(res, mock.delay || 0));
        const json = (status, body) => r.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
        if (mock.mode === 'ok') return json(200, { explanation: EXPLANATION, model: 'claude-haiku-5-5' });
        if (mock.mode === 429) return json(429, { error: 'rate_limited' });
        if (mock.mode === 'daily') return json(429, { error: 'daily_limit' });
        if (mock.mode === 503) return json(503, { error: 'not_configured' });
        if (mock.mode === 502) return json(502, { error: 'upstream' });
        if (mock.mode === 500) return r.fulfill({ status: 500, contentType: 'text/html', body: '<h1>oops</h1>' });
        return r.abort();
      });
    }
    const errText = (page) => page.locator('#sys-ai-error').innerText({ timeout: 2000 }).catch(() => '');
    const waitErr = (page) => page.waitForFunction(() => { const e = document.getElementById('sys-ai-error'); return e && e.textContent.trim(); }, null, { timeout: 5000 }).catch(() => {});

    {
      let ok = true;
      let made;
      // Records the fetch options used for explain.php: the Origin header the server checks depends on them.
      const FETCH_SPY = `(() => { const f = window.fetch; window.__explainInits = [];
        window.fetch = function (url, init) { if (/explain\.php/.test(String(url))) window.__explainInits.push(Object.assign({}, init || {}, { body: undefined, signal: undefined })); return f.apply(this, arguments); }; })();`;
      try { made = await analyzed({ initScript: FETCH_SPY }); } catch (e) { ok = false; }
      check('ai: setup (fixtures analyzed)', ok);
      if (made) {
        const { page, context, seen } = made;
        const mock = { mode: 'ok', delay: 400 };
        await mockExplain(page, mock);
        check('ai: "Explain with AI" button appears after Analyze', await page.locator('#sys-ai-open').isVisible().catch(() => false));
        check('ai: PDF button available after Analyze alone', await page.locator('#pdf').isVisible().catch(() => false));
        check('ai: disclosure not shown before the click', !(await page.locator('#sys-ai-disclosure').isVisible().catch(() => false)));
        const before = await page.locator('#ledger-list li').count();
        await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
        const disc = await page.locator('#sys-ai-disclosure').innerText({ timeout: 2000 }).catch(() => '');
        check('ai: exact disclosure shown before sending', disc.trim() === DISCLOSURE, disc);
        const shownText = await page.locator('#sys-ai-summary').innerText({ timeout: 2000 }).catch(() => '');
        let shown = null;
        try { shown = JSON.parse(shownText); } catch (e) { /* stays null */ }
        check('ai: the summary JSON is shown before sending', shown !== null && typeof shown.score === 'number', shownText.slice(0, 200));
        check('ai: nothing sent and nothing logged before Send', mock.bodies.length === 0 && (await page.locator('#ledger-list li').count()) === before);
        await page.click('#sys-ai-send', { timeout: 2000 }).catch(() => {});
        await page.waitForTimeout(100);
        check('ai: Send disabled while in flight', await page.locator('#sys-ai-send').isDisabled().catch(() => false));
        await page.locator('#sys-ai-send').click({ force: true, timeout: 500 }).catch(() => {});
        await page.evaluate(() => { const b = document.getElementById('sys-ai-send'); if (b) b.click(); });
        await page.waitForSelector('#sys-ai-text p', { timeout: 5000 }).catch(() => {});
        check('ai: exactly one request despite repeated clicks', mock.bodies.length === 1, mock.bodies.length);
        let body = null;
        try { body = JSON.parse(mock.bodies[0]); } catch (e) { /* stays null */ }
        check('ai: request body is exactly {summary}', body !== null && JSON.stringify(Object.keys(body)) === '["summary"]', mock.bodies[0]);
        check('ai: request body equals the summary shown', body !== null && JSON.stringify(body.summary) === JSON.stringify(shown), [mock.bodies[0], shownText]);
        check('ai: no planted personal data in the request', !!mock.bodies[0] && !PERSONAL.test(mock.bodies[0]) && !PERSONAL.test(shownText), mock.bodies[0]);
        check('ai: no lone surrogate in the summary (emoji at the cut)', body !== null && !lone(String(body.summary.model)), body && body.summary.model);
        const hdr = mock.headers[0] || {};
        check('ai: sent as application/json, same-origin (Origin is not "null")', /^application\/json/.test(hdr['content-type'] || '') && (hdr.origin === undefined || hdr.origin === BASE.replace(/\/$/, '')), hdr);
        const inits = await page.evaluate(() => window.__explainInits);
        // "no-referrer" would make a POST's Origin "null" (Fetch spec, e.g. Firefox), which explain.php rejects with 403.
        check('ai: fetch uses referrerPolicy same-origin, POST, no credentials', inits.length === 1 && inits[0].referrerPolicy === 'same-origin' && inits[0].method === 'POST' && inits[0].credentials === 'omit', inits);
        const ledger = await page.locator('#ledger-list').innerText();
        check('ai: outbound log has the entry', (await page.locator('#ledger-list li').count()) === before + 1 && /anonymised summary/.test(ledger) && ledger.includes('127.0.0.1:' + PORT), ledger.slice(-300));
        const paras = await page.locator('#sys-ai-text p').allInnerTexts();
        check('ai: explanation renders as text paragraphs', paras.length === 2 && paras[0].includes('Your PC is mostly fine') && paras[1].includes('Second paragraph'), paras);
        check('ai: model output never parsed as HTML', paras.join(' ').includes('<b>bold</b>') && (await page.locator('#sys-ai-text b, #sys-ai-text img').count()) === 0 && !(await page.evaluate(() => window.__xss)));
        check('ai: no page errors', seen.errors.length === 0, seen.errors);
        check('ai: no outside requests', seen.external.length === 0, seen.external);

        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        const report = await page.locator('#report').innerText();
        const score = (await page.locator('#sys-score').innerText()).trim();
        check('pdf: includes "System report"', report.includes('System report'), report.slice(0, 300));
        check('pdf: includes the health score', new RegExp('\\b' + score + ' ?/ ?100').test(report), [score, report.slice(0, 400)]);
        check('pdf: includes findings and fact tiles', /MiracastPowerManager/.test(report) && /Battery health/.test(report), report.slice(0, 600));
        check('pdf: includes the AI explanation as text', report.includes('Second paragraph: update the drivers.') && report.includes('<b>bold</b>') && (await page.locator('#report b, #report img:not([src*="emblem.png"])').count()) === 0);
        check('pdf: no planted personal data', !PERSONAL.test(report), report.match(/.{0,20}(PC-NAME|DESKTOP-JD123|JohnDoe).{0,20}/));
        check('pdf: footer no longer says nothing was sent', !/nothing was sent/i.test(report), report.slice(-300));
        check('pdf: heading says "System report (Windows)"', report.includes('System report (Windows)') && !report.includes('System report (Linux)'), report.slice(0, 300));
        await page.click('#sys-os-linux', { timeout: 2000 }).catch(() => {});
        check('pdf: Windows report not offered while Linux is selected', !(await page.locator('#pdf').isVisible().catch(() => true)));
        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        check('pdf: no Windows system section while Linux is selected', !(await page.locator('#report').innerText()).includes('System report'));
        await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
        check('pdf: Windows report offered again with Windows selected', await page.locator('#pdf').isVisible().catch(() => false));
        await context.close();
      }
    }
    {
      // Errors: friendly messages, Send usable again after each one
      const { page, context, seen } = await analyzed();
      const mock = { mode: 429 };
      await mockExplain(page, mock);
      await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
      const results = {};
      for (const mode of [429, 'daily', 503, 502, 500, 'abort']) {
        mock.mode = mode;
        await page.click('#sys-ai-send', { timeout: 3000 }).catch(() => {});
        await waitErr(page);
        results[mode] = await errText(page);
        await page.waitForFunction(() => { const b = document.getElementById('sys-ai-send'); return b && !b.disabled; }, null, { timeout: 3000 }).catch(() => {});
      }
      check('ai: 429 says "limit"', /limit/i.test(results[429]), results[429]);
      check('ai: daily cap says "limit"', /limit/i.test(results.daily), results.daily);
      check('ai: 503 has its own friendly message', !!results[503] && results[503] !== results[429] && results[503] !== results[500], results[503]);
      check('ai: 502 has its own friendly message', !!results[502] && results[502] !== results[503] && results[502] !== results[500], results[502]);
      check('ai: other errors and network failure get a generic message', !!results[500] && results[500] === results.abort, [results[500], results.abort]);
      check('ai: every attempt logged, no explanation shown', mock.bodies.length === 6 && (await page.locator('#sys-ai-text p').count()) === 0, mock.bodies.length);
      check('ai: errors cause no page error', seen.errors.length === 0, seen.errors);
      await context.close();
    }
    // Linux: the same flow with the Linux summary; the PDF follows the selected system
    const LXF = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', f + '.txt'), 'utf8');
    const LINUX_UA = 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
    const plantedL = JSON.parse(fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', 'linux', 'PLANTED.json'), 'utf8'));
    const PLANTED_L = [].concat(...Object.values(plantedL)).map((p) => String(p).toLowerCase());
    const leaksL = (s) => PLANTED_L.filter((p) => s.toLowerCase().includes(p)).concat(/\/home\//.test(s) ? ['/home/'] : []);
    const UBUNTU_TEXTS = { system: LXF('ubuntu-system'), journal: LXF('ubuntu-journal-boot'), boots: LXF('boots-ubuntu'), battery: LXF('upower-laptop'), disks: LXF('df-ubuntu') };
    async function linuxAnalyzed(engine = browser) {
      const made = await newPage('ok', { userAgent: LINUX_UA, viewport: { width: 1280, height: 900 } }, engine);
      const { page } = made;
      await page.waitForFunction(() => (document.getElementById('sys-banner') || {}).textContent, null, { timeout: 5000 }).catch(() => {});
      await page.evaluate((map) => {
        Object.keys(map).forEach((k) => { const ta = document.getElementById('sys-paste-' + k); if (ta) ta.value = map[k]; });
      }, UBUNTU_TEXTS);
      await page.click('#sys-linux-analyze', { timeout: 3000 });
      await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
      return made;
    }
    {
      let made;
      try { made = await linuxAnalyzed(); } catch (e) { made = null; }
      check('ai linux: setup (Ubuntu outputs analyzed)', !!made);
      if (made) {
        const { page, context, seen } = made;
        const mock = { mode: 'ok', delay: 200 };
        await mockExplain(page, mock);
        check('ai linux: "Explain with AI" button appears after Analyze', await page.locator('#sys-ai-open').isVisible().catch(() => false));
        check('ai linux: disclosure not shown before the click', !(await page.locator('#sys-ai-disclosure').isVisible().catch(() => false)));
        const before = await page.locator('#ledger-list li').count();
        await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
        const disc = await page.locator('#sys-ai-disclosure').innerText({ timeout: 2000 }).catch(() => '');
        check('ai linux: exact Linux disclosure shown before sending (files or pasted text)', disc.trim() === DISCLOSURE_LINUX, disc);
        const shownText = await page.locator('#sys-ai-summary').innerText({ timeout: 2000 }).catch(() => '');
        let shown = null;
        try { shown = JSON.parse(shownText); } catch (e) { /* stays null */ }
        check('ai linux: the summary shown is the Linux shape', shown !== null && shown.platform === 'linux' && shown.score === 25 && shown.distro === 'Ubuntu 24.04.1 LTS', shownText.slice(0, 200));
        check('ai linux: nothing sent and nothing logged before Send', mock.bodies.length === 0 && (await page.locator('#ledger-list li').count()) === before);
        await page.click('#sys-ai-send', { timeout: 2000 }).catch(() => {});
        await page.waitForSelector('#sys-ai-text p', { timeout: 5000 }).catch(() => {});
        check('ai linux: exactly one request', mock.bodies.length === 1, mock.bodies.length);
        let body = null;
        try { body = JSON.parse(mock.bodies[0]); } catch (e) { /* stays null */ }
        check('ai linux: request body is exactly {summary} with platform "linux"', body !== null && JSON.stringify(Object.keys(body)) === '["summary"]' && body.summary.platform === 'linux', mock.bodies[0]);
        check('ai linux: request body equals the summary shown', body !== null && JSON.stringify(body.summary) === JSON.stringify(shown), [mock.bodies[0], shownText]);
        check('ai linux: no planted identifier in the request or the summary shown', !!mock.bodies[0] && leaksL(mock.bodies[0]).length === 0 && leaksL(shownText).length === 0, leaksL(String(mock.bodies[0])));
        const ledger = await page.locator('#ledger-list').innerText();
        check('ai linux: outbound log gains one entry', (await page.locator('#ledger-list li').count()) === before + 1 && /anonymised summary/.test(ledger), ledger.slice(-300));
        const paras = await page.locator('#sys-ai-text p').allInnerTexts();
        check('ai linux: explanation renders as text paragraphs', paras.length === 2 && paras[0].includes('Your PC is mostly fine') && paras[1].includes('Second paragraph'), paras);
        check('ai linux: model output never parsed as HTML', paras.join(' ').includes('<b>bold</b>') && (await page.locator('#sys-ai-text b, #sys-ai-text img').count()) === 0 && !(await page.evaluate(() => window.__xss)));

        check('pdf linux: PDF button available', await page.locator('#pdf').isVisible().catch(() => false));
        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        const report = await page.locator('#report').innerText();
        check('pdf linux: heading says "System report (Linux)"', report.includes('System report (Linux)') && !report.includes('System report (Windows)'), report.slice(0, 300));
        check('pdf linux: score 25 / 100 and Ubuntu 24.04.1 LTS', /\b25 \/ 100/.test(report) && report.includes('Ubuntu 24.04.1 LTS'), report.slice(0, 600));
        check('pdf linux: "Logs from" date line', /Logs from 2026-10-18/.test(report), report.slice(0, 400));
        check('pdf linux: includes the AI explanation as text', report.includes('Second paragraph: update the drivers.') && (await page.locator('#report b, #report img:not([src*="emblem.png"])').count()) === 0);
        check('pdf linux: no planted identifier, no /home/, no raw journal line', leaksL(report).length === 0 && !/CRTC gamma/.test(report), leaksL(report));
        check('pdf linux: footer says a summary was sent', !/nothing was sent/i.test(report), report.slice(-300));

        await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
        check('pdf linux: Linux report not offered while Windows is selected', !(await page.locator('#pdf').isVisible().catch(() => true)));
        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        check('pdf linux: no Linux system section while Windows is selected', !(await page.locator('#report').innerText()).includes('System report'));
        await page.click('#sys-os-linux', { timeout: 2000 }).catch(() => {});
        check('pdf linux: Linux report offered again with Linux selected', await page.locator('#pdf').isVisible().catch(() => false));
        check('ai linux: no page errors', seen.errors.length === 0, seen.errors);
        check('ai linux: no outside requests', seen.external.length === 0, seen.external);
        await context.close();
      }
    }
    {
      // Linux errors: the same friendly messages as Windows
      let made;
      try { made = await linuxAnalyzed(); } catch (e) { made = null; }
      if (made) {
        const { page, context, seen } = made;
        const mock = { mode: 429 };
        await mockExplain(page, mock);
        await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
        const results = {};
        for (const mode of [429, 503, 502]) {
          mock.mode = mode;
          await page.click('#sys-ai-send', { timeout: 3000 }).catch(() => {});
          await waitErr(page);
          results[mode] = await errText(page);
          await page.waitForFunction(() => { const b = document.getElementById('sys-ai-send'); return b && !b.disabled; }, null, { timeout: 3000 }).catch(() => {});
        }
        check('ai linux: 429 says "limit"', /limit/i.test(results[429]), results[429]);
        check('ai linux: 503 says not available', /not available/i.test(results[503]) && results[503] !== results[429], results[503]);
        check('ai linux: 502 has its own friendly message', !!results[502] && results[502] !== results[503] && results[502] !== results[429], results[502]);
        check('ai linux: every attempt sent with platform linux, no explanation shown', mock.bodies.length === 3 && mock.bodies.every((b) => JSON.parse(b).summary.platform === 'linux') && (await page.locator('#sys-ai-text p').count()) === 0, mock.bodies.length);
        check('ai linux: errors cause no page error', seen.errors.length === 0, seen.errors);
        await context.close();
      } else {
        check('ai linux: errors setup', false);
      }
    }

    // Mac: the same flow with the Mac summary (Set A: silicon.spx plus panics, Chrome crashes and a Jetsam report)
    const MFX = (f) => path.join(here, '..', 'fixtures', 'sys', 'mac', f);
    const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15';
    const MAC_SET_A = ['panic-full-2026-10-02-081533.0001.panic', 'panic-full-2026-10-14-224107.0002.panic',
      'Google Chrome Helper (Renderer)-2026-10-15-091244.ips', 'Google Chrome Helper (Renderer)-2026-10-16-200103.ips', 'JetsamEvent-2026-10-17-130512.ips'];
    const plantedM = JSON.parse(fs.readFileSync(MFX('PLANTED.json'), 'utf8'));
    const PLANTED_M = [].concat(...Object.values(plantedM)).map((p) => String(p).toLowerCase());
    // File names (macOS puts the computer name in them), raw report text and paths must never appear.
    const MAC_FILE_BITS = ['panic-full-', 'kernel-2026', 'google chrome helper (renderer)-', 'jetsamevent-', 'priyas-imac', 'silicon.spx', '.ips', '.spx',
      '/users/', 'processbypid', 'crashreporterkey', 'thesis draft'];
    const leaksM = (s) => { const l = String(s).toLowerCase(); return PLANTED_M.concat(MAC_FILE_BITS).filter((p) => l.includes(p)); };
    async function macAnalyzed(engine = browser) {
      const made = await newPage('ok', { userAgent: MAC_UA, viewport: { width: 1280, height: 900 } }, engine);
      const { page } = made;
      await page.waitForFunction(() => (document.getElementById('sys-banner') || {}).textContent, null, { timeout: 5000 }).catch(() => {});
      const settled = (k) => page.waitForFunction((k) => /^(ok|error)$/.test((document.getElementById('sys-step-mac-' + k) || { getAttribute: () => '' }).getAttribute('data-state') || ''), k, { timeout: 10000 }).catch(() => {});
      await page.setInputFiles('#sys-file-mac-spx', MFX('silicon.spx'), { timeout: 3000 });
      await settled('spx');
      await page.setInputFiles('#sys-file-mac-crash', MAC_SET_A.map(MFX), { timeout: 3000 });
      await settled('crash');
      await page.click('#sys-mac-analyze', { timeout: 3000 });
      await page.waitForSelector('#sys-results:not([hidden])', { timeout: 10000 });
      return made;
    }
    {
      let made;
      try { made = await macAnalyzed(); } catch (e) { made = null; }
      check('ai mac: setup (Set A analyzed)', !!made);
      if (made) {
        const { page, context, seen } = made;
        const mock = { mode: 'ok', delay: 200 };
        await mockExplain(page, mock);
        check('ai mac: "Explain with AI" button appears after Analyze', await page.locator('#sys-ai-open').isVisible().catch(() => false));
        check('ai mac: disclosure not shown before the click', !(await page.locator('#sys-ai-disclosure').isVisible().catch(() => false)));
        const before = await page.locator('#ledger-list li').count();
        await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
        const disc = await page.locator('#sys-ai-disclosure').innerText({ timeout: 2000 }).catch(() => '');
        check('ai mac: exact disclosure shown before sending', disc.trim() === DISCLOSURE, disc);
        const shownText = await page.locator('#sys-ai-summary').innerText({ timeout: 2000 }).catch(() => '');
        let shown = null;
        try { shown = JSON.parse(shownText); } catch (e) { /* stays null */ }
        check('ai mac: the summary shown is the Mac shape', shown !== null && shown.platform === 'mac' && shown.score === 55 && shown.macos === 'macOS 26.0.1 (25A362)' &&
          shown.model === 'MacBook Air (Mac14,2)' && shown.chip === 'Apple M2', shownText.slice(0, 200));
        check('ai mac: nothing sent and nothing logged before Send', mock.bodies.length === 0 && (await page.locator('#ledger-list li').count()) === before);
        await page.click('#sys-ai-send', { timeout: 2000 }).catch(() => {});
        await page.waitForSelector('#sys-ai-text p', { timeout: 5000 }).catch(() => {});
        check('ai mac: exactly one request', mock.bodies.length === 1, mock.bodies.length);
        let body = null;
        try { body = JSON.parse(mock.bodies[0]); } catch (e) { /* stays null */ }
        check('ai mac: request body is exactly {summary} with platform "mac"', body !== null && JSON.stringify(Object.keys(body)) === '["summary"]' && body.summary.platform === 'mac', mock.bodies[0]);
        check('ai mac: request body equals the summary shown', body !== null && JSON.stringify(body.summary) === JSON.stringify(shown), [mock.bodies[0], shownText]);
        check('ai mac: no planted identifier and no file name in the request or the summary shown', !!mock.bodies[0] && leaksM(mock.bodies[0]).length === 0 && leaksM(shownText).length === 0,
          [leaksM(String(mock.bodies[0])), leaksM(shownText)]);
        const ledger = await page.locator('#ledger-list').innerText();
        check('ai mac: outbound log gains one entry', (await page.locator('#ledger-list li').count()) === before + 1 && /anonymised summary/.test(ledger), ledger.slice(-300));
        const paras = await page.locator('#sys-ai-text p').allInnerTexts();
        check('ai mac: explanation renders as text paragraphs', paras.length === 2 && paras[0].includes('Your PC is mostly fine') && paras[1].includes('Second paragraph'), paras);
        check('ai mac: model output never parsed as HTML', paras.join(' ').includes('<b>bold</b>') && (await page.locator('#sys-ai-text b, #sys-ai-text img').count()) === 0 && !(await page.evaluate(() => window.__xss)));

        check('pdf mac: PDF button available', await page.locator('#pdf').isVisible().catch(() => false));
        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        const report = await page.locator('#report').innerText();
        check('pdf mac: heading says "System report (Mac)"', report.includes('System report (Mac)') && !report.includes('System report (Windows)') && !report.includes('System report (Linux)'), report.slice(0, 300));
        check('pdf mac: score 55 / 100 and macOS 26.0.1', /\b55 \/ 100/.test(report) && report.includes('macOS 26.0.1'), report.slice(0, 600));
        check('pdf mac: "System Information from" date line', /System Information from 2026-10-18/.test(report), report.slice(0, 400));
        check('pdf mac: findings and facts', /kernel panic/i.test(report) && /91\.9 %/.test(report) && /Battery health/.test(report), report.slice(0, 600));
        check('pdf mac: includes the AI explanation as text', report.includes('Second paragraph: update the drivers.') && (await page.locator('#report b, #report img:not([src*="emblem.png"])').count()) === 0);
        check('pdf mac: no planted identifier, no file name, no volume name, no raw report text', leaksM(report).length === 0, leaksM(report));
        check('pdf mac: footer says a summary was sent', !/nothing was sent/i.test(report), report.slice(-300));

        await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
        check('pdf mac: Mac report not offered while Windows is selected', !(await page.locator('#pdf').isVisible().catch(() => true)));
        await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
        check('pdf mac: no Mac system section while Windows is selected', !(await page.locator('#report').innerText()).includes('System report'));
        await page.click('#sys-os-mac', { timeout: 2000 }).catch(() => {});
        check('pdf mac: Mac report offered again with Mac selected', await page.locator('#pdf').isVisible().catch(() => false));
        check('ai mac: no page errors', seen.errors.length === 0, seen.errors);
        check('ai mac: no outside requests', seen.external.length === 0, seen.external);
        await context.close();
      }
    }
    {
      // Mac errors: the same friendly messages
      let made;
      try { made = await macAnalyzed(); } catch (e) { made = null; }
      if (made) {
        const { page, context, seen } = made;
        const mock = { mode: 429 };
        await mockExplain(page, mock);
        await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
        const results = {};
        for (const mode of [429, 503, 502]) {
          mock.mode = mode;
          await page.click('#sys-ai-send', { timeout: 3000 }).catch(() => {});
          await waitErr(page);
          results[mode] = await errText(page);
          await page.waitForFunction(() => { const b = document.getElementById('sys-ai-send'); return b && !b.disabled; }, null, { timeout: 3000 }).catch(() => {});
        }
        check('ai mac: 429 says "limit"', /limit/i.test(results[429]), results[429]);
        check('ai mac: 503 says not available', /not available/i.test(results[503]) && results[503] !== results[429], results[503]);
        check('ai mac: 502 has its own friendly message', !!results[502] && results[502] !== results[503] && results[502] !== results[429], results[502]);
        check('ai mac: every attempt sent with platform mac, no explanation shown', mock.bodies.length === 3 && mock.bodies.every((b) => JSON.parse(b).summary.platform === 'mac') && (await page.locator('#sys-ai-text p').count()) === 0, mock.bodies.length);
        check('ai mac: errors cause no page error', seen.errors.length === 0, seen.errors);
        await context.close();
      } else {
        check('ai mac: errors setup', false);
      }
    }

    // Not mocked: the real local endpoint (php -S, no key) must get past Content-Type, Origin and the summary
    // whitelist and stop at "not configured" (503). The paid upstream is never reached.
    for (const [label, engineName] of [['Chromium', 'chromium'], ['WebKit', 'webkit'], ['Chromium, Linux', 'chromium'], ['WebKit, Linux', 'webkit'],
      ['Chromium, Mac', 'chromium'], ['WebKit, Mac', 'webkit']]) {
      const eng = engineName === 'webkit' ? await webkit.launch() : browser;
      try {
        const { page, context, seen } = /Linux/.test(label) ? await linuxAnalyzed(eng) : (/Mac/.test(label) ? await macAnalyzed(eng) : await analyzed({}, eng));
        await page.click('#sys-ai-open', { timeout: 2000 }).catch(() => {});
        const res = page.waitForResponse(/\/api\/explain\.php/, { timeout: 8000 }).catch(() => null);
        await page.click('#sys-ai-send', { timeout: 2000 }).catch(() => {});
        const resp = await res;
        const st = resp ? resp.status() : null;
        const body = resp ? await resp.text().catch(() => '') : '';
        check('ai (' + label + '): real endpoint accepts the request and answers 503 not_configured', st === 503 && /not_configured/.test(body), [st, body]);
        await waitErr(page);
        check('ai (' + label + '): 503 shown as a friendly message', /not available/i.test(await errText(page)), await errText(page));
        check('ai (' + label + '): no page errors', seen.errors.length === 0, seen.errors);
        await context.close();
      } finally {
        if (eng !== browser) await eng.close();
      }
    }
  }

  // 6c1. Link previews (WhatsApp, LinkedIn, Instagram read Open Graph tags)
  console.log('Link preview');
  {
    const { page, context } = await newPage('ok');
    const og = await page.evaluate(() => {
      const m = (sel) => (document.querySelector(sel) || {}).content || null;
      return { title: m('meta[property="og:title"]'), desc: m('meta[property="og:description"]'), image: m('meta[property="og:image"]'),
        url: m('meta[property="og:url"]'), type: m('meta[property="og:type"]'), w: m('meta[property="og:image:width"]'),
        h: m('meta[property="og:image:height"]'), card: m('meta[name="twitter:card"]') };
    });
    check('og:title and og:description set', !!og.title && og.title.includes('PC Check') && !!og.desc, og);
    check('og:image is an absolute https URL to the banner', og.image === 'https://cybersecinfo.com/pccheck/assets/banner.jpg', og.image);
    check('og:url is the clean page URL', og.url === 'https://cybersecinfo.com/pccheck/', og.url);
    check('og:type, image size and large card set', og.type === 'website' && og.w === '1600' && og.h === '800' && og.card === 'summary_large_image', og);
    await context.close();
  }

  // 6c2. Layout: speed card in the right column, above the outbound log (desktop); stacked on phones
  console.log('Speed card placement');
  {
    const { page, context } = await newPage('ok', { viewport: { width: 1280, height: 900 } });
    const speed = await page.locator('#check-speed').boundingBox();
    const browserCard = await page.locator('#check-browser').boundingBox();
    const ledger = await page.locator('#ledger').boundingBox();
    check('desktop: speed card is in the right column', speed.x > browserCard.x + browserCard.width, [speed.x, browserCard.x + browserCard.width]);
    check('desktop: speed card sits above the outbound log', speed.y + speed.height <= ledger.y + 1, [speed.y + speed.height, ledger.y]);
    check('desktop: speed card is about as wide as the log', Math.abs(speed.width - ledger.width) < 2, [speed.width, ledger.width]);
    await context.close();
  }

  // 6d. Robustness: old browsers, Ctrl+P, slow pings, a failing gauge
  console.log('Robustness');
  {
    const { page, context, seen } = await newPage('ok', { initScript: 'window.AbortController = undefined;' });
    await page.click('#speed-go');
    await page.waitForFunction(() => document.getElementById('check-speed').getAttribute('data-status') !== 'idle', null, { timeout: 5000 }).catch(() => {});
    check('old browser: GO explains instead of doing nothing', (await status(page, 'speed')) === 'error' &&
      /too old/i.test(await page.locator('#check-speed [data-role="verdict"]').innerText()), await status(page, 'speed'));
    check('old browser: no page errors', seen.errors.length === 0, seen.errors);
    await context.close();
  }
  {
    const { page, context } = await newPage('ok');
    await runChecks(page);
    await page.evaluate(() => window.dispatchEvent(new Event('beforeprint')));
    check('Ctrl+P: the report is built before printing', (await page.locator('#report').innerText()).includes('PC Check report'));
    await context.close();
  }
  {
    const { page, context, seen } = await newPage('ok', { speed: 'slowping' });
    const t0 = Date.now();
    await page.click('#speed-go');
    await page.waitForFunction(() => window.__dlStarted === true || false, null, { timeout: 1 }).catch(() => {});
    let firstDownloadAt = null;
    for (let i = 0; i < 100 && firstDownloadAt === null; i++) {
      if (seen.speed.some((u) => /__down\?bytes=[1-9]/.test(u))) firstDownloadAt = Date.now() - t0;
      else await page.waitForTimeout(200);
    }
    check('slow pings: download starts within ~6 s (ping time budget)', firstDownloadAt !== null && firstDownloadAt < 8000, firstDownloadAt);
    await context.close();
  }
  {
    const { page, context, seen } = await newPage('ok', { initScript: 'Object.defineProperty(window, "PCGauge", { configurable: true, get() { return { create() { throw new Error("gauge broke"); }, fraction() { return 0; } }; }, set() {} });' });
    await runChecks(page);
    await page.fill('#pw', 'password');
    await page.click('#pw-submit');
    await page.waitForFunction(() => document.getElementById('check-password').getAttribute('data-status') === 'risk', null, { timeout: 10000 }).catch(() => {});
    check('broken gauge: the rest of the page still works', (await status(page, 'password')) === 'risk' && (await status(page, 'dns')) === 'ok', await status(page, 'password'));
    check('broken gauge: no uncaught error', seen.errors.length === 0, seen.errors);
    await context.close();
  }

  // 7. iPhone (WebKit, the engine every iOS browser must use): full run, no sideways scroll
  console.log('iPhone (WebKit)');
  {
    const wk = await webkit.launch();
    try {
      const { page, context, seen } = await newPage('ok', devices['iPhone 14'], wk);
      await runChecks(page);
      await page.fill('#pw', 'password');
      await page.click('#pw-submit');
      await page.waitForFunction(() => document.getElementById('check-password').getAttribute('data-status') === 'risk');
      check('iPhone: browser shows the iOS note', (await status(page, 'browser')) === 'info', await status(page, 'browser'));
      check('iPhone: connection, DNS ok', (await status(page, 'connection')) === 'ok' && (await status(page, 'dns')) === 'ok');
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      check('iPhone: no horizontal scroll after the password check', overflow <= 0, overflow);
      check('iPhone: no page errors', seen.errors.length === 0, seen.errors);
      await page.screenshot({ path: path.join(shots, 'iphone.png'), fullPage: true });
      await context.close();
    } finally {
      await wk.close();
    }
  }
} finally {
  await browser.close();
  php.kill();
}

console.log(`\ne2e: ${passed} passed, ${failed} failed`);
process.exitCode = failed ? 1 : 0;
