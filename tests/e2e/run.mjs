// End-to-end tests with Playwright. Every outside service is simulated with page.route.
// Run from tests/: node e2e/run.mjs   (starts php -S on 127.0.0.1:$BSC_PORT, default 8765, serving the project folder)
import { chromium, webkit, devices } from 'playwright';
import { spawn } from 'node:child_process';
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

const php = spawn('php', ['-S', '127.0.0.1:' + PORT + '', '-t', root], { stdio: 'ignore' });
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
  const { initScript, speed = 'ok', ...contextOpts } = opts;
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

  // Cloudflare speed test: zero-filled bodies after a short delay. speed: 'stall' never answers the 25 MB download.
  await page.route(/speed\.cloudflare\.com\//, async (r) => {
    const url = r.request().url();
    seen.speed.push(url);
    const headers = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Expose-Headers': 'cf-meta-colo', 'cf-meta-colo': 'DUB' };
    if (r.request().method() === 'OPTIONS') return r.fulfill({ status: 204, headers: Object.assign({ 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'content-type' }, headers) });
    const bytes = parseInt((url.match(/bytes=(\d+)/) || [])[1] || '0', 10);
    if (speed === 'stall' && bytes === 25000000) return; // never answered: the page's own timeout must end it
    if (speed === 'down') return r.fulfill({ status: 503, headers, body: 'down' });
    if (speed === 'slowping' && bytes === 0) await new Promise((res) => setTimeout(res, 1500));
    await new Promise((res) => setTimeout(res, 20));
    return r.fulfill({ status: 200, contentType: 'application/octet-stream', headers, body: url.includes('__down') ? Buffer.alloc(bytes) : '' });
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
    check('ledger in English', (await page.locator('#ledger').innerText()).includes('Sent'));
    const text = await page.locator('body').innerText();
    check('no Portuguese text on screen', !/[ãõçâêô]|Não |Verificar|senha|aparelho/i.test(text), (text.match(/.{0,30}(?:[ãõçâêô]|Não |Verificar|senha|aparelho).{0,30}/i) || [])[0]);
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

    await context.close();
  }
  {
    const { page, context, seen } = await newPage('ok');
    await runChecks(page);
    check('Check now never requests speed.cloudflare.com', seen.speed.length === 0, seen.speed);
    check('speed card is idle until GO', (await status(page, 'speed')) === 'idle');
    check('data warning shown', (await page.locator('#check-speed').innerText()).includes('55 MB'));
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
    const files = { rel: fx('reliability.xml'), bat: fx('battery-report.html'), msi: fx('msinfo32-head.txt'), pt: fx('msinfo32-pt.txt'), de: fx('msinfo32-de.txt') };
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
        bat, msi, pt: S.parseMsinfo(text.pt), de: S.parseMsinfo(text.de),
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
      check('battery: health between 0 and 100 and cycles', r.bat.healthPct > 80 && r.bat.healthPct < 100 && r.bat.cycles === 96, r.bat);
      check('battery: design and full capacity in mWh', r.bat.designMWh === 76316 && r.bat.fullMWh === 68979, r.bat);
      check('msinfo: OS, model, CPU, RAM', /Windows 11/.test(r.msi.os) && /Predator/.test(r.msi.model) && /Ultra 7/.test(r.msi.cpu) && r.msi.ramGb === 32, r.msi);
      check('msinfo: no problem devices on this PC', Array.isArray(r.msi.problemDevices) && r.msi.problemDevices.length === 0, r.msi.problemDevices);
      check('msinfo: Portuguese labels parse', /Windows 11/.test(r.pt.os) && r.pt.ramGb === 32, r.pt);
      check('msinfo: German reports unsupported language', r.de.unsupportedLanguage === true, r.de);
      check('wrong file: battery report is not a reliability file', r.wrong.error === 'not_reliability', r.wrong);
      check('wrong file: reliability is not a battery report', r.wrongBat.error === 'not_battery', r.wrongBat);
      check('wrong file: random text is not msinfo', r.wrongMsi.error === 'not_msinfo', r.wrongMsi);
      check('msinfo: 27 MB file parses in < 2 s and only the head is read', r.bigMs < 2000 && /Windows 11/.test(r.bigOs), [Math.round(r.bigMs), r.bigOs]);
    }
    await context.close();
  }

  // 8b. System report rules, score, anonymiser and AI summary
  console.log('System report rules');
  {
    const fx = (f) => fs.readFileSync(path.join(here, '..', 'fixtures', 'sys', f)).toString('base64');
    const files = { rel: fx('reliability.xml'), bat: fx('battery-report.html'), msi: fx('msinfo32-head.txt') };
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
        keys: Object.keys(S.buildSummary(real)).sort()
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
      check('summary has only whitelisted fields', JSON.stringify(r.keys) === JSON.stringify(['batteryHealthPct', 'findings', 'hardwareErrors30d', 'model', 'os', 'ramGb', 'score', 'shutdowns30d', 'stabilityNow', 'topCrashApps']), r.keys);
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
      check('system: Mac button shows Coming soon and hides the Windows steps', /Coming soon/i.test(await page.locator('#sys-soon').innerText({ timeout: 2000 }).catch(() => '')) && !(await page.locator('#sys-steps').isVisible()));
      await page.click('#sys-os-windows', { timeout: 2000 }).catch(() => {});
      check('system: back to Windows hides Coming soon', await page.locator('#sys-steps').isVisible().catch(() => false));
      await context.close();
    }
    {
      const { page, context } = await newPage('ok', { userAgent: MAC_UA });
      await waitBanner(page);
      const banner = await page.locator('#sys-banner').innerText({ timeout: 2000 }).catch(() => '');
      check('system: macOS UA -> Mac banner', /You.re on macOS/.test(banner), banner);
      check('system: macOS UA -> Mac pre-selected', (await pressed(page, 'mac')) === 'true');
      check('system: macOS UA -> Coming soon', /Coming soon/i.test(await page.locator('#sys-soon').innerText({ timeout: 2000 }).catch(() => '')));
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
      const { page, context, seen } = await newPage('ok', { userAgent: WIN_UA });
      await page.setInputFiles('#sys-file-reliability', FX('battery-report.html'), { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const msg = await page.locator('#sys-step-reliability [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
      check('wrong file gives a clear message', /doesn.t look like a Reliability history file/i.test(msg), msg);
      await page.setInputFiles('#sys-file-msinfo', FX('msinfo32-de.txt'), { timeout: 3000 }).catch(() => {});
      await page.waitForTimeout(300);
      const de = await page.locator('#sys-step-msinfo [data-role="msg"]').innerText({ timeout: 2000 }).catch(() => '');
      check('system: other-language report says so', /language PC Check can.t read yet/i.test(de), de);
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
      if (seen.speed.some((u) => /bytes=100000\b/.test(u))) firstDownloadAt = Date.now() - t0;
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
