# PC Check Stage A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an animated speed test, a WebRTC IP-leak check, a trackability check, a fairer outdated-browser verdict and a locally generated PDF report to PC Check.

**Architecture:** Same structure as today. `assets/app.js` stays one ES2017 IIFE holding all checks: each check gets a pure `evaluateX()` that is exposed on `window.__bsc` for tests and a `runX()` that does I/O and calls `setCheck()`. The SVG speedometer is drawn by a new self-contained `assets/gauge.js`, which exposes `window.PCGauge` and has no knowledge of the checks. `api/versions.php` gains release dates. The PDF is a print-only DOM section that `app.js` builds when the button is clicked, followed by `window.print()`.

**Tech Stack:** vanilla JS (ES2017, no libraries), SVG, CSS `@media print`, PHP 7.4+, Playwright (Chromium + WebKit), PHP test scripts.

**Spec:** `docs/superpowers/specs/2026-10-17-pc-check-stage-a-design.md`

## Global Constraints

- English only: every new string goes in `STR.en` only. `STR.pt` stays untouched.
- ES2017 in `assets/*.js` (no `?.`, `??` or class fields). Never use `innerHTML` with outside data. Build nodes with `el()`.
- CSP stays strict. The only change is adding `https://speed.cloudflare.com` to `connect-src`, in both the `<meta>` in `index.html` and the `.htaccess`. Set styles from JS with CSSOM (`node.style.x = …`) or SVG attributes, never with `setAttribute('style', …)`.
- Nothing leaves the device before the user clicks. Every outbound request is logged with `logOutbound(host, purposeSpec, dataArray)`.
- The speed test runs only from its own GO button, never from "Check now".
- Bump the asset URLs in `index.html` (`styles.css?v=5`, `app.js?v=4`, new `gauge.js?v=1`) whenever those files change.
- PHP compatibility: 7.4 (no `match`, no `str_contains`, no nullsafe operator).
- All tests stay green: `cd tests && BSC_PORT=8767 npm test`. Port 8080 is occupied on this PC.

## Review Focus

1. **The connection dies or slows to a crawl during the speed test.** Expected: each request aborts at 10 s, the phase ends with the samples collected so far, the gauge settles, and the card shows partial results or an `error` status. It must never spin forever. Test: Task 5 "speed: stalled download ends with partial result".
2. **The user presses GO twice, or "Check now" while the speed test is running.** Expected: the second GO is ignored (the button is disabled while running), and "Check now" still works without touching the speed test. Test: Task 5 "speed: GO is disabled while running; Check now unaffected".
3. **A dual-stack connection, where WebRTC returns IPv4 and the trace returns IPv6.** Expected: no leak is reported. Test: Task 3 `evaluateWebRtc` case "different families → ok".
4. **The password has been checked and then the PDF is printed.** Expected: the PDF contains only the 5-character prefix and the status, never the password or the full hash. Test: Task 7 "pdf: never contains password or full hash".
5. **The gauge on a 375 px screen and on an iPhone.** Expected: no horizontal scroll, and the GO button is tappable (at least 44 px). Test: Task 6 "gauge: fits 375 px and iPhone".

---

### Task 1: Release dates in `api/versions.php`

**Files:**
- Modify: `api/_lib.php` (add parsers), `api/versions.php`
- Create: `tests/fixtures/chrome-releases-win.json` (real body from `https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions/all/releases?filter=endtime=none`)
- Test: `tests/php/parsers_test.php`, `tests/api/run.mjs`

**Interfaces:**
- Produces:
  - `bsc_parse_chrome_release_date(string $json): ?string`: ISO-8601 UTC string `YYYY-MM-DDTHH:MM:SSZ` of the newest `releases[].serving.startTime`, or `null`.
  - `bsc_parse_firefox_versions()` gains a `released` key (`YYYY-MM-DD` from `LAST_RELEASE_DATE`, or `null`).
  - JSON response: `chrome.<platform>.released` (string|null), `firefox.released` (string|null). The current fields are unchanged.

- [ ] **Step 1: Write failing parser tests.** Use the real fixture (released matches `^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`), plus `'{"releases":[]}'` → `null` and `'<html>'` → `null`. Firefox real fixture: `released === $real['LAST_RELEASE_DATE']`. Missing key → `null`.
- [ ] **Step 2: Run** `php tests/php/parsers_test.php`. Expected: FAIL on the new checks.
- [ ] **Step 3: Implement the parsers and wire them into `versions.php`** (one extra `bsc_http_get` per Chrome platform). A failed release fetch only sets `released: null` and does not mark the answer incomplete.
- [ ] **Step 4: Extend `tests/api/run.mjs`** live block: each `chrome.<p>.released` is null or ISO. Run `BSC_LIVE=1 node api/run.mjs` and `php tests/php/parsers_test.php`. Expected: all pass.
- [ ] **Step 5: Commit** `feat(api): release dates for the latest browser versions`.

### Task 2: Fairer outdated-browser verdict

**Files:**
- Modify: `assets/app.js` (`evaluateBrowser`, add `STR.en.browserRolling`)
- Test: `tests/e2e/run.mjs` (unit calls through `window.__bsc.evaluateBrowser`)

**Interfaces:**
- Consumes: the `released` fields from Task 1.
- Produces: `evaluateBrowser(b, v, now)`. `now` is an optional `Date` (default `new Date()`) so tests can fix the clock.

- [ ] **Step 1: Write failing e2e unit cases** via `page.evaluate`, with Chrome visitor 155.0.8059.82 on win and latest 156.0.8078.36:
  - released 3 days ago → `status === 'info'`, verdict key `browserRolling`;
  - released 20 days ago → `warn`;
  - visitor 153 (2 behind) with released 3 days ago → `risk`;
  - `released` missing → `warn` (old behaviour);
  - same major with a pending patch and released 3 days ago → `info`.
  - Firefox one behind with `firefox.released` 3 days ago → `info`.
- [ ] **Step 2: Run** `BSC_PORT=8767 node e2e/run.mjs`. Expected: the new cases FAIL.
- [ ] **Step 3: Implement.** The rule is "behind by exactly 1 major, or same major with a pending patch" AND released < 14 days ago → `info` with `browserRolling` ("A new version is rolling out and should reach you in the next days."), keeping the existing `fixUpdate`.
- [ ] **Step 4: Run the e2e.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: do not alarm while a browser update is still rolling out`.

### Task 3: WebRTC leak check

**Files:**
- Modify: `index.html` (new `<article class="check" id="check-webrtc">`, after `#check-dns`, same structure as `#check-dns`), `assets/app.js`
- Test: `tests/e2e/run.mjs`

**Interfaces:**
- Consumes: `fetchTrace()` promise (`{ip, …}`), `setCheck`, `logOutbound`.
- Produces:
  - `gatherWebRtc(timeoutMs): Promise<{supported: boolean, srflx: string[], host: string[]}>`. `host` holds only non-`.local` addresses.
  - `evaluateWebRtc(result, traceIp): checkData`, where `traceIp` may be `null`.
  - `runWebRtc(tracePromise): Promise`, added to `runAll()` and to the summary counts. `state.checks.webrtc`.

- [ ] **Step 1: Write failing unit cases** for `evaluateWebRtc`:
  - unsupported → `ok`;
  - srflx `['203.0.113.7']`, trace `203.0.113.7` → `ok`;
  - srflx `['198.51.100.9']`, trace `203.0.113.7` → `risk`;
  - srflx `['203.0.113.7']`, trace `2001:db8::1` → `ok` (different families);
  - srflx `['198.51.100.9','2001:db8::1']`, trace `2001:db8::1` → `ok`;
  - host `['192.168.1.20']` with no leak → `warn`;
  - trace `null` with srflx present → `info` (`webrtcNoCompare`), and the facts list the srflx IPs.
- [ ] **Step 2: Write the failing e2e flow.** An `addInitScript` stub replaces `RTCPeerConnection` and emits a srflx candidate `candidate:1 1 udp 1 203.0.113.7 5000 typ srflx …`, which matches the mocked trace IP, so the card shows `ok`. The ledger shows `stun.cloudflare.com`. Run, expect FAIL.
- [ ] **Step 3: Implement** using STUN `stun:stun.cloudflare.com:3478`, a data channel and an offer, collecting candidates for up to 3000 ms and closing the connection afterwards. Log `logOutbound('stun.cloudflare.com', ['lpStun'], [])` with the text "A STUN request (no personal data)".
- [ ] **Step 4: Run all tests.** Expected: PASS, including the iPhone block (WebKit) with no page errors.
- [ ] **Step 5: Commit** `feat: WebRTC IP leak check`.

### Task 4: Trackability check

**Files:**
- Modify: `index.html` (`#check-tracking` after `#check-webrtc`, plus a bait element `<div id="bait" class="adsbox ad-banner sponsor-ad" aria-hidden="true">` with CSS that keeps it in the layout but invisible to the user: 1×1 px, off-screen), `assets/app.js`, `assets/styles.css`
- Test: `tests/e2e/run.mjs`

**Interfaces:**
- Produces:
  - `readSurface(): {browser, os, language, timeZone, screen, pixelRatio, cores, memoryGb, gpu, touch, canvasHash}`. Missing values are `null`.
  - `detectProtections(browserInfo): Promise<{gpc: boolean, dnt: boolean, blocker: boolean, canvasRandomised: boolean, webkitItp: boolean}>`.
  - `evaluateTracking(surface, prot): checkData`. Protections counted: `gpc`, `blocker`, `canvasRandomised`, `webkitItp` (`dnt` is shown but not counted). ≥ 2 → `ok`, 1 → `info`, 0 → `warn`. The verdict text says it is an estimate.
  - `runTracking(): Promise`, added to `runAll()`. Nothing is logged to the ledger, because nothing leaves the device.

- [ ] **Step 1: Write failing unit cases** for `evaluateTracking`:
  - 0 protections → `warn`;
  - `{gpc:true}` → `info`;
  - `{gpc:true, blocker:true}` → `ok`;
  - `{dnt:true}` alone → `warn`;
  - `{webkitItp:true, blocker:true}` → `ok`.
- [ ] **Step 2: Write the failing e2e case.** Chromium with no blocker gives a defined status and facts that include "CPU cores" and "Time zone", and the ledger count is unchanged by this check. An init script that sets `navigator.globalPrivacyControl = true` changes the count. Run, expect FAIL.
- [ ] **Step 3: Implement.**
  - Canvas randomisation: draw the same text twice into two canvases and compare their `toDataURL()`.
  - Blocker: after 100 ms, check whether `#bait` has `offsetHeight === 0`, has `display:none`, or was removed.
  - WebKit ITP: true when the browser family is `ios` or `safari`.
- [ ] **Step 4: Run all tests.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: trackability check (local only)`.

### Task 5: Speed measurement engine and card

**Files:**
- Modify: `index.html` (`#check-speed` after `#check-tracking`, plus a gauge container `<div class="gauge" id="gauge"></div>`, GO, Cancel and Test again buttons, a data warning line, and the CSP `connect-src`), `.htaccess` (CSP), `assets/app.js`, `assets/styles.css`
- Test: `tests/e2e/run.mjs`

**Interfaces:**
- Consumes: `request(url, opts)`, `logOutbound`, `window.PCGauge` from Task 6 (guard with `if (window.PCGauge)` so this task works on its own).
- Produces:
  - `measureSpeed(onProgress, signal): Promise<{pingMs, jitterMs, downMbps, upMbps, colo, partial}>`.
    - `onProgress(phase, mbpsOrMs)` where `phase` is `'ping'`, `'download'` or `'upload'`.
    - Download sizes: 100000, 1000000, 10000000, 25000000 bytes, with an 8000 ms budget. Upload sizes: 1000000, 5000000, 10000000, with a 6000 ms budget.
    - Each request has an abort timeout of 10000 ms. Ping uses 10 × `__down?bytes=0`, takes the median, and jitter is the mean absolute difference. Throughput is the 90th percentile of the per-request Mbps.
  - `evaluateSpeed(r): checkData`. Download ≥ 25 Mbps → `ok`, 10–25 → `info`, < 10 → `warn`. Ping > 100 ms adds a note. Facts: download, upload, ping, jitter, Cloudflare data centre.
  - `runSpeed()` / `cancelSpeed()`. `state.speed = {running, result}`. The speed check is not part of `runAll()` and not part of the summary counts.
  - Copy: data warning "Uses up to about 55 MB of data."

- [ ] **Step 1: Write failing unit cases** for `evaluateSpeed`:
  - `{downMbps:120, upMbps:20, pingMs:15}` → `ok`;
  - `downMbps:15` → `info`;
  - `downMbps:4` → `warn`;
  - `pingMs:180` → the note is present.
- [ ] **Step 2: Write the failing e2e cases.**
  - Mock `speed.cloudflare.com` so `__down` returns `bytes` zero bytes after a small delay and `__up` returns 200. After the GO click the card status is not `idle`, the facts show "Mbps", and the ledger has `speed.cloudflare.com` entries.
  - "Check now" never requests `speed.cloudflare.com`.
  - **"speed: stalled download ends with partial result":** `__down?bytes=25000000` never answers. Within 20 s the card is not `running`, and the facts show a download value from the smaller sizes.
  - **"speed: GO is disabled while running; Check now unaffected":** during the run GO is `disabled`, and clicking Check now still completes the other checks.
  - Cancel: clicking Cancel mid-run stops it, the status leaves `running`, and no further `speed.cloudflare.com` requests are made.
  - Run, expect FAIL.
- [ ] **Step 3: Implement.** Use `AbortController` for timeouts and Cancel. Read `cf-meta-colo` from the response headers. Each phase logs one ledger entry with the data "test bytes only".
- [ ] **Step 4: Run all tests.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: speed test (Cloudflare) with cancel and timeouts`.

### Task 6: Animated gauge (`assets/gauge.js`)

**Files:**
- Create: `assets/gauge.js`
- Modify: `index.html` (load `assets/gauge.js?v=1` before `app.js`), `assets/styles.css`, `assets/app.js` (call the gauge from `runSpeed`)
- Test: `tests/e2e/run.mjs`

**Interfaces:**
- Produces:
  - `window.PCGauge.create(container: Element): {set(mbps: number): void, phase(name: 'ping'|'download'|'upload'|'done'|null): void, reset(): void}`.
  - `window.PCGauge.fraction(mbps: number): number` maps the scale ticks 0, 5, 10, 50, 100, 250, 500, 750, 1000 evenly onto 0..1 (piecewise linear between ticks, clamped). It is exposed for tests.
- Visual (spec): a 270° SVG arc. The track is `#1f2937`. The value arc is a cyan gradient from `#22d3ee` to `#06b6d4` with a glow filter. There is a needle and tick labels. The big live number uses Orbitron with "Mbps" below it. A round GO button (≥ 120 px on desktop, ≥ 96 px at 375 px) sits in the centre until the test starts. A phase strip "Ping · Download · Upload" highlights the active phase. Easing uses `requestAnimationFrame`. With `prefers-reduced-motion`, set values directly with no animation.

- [ ] **Step 1: Write the failing tests.**
  - `PCGauge.fraction(0) === 0`, `fraction(100) === 0.5` (100 is the 5th of 9 ticks, so 4/8 = 0.5), `fraction(1000) === 1`, `fraction(5000) === 1`, `fraction(-1) === 0`.
  - **"gauge: fits 375 px and iPhone":** run the mocked speed test at 375 px (Chromium) and on iPhone 14 (WebKit). Check there is no horizontal scroll and that the GO button's `getBoundingClientRect().height ≥ 44`. Take screenshots `speed-desktop.png`, `speed-375.png` and `speed-iphone.png`.
  - Run, expect FAIL.
- [ ] **Step 2: Implement `gauge.js`** as an ES2017 IIFE. Build the SVG with `document.createElementNS`. It does not touch `fetch` or the checks.
- [ ] **Step 3: Run all tests and look at the three screenshots.** Expected: PASS. The gauge is legible and matches the cybersecinfo colours.
- [ ] **Step 4: Commit** `feat: animated speed gauge`.

### Task 7: PDF report

**Files:**
- Modify: `index.html` (button `#pdf` with the hint "Choose “Save as PDF” in the print window.", hidden until a check has finished; empty `<section id="report" class="report" hidden>`), `assets/app.js`, `assets/styles.css` (`@media print` rules)
- Test: `tests/e2e/run.mjs`

**Interfaces:**
- Consumes: `state.checks.*`, `state.speed.result`, `state.ledger`, `state.hash`.
- Produces: `buildReport(): void`, which fills `#report` from the state at click time and is followed by `window.print()`.
  - Content: the emblem `assets/emblem.png`, the title "PC Check report", a local date and time, and the page URL. For each check: name, status pill text, verdict, facts and fix. The speed results, if the speed test was run. The outbound log. Footer: "Generated locally in your browser — nothing was sent to CyberSecInfo."
  - Password: status plus prefix only.
- Print CSS: A4, white background, black text, cyan accents, the app hidden and `#report` shown, and `break-inside: avoid` on each check.

- [ ] **Step 1: Write the failing e2e cases** in Chromium.
  - Run the checks, check the password `password`, then click `#pdf` with `window.print` stubbed to a no-op through an init script.
  - Then `page.emulateMedia({media:'print'})`: `#report` is visible and `.layout` is hidden.
  - `page.pdf()` text, extracted by reading `#report.innerText` (proxy): it includes "PC Check report", every check name and "5BAA6".
  - **"pdf: never contains password or full hash":** the `#report` text and HTML do not contain `password` as a value or `1E4C9B93F3F0682250B6CF8331B7EE68FD8`.
  - Before any click, `#pdf` is hidden and `#report` is empty.
  - Run, expect FAIL.
- [ ] **Step 2: Implement.**
- [ ] **Step 3: Run all tests.** Expected: PASS. Open the generated `page.pdf()` (save to `e2e/screenshots/report.pdf`) and check it shows the logo.
- [ ] **Step 4: Commit** `feat: PDF report generated in the browser`.

### Task 8: Docs, version bump, deploy and live verification

**Files:**
- Modify: `README.md` (table rows for Speed, WebRTC leak, Trackability, PDF report; the privacy model mentions speed.cloudflare.com and STUN; the CSP line), `index.html` (`?v=` bumps, the kicker becomes "Browser · Connection · DNS · Password · Speed · Privacy", plus chips for the new checks)

- [ ] **Step 1: Run the full suite** `cd tests && BSC_PORT=8767 npm test`. Expected: every line `0 failed`.
- [ ] **Step 2: Commit and push** to `github.com/ahuttener/pc-check`.
- [ ] **Step 3: Deploy** to `public_html/pccheck/`. Back up `index.html`, `.htaccess`, `assets/` and `api/` as `*.bak-YYYYMMDD-stageA` first, upload as `.novo`, then `mv`. Do not upload `tests/`, `docs/`, `README.md` or `LICENSE`.
- [ ] **Step 4: Verify live in Chrome.**
  - Check now: all checks finish with no console errors.
  - GO: the speed numbers are within ±30 % of `https://speed.cloudflare.com` run right after.
  - PDF opens the print dialog.
  - The live headers show the CSP with `speed.cloudflare.com`.
