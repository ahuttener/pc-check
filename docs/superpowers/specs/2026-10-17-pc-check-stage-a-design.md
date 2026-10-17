# PC Check — Stage A: more checks + PDF report (design)

Date: 2026-10-17 · Owner: Adriano Huttener · Live: https://cybersecinfo.com/pccheck/ · Repo: github.com/ahuttener/pc-check

## Why

PC Check is live with four browser checks (browser version, connection, DNS leak, breached password). The owner finds it too basic and wants more value **without anything to download**, plus a downloadable PDF report like GRC Audit's. It serves two audiences: an ordinary visitor ("is my setup OK, and how do I fix it?") and a recruiter reading the portfolio (it must look like serious security engineering, and be honest).

## Goals

1. **Internet speed test** — download, upload, latency and jitter.
2. **WebRTC IP leak** — does the browser reveal the real IP even with a VPN on?
3. **Trackability** — what any site can read about this browser/device without cookies, and whether privacy protections are active.
4. **Fairer "outdated browser" verdict** — do not alarm people when the new version is still rolling out.
5. **PDF report** with the CyberSecInfo logo, like GRC Audit's "Download PDF report".

## Non-goals / anti-goals

- Nothing to install, nothing stored on the server, no cookies, no analytics, no third-party scripts (unchanged privacy model).
- No claim we cannot prove: never say "your browser is unique among N users" (we have no population data). No CPU/RAM/temperature *health* claims (a web page cannot measure them).
- No data sent anywhere without the visitor clicking, and every request appears in the outbound log.
- English only (owner's decision).

## Constraints

- Current code: `index.html`, `assets/app.js` (ES2017, no `innerHTML` with outside data, `window.__bsc` test hooks), `assets/styles.css`, PHP proxy in `api/` (PHP 7.4+), strict CSP in `<meta>` and `.htaccess` (`default-src 'none'`; frames therefore forbidden).
- Tests: `tests/` (PHP parser tests, API tests on `php -S`, Playwright e2e with every outside service mocked, Chromium + WebKit/iPhone). All must stay green; new features get new tests.
- After CSS/JS changes bump `?v=` on the asset URLs (browsers cached old files before).
- Deploy: `public_html/pccheck/` on Hostinger via SSH, backup first.

## Design (decided)

### Layout
Existing four cards stay. New cards, in this order after them: **Speed**, **WebRTC leak**, **Trackability**. Same card component, same statuses (`ok`, `warn`, `risk`, `info`, `error`), same outbound log. A **"Download PDF report"** button appears next to "Check again" once at least one check has finished.

### 1. Speed test (Cloudflare)
- Endpoints (verified 17/10 to send `Access-Control-Allow-Origin: *` for GET, OPTIONS and POST): `GET https://speed.cloudflare.com/__down?bytes=N`, `POST https://speed.cloudflare.com/__up`.
- **Not** part of "Check now": it has its own **"Test speed"** button inside the card, because it uses data (warning text: see "Decisions settled" below — important on mobile).
- Latency: 10 × `__down?bytes=0`, median of the request time (prefer `Server-Timing`/Resource Timing if available, else wall clock). Jitter: mean absolute difference between consecutive samples.
- Download: increasing sizes (100 kB, 1 MB, 10 MB, 25 MB) until ~8 s of measuring or sizes run out; result = 90th percentile of per-request Mbps. Upload: 1 MB, 5 MB, 10 MB, same rule, ~6 s budget.
- Verdict thresholds (download): ≥ 25 Mbps `ok`, 10–25 `info`, < 10 `warn`; latency > 100 ms adds a note. Facts: download, upload, latency, jitter, Cloudflare data centre (`cf-meta-colo`).
- Outbound log: one entry per phase ("speed.cloudflare.com — latency/download/upload", data sent: "test bytes only").
- CSP: add `https://speed.cloudflare.com` to `connect-src` (meta + `.htaccess`).
- **Animated gauge (owner's request, "like speedtest.net, in CyberSecInfo colours"):** inside the Speed card, a large circular speedometer drawn in SVG by `app.js` (no library, no inline styles in HTML; animate via SVG attributes / CSSOM so the strict CSP still holds). Dark panel, cyan arc (`#22d3ee` → `#06b6d4`) with glow, scale 0–1000 Mbps (non-linear: 0, 5, 10, 50, 100, 250, 500, 750, 1000), needle and arc follow the live Mbps smoothly (`requestAnimationFrame`, eased). Big live number in Orbitron + "Mbps" label. A round **GO** button in the centre starts the test (replaces the plain "Test speed" button). Phase indicator under the gauge: Ping → Download → Upload, the active phase highlighted; ping/jitter/download/upload tiles fill in as each phase ends, then a "Test again" button. Inspired by speedtest.net's feel, but our own design — no Ookla branding, layout or assets copied. Respects `prefers-reduced-motion` (no needle animation, numbers only). Works at 375 px.
- **Cookies:** none. Cloudflare's speed endpoints set no cookies (checked 17/10, no `Set-Cookie`), and the page sets none, so no consent banner is needed. speedtest.net asks for consent because of its ads and trackers, which this page does not have.

### 2. WebRTC IP leak
- Runs as part of "Check now". `RTCPeerConnection({iceServers:[{urls:'stun:stun.cloudflare.com:3478'}]})`, data channel + offer, collect ICE candidates for up to 3 s.
- Public IPs = `srflx` candidates. Compare with the public IP from the Cloudflare trace (already fetched by the connection check).
  - WebRTC unavailable/blocked → `ok` ("WebRTC can't expose your IP here").
  - srflx IP equals the trace IP → `ok` (no leak; note: "with a VPN on, this should be the VPN's IP").
  - srflx IP differs from the trace IP → `risk` ("Your real IP may be leaking past your VPN or proxy"), with fix steps per browser.
  - Host candidates showing a private IP (not `.local` mDNS) → `warn` (local network address exposed).
- Outbound log entry: `stun.cloudflare.com (UDP 3478)`, data sent: "a STUN request (no personal data)". CSP does not govern WebRTC; no CSP change.

### 3. Trackability
- 100 % local; nothing is sent. Runs with "Check now".
- "What any site can read without cookies": browser/OS, language, time zone, screen size and pixel ratio, CPU cores (`hardwareConcurrency`), approximate RAM (`deviceMemory`, Chromium only), GPU (`WEBGL_debug_renderer_info`), touch support, canvas fingerprint hash (short), number of these that are available.
- Protection signals: Global Privacy Control (`navigator.globalPrivacyControl`), Do Not Track, content/tracker blocker detected (bait element technique: a hidden element with ad-like class names; blocked if hidden/removed), canvas readout randomised (draw twice, hashes differ → protected, e.g. Brave/Firefox resistFingerprinting).
- Verdict (heuristic, stated as such): `ok` "Low trackability" if ≥ 2 protections; `info` "Medium" if 1; `warn` "High" if 0. Fix: suggest a tracker blocker, GPC, or a privacy-focused browser. Wording must say this is an estimate.

### 4. Fairer browser verdict
- `api/versions.php` also returns the release date of the latest stable version per Chrome platform (versionhistory `.../channels/stable/versions/all/releases?filter=endtime=none` → `serving.startTime`) and Firefox `LAST_RELEASE_DATE`. New fields: `chrome.<platform>.released`, `firefox.released` (ISO dates). Cached like the rest.
- In `app.js`: if the visitor has the same major with a pending patch **and** the latest release is < 14 days old (one major behind always stays `warn`: rollout start times change often and are not a reliable ship date — final review, 17/10) → `info` "A new version is rolling out — it should reach you in the next days" (instead of `warn`). ≥ 2 majors behind stays `risk`.

### 5. PDF report
- "Download PDF report" builds a **print-only section** in the page (hidden on screen, shown by `@media print`) and calls `window.print()` — no iframe (CSP forbids frames), no library, nothing leaves the device.
- Content: CyberSecInfo emblem (`assets/emblem.png`) + "PC Check report", date/time and the page URL; for each check: name, status, verdict, facts, fix; speed results if run; the outbound log; footer "Generated locally in your browser — nothing was sent to CyberSecInfo". The password section shows only the status and the 5-character prefix, never the password or full hash.
- Print styles: light background, black text, cyan accents, A4, page breaks avoided inside a check.

## Testing (decided)
- PHP: parser tests for the new release-date fields (fixtures from the real releases endpoint).
- e2e (Chromium + iPhone/WebKit): mock `speed.cloudflare.com` (fixed bodies + delays → known Mbps), stub `RTCPeerConnection` with `addInitScript` for the three leak cases, bait element hidden/visible, GPC on/off; rolling-out verdict with a fresh `released` date; PDF: `page.emulateMedia({media:'print'})` shows the report and hides the app, and Chromium `page.pdf()` contains the emblem and each check, but never the password or full hash. No horizontal scroll at 375 px and iPhone. Nothing leaves before a click; speed test never runs without its own click.

## Decisions settled after the builder review (designer's calls)

- **Language:** all new strings English only (`STR.en`). The existing `STR.pt` dictionary stays untouched and unused (`detectLang()` always returns `en`); no new pt keys.
- **WebRTC comparison:** compare **per address family** (IPv4 with IPv4, IPv6 with IPv6). Leak (`risk`) only if a srflx address differs from the trace address **of the same family**. Families present only on one side are not a leak. If the trace failed → `info` "Couldn't compare: the connection check didn't return your public IP", still listing the WebRTC addresses. Through WARP the trace IP is the WARP IP — same rule applies.
- **PDF:** the print section is built from the DOM at click time (nothing exists or is sent before the click). Show a one-line hint next to the button: "Choose “Save as PDF” in the print window." The `page.pdf()` test is a proxy for the real flow; acceptable.
- **Speed data and time limits:** worst case is about **55 MB** (download ≈ 36 MB + upload 16 MB + latency) — the warning says "uses up to about 55 MB of data". Every request has its own abort timeout (10 s); the time budget is checked between requests and a timed-out request ends that phase with the samples collected so far. A **Cancel** button aborts everything.
- **Rolling-out rule:** ≥ 2 majors behind stays `risk` even if the release is new. If `released` is missing, fall back to the current verdict.
- **Trackability protections:** counted signals are GPC on, content blocker detected, canvas randomised, and **Safari/WebKit's built-in tracking prevention** (counts as one protection when the engine is Safari/WebKit, including all iOS browsers). Do Not Track is shown as a fact but **not counted** (deprecated, ignored by most sites).

## Left to the builder
Exact copy text, card icons, exact Mbps math details within the rules above, fact ordering, print CSS details.

## Stage B (separate design, after Stage A ships)
System reports for Windows / Mac / Linux (visitor picks the OS): guided steps to save reports the OS already produces (Windows `perfmon /rel`, `powercfg /batteryreport`, `msinfo32`; Mac System Information + DiagnosticReports; Linux pasted output of `journalctl`, `upower`, `lsblk`), personal data removed **in the browser** before anything is sent, only a technical summary goes to the AI through the site's existing key, nothing stored, results dashboard + steps + the same PDF report. Decisions so far are in the owner's brainstorm of 17/10; it gets its own design document.
