<img src="assets/banner.jpg" alt="PC Check: browser and connection security check by CyberSecInfo" width="100%" />

# PC Check — Browser, Connection, DNS & Password Security

**▶ Live:** [cybersecinfo.com/pccheck](https://cybersecinfo.com/pccheck/) · part of [CyberSecInfo](https://cybersecinfo.com)

**Security, privacy and speed checks that run in the visitor's own browser, with nothing to install, nothing stored, a live log of every request that leaves the device and a PDF report generated locally.**

![JavaScript](https://img.shields.io/badge/JavaScript-ES2017-yellow)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-777bb4)
![Playwright](https://img.shields.io/badge/tests-Playwright-2ead33)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

PC Check is being built in stages. This first stage checks what a web page can honestly see from the browser. The next stage adds diagnostics from reports the operating system already produces (crash history, battery, system info), still with nothing to install.

| Check | What it tells you | How |
|---|---|---|
| **Outdated browser** | Whether your browser is behind the latest release | The version is read locally and compared with the latest Chrome (per platform) and Firefox/ESR versions published by Google and Mozilla |
| **Secure connection** | TLS version, Encrypted Client Hello, post-quantum key exchange | Cloudflare's public `cdn-cgi/trace` endpoint. TLS 1.2 here often means an antivirus or proxy is inspecting your HTTPS |
| **DNS leak** | Which DNS servers really resolve your lookups | The browser looks up 20 one-off names under `bash.ws`; the free bash.ws service reports which resolvers asked |
| **Leaked password** | Whether a password appears in known breaches | Have I Been Pwned's Pwned Passwords range API with k-anonymity: only the first 5 characters of the SHA-1 hash leave the device |
| **WebRTC leak** | Whether WebRTC reveals a real IP past a VPN or proxy | A STUN request to `stun.cloudflare.com`; the public address WebRTC reports is compared with the connection's IP, per address family (no false alarm on dual-stack IPv4/IPv6) |
| **Trackability** | What any site can read without cookies, and which protections are active | 100 % local: browser, system, time zone, screen, CPU cores, memory, GPU, canvas hash; Global Privacy Control, tracker blocker (bait element), canvas randomisation, Safari's built-in tracking prevention. Stated as an estimate |
| **Internet speed** | Download, upload, ping and jitter, on an animated gauge | Cloudflare's speed endpoints (`speed.cloudflare.com/__down`, `__up`); runs only from its own GO button (up to ~55 MB), each request has a 10 s timeout and the test can be cancelled |
| **System report (Windows)** | A health score for the PC, with the findings and how to fix each one | You save the reports Windows already writes (Reliability history via `perfmon /rel`, `powercfg /batteryreport /output "%USERPROFILE%\Downloads\battery-report.html"`, which saves the battery report in the Downloads folder, `msinfo32` export) and PC Check parses them in the browser. Optional AI explanation of an anonymised summary |
| **System report (Linux)** | The same health score, findings and fixes for a Linux PC | You paste the output of five read-only commands (`uname`/`os-release`, `journalctl` for this boot and the previous one, `upower`, `df`/`lsblk`) and PC Check parses it in the browser; nothing you paste leaves the device. Optional AI explanation of an anonymised summary |
| **System report (Mac)** | The same health score, findings and fixes for a Mac | No Terminal: you save a System Information report as a `.spx` file (File → Save…) and, optionally, choose the crash and panic reports macOS keeps in `/Library/Logs/DiagnosticReports` and `~/Library/Logs/DiagnosticReports` (Finder → Go → Go to Folder…). PC Check parses them in the browser; the files and their names never leave the device. Optional AI explanation of an anonymised summary |
| **System report (iPhone)** | The same health score, findings and fixes for an iPhone (works on iPad too) | Everything happens on the iPhone, in Settings and the Files app: no computer, no app. Turn on Share iPhone Analytics (Settings → Privacy & Security → Analytics & Improvements), open Analytics Data, save a few logs with Share → Save to Files, then choose them in the page with Choose Files; optionally type the battery Maximum Capacity from Settings → Battery → Battery Health. PC Check parses the logs in the browser; the files and their names never leave the device. Optional AI explanation of an anonymised summary |
| **System report (Android)** | Coming soon | |
| **PDF report** | Everything above, with the CyberSecInfo logo | Built in the page at click time and printed (“Save as PDF”); never contains the password or its full hash |

The outdated-browser verdict compares against the Chrome version Google is **actually serving** (a published version can sit at 0 % rollout) and says "rolling out" instead of raising an alarm while a release is under 14 days old.

The page is in English and works in light and dark mode, down to 375 px wide.

## Privacy model

- **Nothing leaves the device before you click.** No request is made on page load beyond the page's own files.
- **Outbound log.** Every request is listed on screen as it happens: destination, purpose and the exact data sent.
- **k-anonymity for passwords.** The password is hashed in the browser; the Pwned Passwords API receives only a 5-character prefix and returns hundreds of matching suffixes (padded with fake ones, `Add-Padding: true`). The comparison happens locally. The input is cleared right after submit and the full hash is never shown.
- **No cookies, no analytics, no ads, no third-party scripts, no browser storage.** Cloudflare's speed endpoints set no cookies either, so the page needs no consent banner.
- **Speed test and WebRTC are opt-in by design.** The speed test only runs from its own button; the STUN request carries no personal data and is listed in the outbound log.
- **Report files and pasted text never leave the device.** The Windows reports, the Linux command output and the Mac System Information and crash reports and the iPhone logs are parsed in the browser; pasted text is never sent, logged or put in the PDF. Mac file names (which carry the computer name) and iPhone log names are never shown, stored or put in the PDF; the iPhone logs never leave the phone. Only if you click "Explain with AI" is a small anonymised JSON summary (shown to you first) sent to Claude (Anthropic) through cybersecinfo.com. Nothing is stored except rate-limit hashes and a daily counter.
- **The server keeps nothing personal.** The PHP proxy stores no IPs, no test IDs, no results. The rate limiter keeps only a salted SHA-256 of the IP for a 10-minute window.

## Architecture

```mermaid
flowchart LR
  subgraph Browser["Visitor's browser"]
    UI["index.html + app.js"]
  end
  subgraph Host["cybersecinfo.com (PHP)"]
    V["api/versions.php<br/>cache 6 h"]
    D["api/dnsleak.php<br/>rate limit 30 / 10 min"]
  end
  UI -- "trace (TLS, ECH, KEX)" --> CF["Cloudflare<br/>cdn-cgi/trace"]
  UI -- "SHA-1 prefix (5 chars)" --> HIBP["Pwned Passwords<br/>range API"]
  UI -- "20 DNS lookups (img)" --> BW1["*.bash.ws"]
  UI -- "GET" --> V
  UI -- "GET id, ip" --> D
  V -- "HTTPS GET" --> G["Google versionhistory API"]
  V -- "HTTPS GET" --> M["Mozilla product-details"]
  D -- "HTTPS POST id, ip" --> BW2["bash.ws dnsleak API"]
```

The browser talks to Cloudflare and Pwned Passwords directly (both send CORS headers). Google, Mozilla and bash.ws are reached through two small PHP endpoints, because they either lack CORS or need a server-side call.

## Security decisions

- **Strict Content Security Policy** (`default-src 'none'`, scripts, styles and fonts from `'self'` only, `connect-src` limited to the four services (Pwned Passwords, two Cloudflare trace hosts, Cloudflare speed), `frame-ancestors 'none'`). No inline scripts or styles; no `innerHTML` with outside data.
- **Hardened PHP proxy** (`api/_lib.php`):
  - GET only (405 otherwise); strict input validation (`id` must match `^[1-9][0-9]{8}$`, `ip` must be a public IP).
  - Outbound calls are HTTPS-only (`CURLPROTO_HTTPS`), certificate verified, redirects off, 9-second timeout, 1 MB response cap.
  - Upstream answers are reduced to the minimum fields, IPs re-validated, control characters stripped, text length and server count capped.
  - Per-IP sliding-window rate limit with `flock`, 429 + `Retry-After`.
  - `_lib.php` and the cache folder are denied by `.htaccess` and also refuse direct execution.
- **Response headers:** `nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, restrictive `Permissions-Policy`.
- **Old-browser friendly:** `app.js` is written in ES2017 on purpose, so outdated browsers can still run the page and be told they are outdated.

## Honest limitations

- The DNS test depends on the free bash.ws service; if it is down, the check says so.
- TLS is measured on the connection to Cloudflare, not to every site you visit.
- Safari and iOS browsers update with the operating system, so their version cannot be compared from a web page; the check gives guidance instead.
- A password that was **not** found in breaches is not necessarily strong; it is just not in the known lists.
- A VPN, ad blocker or corporate network can block some checks; each one then shows "Couldn't check" instead of a guess.

## Tests

From `tests/` (needs PHP 7.4+ with cURL and Node 18+):

```bash
npm install                               # Playwright
npx playwright install chromium
node --check ../assets/app.js && for f in ../api/*.php; do php -l "$f"; done
php php/parsers_test.php                  # parsers with real and hostile upstream fixtures
php php/ratelimit_test.php                # sliding window, IPs never stored in clear
node api/run.mjs                          # endpoints on php -S (BSC_LIVE=1 also hits Google/Mozilla)
node e2e/run.mjs                          # Playwright: every outside service mocked with page.route
```

The end-to-end suite checks that nothing leaves before the click, that the password `password` produces only `/range/5BAA6`, that each failing service shows "Couldn't check" without breaking the page, that the outbound log renders every request, that the page stays English-only even for a Portuguese browser, and takes screenshots in light, dark and 375 px with no horizontal scroll and a visible keyboard focus.

## Deploy (Hostinger or any Apache + PHP host)

Requirements: PHP 7.4+ with cURL (falls back to `file_get_contents` with TLS verification), Apache with `mod_headers` for the security headers.

Upload `index.html`, `.htaccess`, `assets/` and `api/` (with `api/cache/.htaccess`) to `public_html/pccheck/`. Leave out `tests/`, `README.md`, `LICENSE` and `HANDOFF.md`. Make sure `api/cache/` is writable by PHP.

### Configuring the AI explanation

`api/explain.php` reads `ANTHROPIC_API_KEY` and, optionally, `LLM_MODEL` (default `claude-haiku-5-5`) from `grcaudit-config.php`, located three directories above `api/` (outside the web root). The file may return an array, or use `define()` or plain variables. Never commit it. Without a key the endpoint answers 503 `not_configured`.

Limits: POST JSON up to 8 KB, same-origin only, 5 requests per hour per IP and 200 per day overall.

## Credits

- [Pwned Passwords](https://haveibeenpwned.com/Passwords) by Troy Hunt (Have I Been Pwned), CC BY 4.0
- [Cloudflare](https://www.cloudflare.com/) `cdn-cgi/trace`
- [bash.ws](https://bash.ws/) DNS leak test ([terms](https://bash.ws/terms)), integration modelled on their official plugin [macvk/wp-vpn-leak-tests](https://github.com/macvk/wp-vpn-leak-tests)
- [Google Chrome version history API](https://developer.chrome.com/docs/web-platform/versionhistory/guide) and [Mozilla product-details](https://product-details.mozilla.org/1.0/)
- Fonts (self-hosted, SIL Open Font License 1.1): [Orbitron](https://fonts.google.com/specimen/Orbitron) and [Roboto](https://fonts.google.com/specimen/Roboto) (`assets/fonts/OFL-orbitron.txt`, `OFL-roboto.txt`), [Atkinson Hyperlegible Mono](https://www.brailleinstitute.org/freefont/) by the Braille Institute (`OFL-mono.txt`)

## License

MIT, see [LICENSE](LICENSE).
