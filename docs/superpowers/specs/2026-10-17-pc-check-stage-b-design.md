# PC Check — Stage B: system reports for Windows, Mac and Linux (design)

Date: 2026-10-17 · Owner: Adriano Huttener · Live page: https://cybersecinfo.com/pccheck/ · Repo: github.com/ahuttener/pc-check · Builds on Stage A (`2026-10-17-pc-check-stage-a-design.md`).

## Why

Stage A checks what a web page can see from the browser. Visitors also want to know **why their computer misbehaves** (blue screens, crashes, battery, disk) — "System Diagnostics" from the banner — without installing anything. Operating systems already write reports that answer this; PC Check teaches the visitor to save them, reads them **in the browser**, and explains what is wrong and how to fix it. Audiences: ordinary visitors (plain-English diagnosis + steps) and recruiters (careful privacy engineering).

## Goals

1. A **System report** section on the PC Check page with three buttons — **Windows / Mac / Linux** — the visitor's OS pre-selected by detection (userAgent/userAgentData), always changeable (e.g. someone on a phone checking their laptop).
2. A step-by-step guide per OS (owner chose "step by step" in the brainstorm) to produce the reports with tools already on the system.
3. The visitor drops/selects the files (or pastes text, Linux). **All parsing happens in the browser with fixed rules**; nothing is uploaded.
4. A results panel in the Stage A style: a health score, "What we found" list by severity, fact tiles, and fix steps.
5. An optional **"Explain with AI"** button that sends only an anonymised technical summary to Claude through the site's PHP proxy and shows a plain-English explanation.
6. Results included in the Stage A **PDF report**.

## Non-goals / anti-goals

- No download, no installer, no browser extension, and **never ask the visitor to paste commands into PowerShell/Terminal on Windows or Mac** (that is exactly what scammers ask; a security site must not train people to do it). Linux is the exception: read-only commands (`journalctl`, `upower`, `lsblk`, `df`, `uname`) whose output the visitor pastes, each explained.
- No live CPU/RAM/temperature numbers (impossible without software).
- The original files never leave the device. Nothing is stored on the server (no logs of summaries either). No cookies, no analytics, no ads.
- No claim stronger than the data supports (e.g. "battery holds 78 % of its original charge", not "battery is failing" unless < 60 %).

## Constraints

- Same codebase and rules as Stage A: vanilla ES2017, strict CSP (`default-src 'none'`; the AI call goes to `'self'` so `connect-src` needs no change), no `innerHTML` with outside data, English only, outbound log entry for the AI request, tests in Chromium + WebKit, `?v=` bumps, deploy via SSH with backup.
- New parsing code lives in its own file(s) (e.g. `assets/sysreport.js`) exposing pure parsers on `window.__bsc`-style hooks for tests.
- Files are read with `FileReader`/`Blob.text()`; size cap per file (10 MB) and type check; parsing must not freeze the page (yield between big steps or use `DOMParser` once).
- AI: reuse the Anthropic key in `~/domains/cybersecinfo.com/grcaudit-config.php` (outside `public_html`, never sent to the browser), via a new `api/explain.php` using the Stage A hardened helpers (`_lib.php`): POST only, JSON body ≤ 8 KB, strict schema of the summary, per-IP rate limit (5 / hour) and a **global daily cap** (e.g. 200 calls/day, stored as a counter file) so the bill cannot run away, model = the cheapest current Claude model suitable for short explanations (pick with the claude-api skill at plan time), no logging of bodies.

## Reports per OS (decided; formats to be confirmed against real samples in the first plan task)

**Windows** (all built in, saved via GUI):
1. *Crash history* — Reliability Monitor (`Win + R` → `perfmon /rel` → "Save reliability history…") → XML: application failures, Windows failures, **BlueScreen** events with bug-check codes, driver/update installs, per-day stability index.
2. *Battery* (laptops) — `Win + R` → `cmd`… is a command, so instead: Settings has no export; use **`powercfg /batteryreport` only if the visitor is comfortable**? → **Ruling:** battery report is offered for Windows as an *optional* step with a clear note that it is a built-in Windows tool run from the Run box (`Win + R` → `powercfg /batteryreport` → opens nothing, writes `battery-report.html` to the user folder). It is a single read-only built-in command typed in the Run box, not a pasted script; we show exactly what it does. → parse design capacity, full charge capacity, cycle count.
3. *System info* — `Win + R` → `msinfo32` → File → Export (`.txt`) → OS version, model, CPU, RAM, BIOS date, driver problems ("Problem Devices").

**Mac** (System Information app, `Option`-click Apple menu → System Information → File → Save → `.spx`, an XML plist): model, macOS version, memory, storage free/total, **battery cycle count + condition**, plus optional **panic reports** from Console → Crash Reports / `~/Library/Logs/DiagnosticReports/*.panic` or `.ips` files (count + date + top cause).

**Linux** (paste box per command, each explained, all read-only): `uname -a` + `cat /etc/os-release`; `journalctl -p 3 -b -o short` (errors this boot); `journalctl --list-boots | tail -5` (recent unexpected reboots via `-b -1 -p 3`); `upower -i $(upower -e | grep BAT)`; `df -h` + `lsblk -o NAME,SIZE,TYPE,MOUNTPOINT`.

## Privacy: anonymise in the browser

Before anything is shown in the AI summary (and before the PDF), remove: computer name, user name and home paths (`C:\Users\<name>`, `/Users/<name>`, `/home/<name>`), serial numbers, hardware UUIDs, MAC/IP addresses, e-mail addresses, Wi-Fi names. The **AI summary** is a small structured JSON built by our code (counts, codes, versions, percentages) — never raw report text. The page shows the exact JSON before sending ("This is everything that will be sent") and logs the request in the outbound log.

## Findings and scoring (rules)

Each parser emits normalised findings `{id, severity: 'risk'|'warn'|'info'|'ok', title, detail, fix}`. Initial rule set (extendable):
- Blue screens in the last 30 days: ≥ 3 → risk, 1–2 → warn; most frequent bug-check code mapped to a plain-English cause table (e.g. `0x133 DPC_WATCHDOG_VIOLATION` → driver/SSD firmware, `0x50`, `0x1A` → memory, `0x116/0x117` → graphics driver) with the fix.
- Application crashes: top 3 apps by count; ≥ 10 in 30 days → warn.
- Stability index (Windows) latest < 5 → warn.
- Battery: full charge / design < 60 % → risk, < 80 % → warn; cycles shown.
- Disk: free space < 10 % → warn, < 5 % → risk (Mac/Linux; Windows via msinfo32 drives).
- Problem devices / failed drivers → warn with the device name.
- Kernel panics (Mac) ≥ 2 in 30 days → risk.
- OS out of support (Windows 10 after Oct 2025, macOS older than the 3 latest majors) → warn.
- Linux: repeated error units in journal → warn; battery as above; disk as above.
Health score 0–100 = 100 − weighted findings (risk 25, warn 10, info 0), floored at 0; shown with the Stage A visual language (gauge-style ring).

## UI

**Detected-system banner (owner's request):** at the top of the System report panel, a banner "You're on Windows 11" / "You're on macOS 15" / "You're on Linux (Ubuntu)" with the system's icon. Version from `navigator.userAgentData.getHighEntropyValues(['platformVersion'])` where available (Windows 11 = platformVersion major ≥ 13), else the user-agent string; when unknown just the family. On a phone/tablet: "You're on Android/iPhone — this part runs on a computer; you can still read the guide." Icons: simple single-colour glyphs in the site's cyan — Windows four-pane window, Apple glyph, Tux — the same style as the Editor PDF download page, used only to name the system (nominative use), **not** the full-colour official logo artwork, which Apple's and Microsoft's trademark guidelines reserve; Tux is free to use. Inline SVG in the page sprite (no external requests).

Below the banner, a full-width **System report** panel: OS buttons → numbered steps (with a short animated GIF/screenshot per Windows/Mac step) → drop zone / file pickers (or paste boxes on Linux) → results (score ring, findings, tiles, fixes) → "Explain with AI" (optional) → results flow into the PDF. Mobile: works for reading results and pasting; the guide notes the steps are done on the computer.

## Testing

Real sample files (owner's own, anonymised before committing as fixtures; plus synthetic edge cases): parsers unit-tested; anonymiser tested with planted names/serials/MACs; e2e: OS detection + switching, file drop, oversize/wrong file errors, results, AI button (mocked `api/explain.php`), PDF includes the system section and no personal data; PHP tests for `explain.php` (schema validation, size limit, rate limit, daily cap, key never echoed).

## Decisions settled after the builder review (designer's calls)

- **Release slicing:** ship in three slices, each live on its own: **B1 Windows** (owner's PC provides real samples), **B2 Linux** (pasted text; fixtures from real command output on any Linux box / WSL), **B3 Mac** (public sample `.spx`/`.ips` structures + synthetic, refined if a real Mac sample appears). The OS banner, the three buttons and the anonymiser ship in B1; Mac/Linux buttons show "coming soon" until their slice lands.
- **Report languages:** Reliability XML and `.spx` are parsed by structure/keys (language-neutral). Label-based parsing (msinfo32 `.txt`, `battery-report.html`) matches **English and Portuguese** labels; any other language gets a clear message ("This report is in a language PC Check can't read yet — the crash history still works") instead of wrong numbers.
- **Windows battery step (final):** one built-in command typed in the Run box, with an explicit output path so it lands somewhere findable: `powercfg /batteryreport /output "%USERPROFILE%\Desktop\battery-report.html"`. The guide shows exactly what it does ("creates a battery report file on your Desktop; changes nothing"). This is the only typed command on Windows/Mac and is optional. msinfo32 uses its GUI File → Export.
- **Mac panics:** guide uses Finder → Go → Go to Folder (`⇧⌘G`) → `/Library/Logs/DiagnosticReports` and `~/Library/Logs/DiagnosticReports`; parse both `.panic` and `.ips` (first line is a JSON header with `bug_type`, `timestamp`; `bug_type` 210 = kernel panic): count, dates, first line of the panic string.
- **"Last 30 days":** measured back from the report's own generation date (or, if absent, its newest event); the results say "report from <date>"; reports older than 30 days get an info note "this report is <n> days old".
- **PDF:** adds a "System report" section with the anonymised findings and the anonymised fact tiles (OS, model, CPU, RAM, battery %, disk %) — the same data shown on screen; built from state at click time like Stage A.
- **AI disclosure (exact copy):** before sending — "Optional: send this anonymised summary to Claude (Anthropic) through cybersecinfo.com to get a plain-English explanation. Only the summary below is sent — not your files. Nothing is stored." The request appears in the outbound log.

## Open for the owner (to confirm before planning)

1. The owner provides sample reports from his own PC (Reliability XML, battery report, msinfo32 export) so parsers match reality; a Mac and a Linux sample if available (otherwise public samples + synthetic).
2. Daily AI cap value (default 200 explanations/day ≈ a few cents each with the cheapest model).

## Left to the builder

Exact copy, GIF production, cause-table wording, score weights within the rules above, file-picker UX details.
