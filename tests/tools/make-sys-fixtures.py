"""One-off: build anonymised test fixtures from real Windows reports.

Reads the reports from %USERPROFILE%\\Downloads\\pccheck-amostras (never committed) and writes
tests/fixtures/sys/. Personal values are taken from this machine's environment and the reports
themselves, then replaced, so this script holds no personal data.
Run: python -I tests/tools/make-sys-fixtures.py
"""
import os
import re
from datetime import datetime, timedelta

SRC = os.path.join(os.environ['USERPROFILE'], 'Downloads', 'pccheck-amostras')
OUT = os.path.join(os.path.dirname(__file__), '..', 'fixtures', 'sys')
os.makedirs(OUT, exist_ok=True)

COMPUTER = os.environ.get('COMPUTERNAME', '')
USER = os.environ.get('USERNAME', '')


# Installed software that says too much about the owner (banking security modules): replaced by a
# neutral name. The reports are read as UTF-16, so accented names arrive intact; any one-word source ending in " BB"
# (the bank's diagnostics module) is matched without spelling its name.
PRIVATE_SOURCES = re.compile(r'<Source>(?:[^<\s]+ BB|Topaz OFD[^<]*|Warsaw[^<]*|GbPlugin[^<]*)</Source>', re.I)


def scrub(text):
    for word, repl in ((USER, 'USER'), (COMPUTER, 'PC-NAME')):
        if word:
            text = re.sub(re.escape(word), repl, text, flags=re.I)
    return PRIVATE_SOURCES.sub('<Source>ExampleApp.exe</Source>', text)


def read_utf16_or_utf8(path, limit=None):
    raw = open(path, 'rb').read(limit) if limit else open(path, 'rb').read()
    if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return raw.decode('utf-16', errors='replace')
    return raw.decode('utf-8-sig', errors='replace')


def write_utf16(path, text):
    with open(path, 'wb') as f:
        f.write(b'\xff\xfe' + text.replace('\r\n', '\n').replace('\n', '\r\n').encode('utf-16-le'))


# 1. Reliability history: keep the structure, trim to the last 30 days of problems + 200 graph points.
rel = read_utf16_or_utf8(os.path.join(SRC, 'reliability.xml'))
generated = re.search(r'TimeGenerated="([^"]+)"', rel).group(1)
gen_dt = datetime.fromisoformat(generated[:19])
points = re.findall(r'<GraphDataPoint>.*?</GraphDataPoint>', rel, re.S)[:200]


def events(section):
    m = re.search(r'<%s>(.*?)</%s>' % (section, section), rel, re.S)
    return re.findall(r'<Event>.*?</Event>', m.group(1), re.S) if m else []


def keep(ev):
    t = datetime.fromisoformat(re.search(r'<Time>([^<]+)</Time>', ev).group(1)[:19])
    problem = re.search(r'<Problem>([^<]*)</Problem>', ev).group(1)
    if problem in ('Shut down unexpectedly', 'Hardware error', 'Windows was not properly shut down'):
        return t >= gen_dt - timedelta(days=200)   # keep a history of the serious ones
    return t >= gen_dt - timedelta(days=30)


rac = [e for e in events('RacEvents') if keep(e)][:60]
wer = [e for e in events('WerEvents') if keep(e)]
# Cap the noisy "Stopped working" floods while keeping their proportions recognisable.
seen = {}
wer_kept = []
for e in wer:
    src = re.search(r'<Source>([^<]*)</Source>', e).group(1)
    seen[src] = seen.get(src, 0) + 1
    if seen[src] <= 25:
        wer_kept.append(e)


def rel_xml(pts, rac_events, wer_events):
    nl2, nl3 = '\n\t\t', '\n\t\t\t'
    return ('<?xml version="1.0" encoding="utf-16" ?>\n<RelMonReport TimeGenerated="%s">\n\t<GraphData>\n\t\t%s\n\t</GraphData>\n'
            '\t<Events>\n\t\t<RacEvents>\n\t\t\t%s\n\t\t</RacEvents>\n\t\t<WerEvents>\n\t\t\t%s\n\t\t</WerEvents>\n\t</Events>\n</RelMonReport>\n') % (
        generated, nl2.join(pts), nl3.join(rac_events), nl3.join(wer_events))


write_utf16(os.path.join(OUT, 'reliability.xml'), scrub(rel_xml(points, rac, wer_kept)))

# 1b. Synthetic German reliability history: Problem and State are localised UI text, which PC Check
# cannot read in German, so the parser must say so instead of reporting a healthy PC.
REL_DE = [('Stopped responding and was closed', 'Reagiert nicht mehr und wurde geschlossen'),
          ('Stopped working', 'Funktioniert nicht mehr'), ('Shut down unexpectedly', 'Unerwartet heruntergefahren'),
          ('Windows was not properly shut down', 'Windows wurde nicht ordnungsgemäß heruntergefahren'),
          ('Hardware error', 'Hardwarefehler'), ('Failed Windows Update', 'Fehler bei Windows-Update'),
          ('Successful Windows Update', 'Erfolgreiches Windows-Update'),
          ('Successful application installation', 'Erfolgreiche Anwendungsinstallation'),
          ('Successful application reconfiguration', 'Erfolgreiche Neukonfiguration der Anwendung'),
          ('Report sent', 'Bericht gesendet'), ('Not reported', 'Nicht gemeldet')]


def to_de(ev):
    for a, b in REL_DE:
        ev = ev.replace('<Problem>%s</Problem>' % a, '<Problem>%s</Problem>' % b).replace('<State>%s</State>' % a, '<State>%s</State>' % b)
    return ev


write_utf16(os.path.join(OUT, 'reliability-de.xml'),
            scrub(rel_xml(points[:5], [to_de(e) for e in rac[:15]], [to_de(e) for e in wer_kept[:25]])))

# 2. Battery report: replace the computer name and the battery serial number.
bat = open(os.path.join(SRC, 'battery-report.html'), 'rb').read().decode('utf-8-sig')
bat = re.sub(r'(COMPUTER NAME\s*</td><td>)[^<]*', r'\1PC-NAME', bat)
bat = re.sub(r'(SERIAL NUMBER</span></td><td>)[^<]*', r'\1SERIAL', bat)
open(os.path.join(OUT, 'battery-report.html'), 'w', encoding='utf-8', newline='').write(scrub(bat))

# 3. msinfo32: only the head (System Summary) and the Problem Devices section.
msi = read_utf16_or_utf8(os.path.join(SRC, 'msinfo32.txt'), 600000)
head = msi[:msi.index('[Hardware Resources]')]
pd = msi[msi.index('[Problem Devices]'):]
pd = pd[:pd.index('[USB]')]
head = re.sub(r'(System Name:? *\t?)[^\t\r\n]*', r'\1PC-NAME', head)
head = re.sub(r'(Username\t)[^\t\r\n]*', r'\1PC-NAME\\USER', head)
head = re.sub(r'(System SKU\t)[^\t\r\n]*', r'\1SKU', head)
en = scrub(head + pd)
write_utf16(os.path.join(OUT, 'msinfo32-head.txt'), en)

# 4. Synthetic translation: German (unsupported; PC Check reads English reports only).
DE = [('[System Summary]', '[Systemübersicht]'), ('Item\tValue', 'Element\tWert'), ('OS Name', 'Betriebsystemname'),
      ('Version\t', 'Version\t'), ('System Model', 'Systemmodell'), ('Processor', 'Prozessor'),
      ('Installed Physical Memory (RAM)', 'Installierter physischer Speicher (RAM)'), ('BIOS Version/Date', 'BIOS-Version/-Datum'),
      ('[Problem Devices]', '[Problemgeräte]')]
for name, table in (('msinfo32-de.txt', DE),):
    t = en
    for a, b in table:
        t = t.replace(a, b)
    write_utf16(os.path.join(OUT, name), t)

print('ok', {f: os.path.getsize(os.path.join(OUT, f)) for f in os.listdir(OUT)})
