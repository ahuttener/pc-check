<?php
/**
 * The system-report fixtures come from a real PC. Fail if any personal identifier survived.
 * Forbidden names come from the environment of the machine that runs the test, plus fixed strings that
 * guard on any machine: the owner's surname and account name, and the banking security modules the
 * owner's PC has installed (the fixture generator renames them to ExampleApp.exe).
 * Run: php tests/php/fixtures_pii_test.php
 */

/** Every e-mail, MAC, IPv4/IPv6 and international phone number in a Linux, Mac, iPhone or Android fixture must be a planted one (Android also: IMEI-like numbers and Wi-Fi names). Returns the number of problems. */
function planted_check($file, $text, $planted, $label = '')
{
    $bad = 0;
    $name = basename($file);
    $found = array(
        'emails' => array(),
        'macs' => array(),
        'ips' => array(),
        'phones' => array(),
    );
    preg_match_all('/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i', $text, $m);
    $found['emails'] = $m[0];
    preg_match_all('/(?<![0-9A-F:-])(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}(?![0-9A-F:-])/i', $text, $m);
    $found['macs'] = $m[0];
    $rest = str_ireplace($found['macs'], ' ', $text);
    preg_match_all('/(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])/', $rest, $m);
    $found['ips'] = $m[0];
    // IPv6: only strings with "::" or at least 4 colon-separated hex groups (PCI addresses and times are not IPs).
    preg_match_all('/(?<![0-9A-F:])(?:[0-9A-F:]*::[0-9A-F:]*|(?:[0-9A-F]{1,4}:){3,}[0-9A-F]{1,4})(?![0-9A-F:])/i', $rest, $m);
    foreach ($m[0] as $v) {
        $found['ips'][] = $v;
    }
    // International phone numbers: only matches with at least 8 digits count (+0100 time zones never do).
    preg_match_all('/\+[1-9][0-9 ().-]{6,20}[0-9]/', $text, $m);
    foreach ($m[0] as $v) {
        if (preg_match_all('/[0-9]/', $v) >= 8) {
            $found['phones'][] = $v;
        }
    }
    if ($label === 'android') {
        $found['imeis'] = array();
        $found['ssids'] = array();
        preg_match_all('/(?<![0-9])[0-9]{15}(?![0-9])/', $text, $m);
        $found['imeis'] = $m[0];
        preg_match_all('/SSID:?\s*"([^"]{1,64})"/i', $text, $m);
        $found['ssids'] = $m[1];
    }
    foreach ($found as $kind => $list) {
        foreach ($list as $v) {
            if (!isset($planted[$kind][strtolower($v)])) {
                $bad++;
                fwrite(STDERR, 'FAIL: ' . $name . ' contains an unplanted ' . $kind . ' value: ' . $v . "
");
            }
        }
    }
    return $bad;
}

$dir = __DIR__ . '/../fixtures/sys/';
$files = array_values(array_filter(glob($dir . '*'), 'is_file'));
$failures = 0;
if (!$files) {
    fwrite(STDERR, "FAIL: no fixtures in tests/fixtures/sys\n");
    exit(1);
}

$fixed = array('huttener', 'AdrianoCH', 'stico BB', 'Topaz OFD', 'Warsaw', 'GbPlugin');
$forbidden = array_unique(array_filter(array_merge(array(getenv('COMPUTERNAME'), getenv('USERNAME')), $fixed)));
$planted = array();
$plantedIpv6 = array();
$groups = array(
    'linux' => array('dir' => $dir . 'linux/', 'glob' => '*.txt'),
    'mac' => array('dir' => $dir . 'mac/', 'glob' => '*'),
    'ios' => array('dir' => $dir . 'ios/', 'glob' => '*'),
    'android' => array('dir' => $dir . 'android/', 'glob' => '*.txt'),
);
$dirFiles = array();
foreach ($groups as $label => $g) {
    $dirFiles[$label] = array();
    $planted[$label] = array();
    if (!is_dir($g['dir']) || !is_file($g['dir'] . 'PLANTED.json')) {
        $failures++;
        fwrite(STDERR, 'FAIL: tests/fixtures/sys/' . $label . "/ or its PLANTED.json is missing\n");
        continue;
    }
    foreach (glob($g['dir'] . $g['glob']) as $f) {
        if (is_file($f) && basename($f) !== 'PLANTED.json') {
            $dirFiles[$label][] = $f;
        }
    }
    $decoded = json_decode(file_get_contents($g['dir'] . 'PLANTED.json'), true);
    if (!is_array($decoded)) {
        $failures++;
        fwrite(STDERR, 'FAIL: ' . $label . "/PLANTED.json is not valid JSON\n");
        continue;
    }
    foreach (array('emails', 'macs', 'ips', 'phones', 'imeis', 'ssids') as $k) {
        foreach (isset($decoded[$k]) ? $decoded[$k] : array() as $v) {
            $planted[$label][$k][strtolower($v)] = true;
            if (($label === 'mac' || $label === 'ios' || $label === 'android') && $k === 'ips' && strpos($v, '::') !== false) {
                $plantedIpv6[] = $v;
            }
        }
    }
}
$androidTool = __DIR__ . '/../tools/make-android-zips.mjs';
if (!is_file($androidTool)) {
    $failures++;
    fwrite(STDERR, "FAIL: tests/tools/make-android-zips.mjs is missing\n");
} else {
    $dirFiles['android'][] = $androidTool;
}
$allFiles = array_merge($files, $dirFiles['linux'], $dirFiles['mac'], $dirFiles['ios'], $dirFiles['android']);
foreach ($allFiles as $file) {
    $label = null;
    foreach ($groups as $l => $g) {
        if (strpos($file, $g['dir']) === 0) {
            $label = $l;
        }
    }
    if ($file === $androidTool) {
        $label = 'android';
    }
    $raw = file_get_contents($file);
    $text = (substr($raw, 0, 2) === "\xFF\xFE") ? mb_convert_encoding(substr($raw, 2), 'UTF-8', 'UTF-16LE') : $raw;
    foreach ($forbidden as $word) {
        if (stripos($text, $word) !== false) {
            $failures++;
            fwrite(STDERR, 'FAIL: ' . basename($file) . " contains a personal name\n");
        }
    }
    if ($label !== null) {
        $failures += planted_check($file, $text, $planted[$label], $label);
        if (($label === 'mac' || $label === 'ios' || $label === 'android') && strpos(str_replace($plantedIpv6, '', $text), '::') !== false) {
            $failures++;
            fwrite(STDERR, 'FAIL: ' . basename($file) . " contains '::' outside a planted IPv6 value\n");
        }
        if (($label === 'ios' || $label === 'android') && preg_match('/\x{00E3}|\x{00F5}|\x{00E7}|\x{00E2}|\x{00EA}|\x{00F4}|\x{00C3}|\x{00D5}|\x{00C7}/u', $text)) {
            // Same accented letters the e2e language grep looks for: no Portuguese in iPhone fixtures.
            $failures++;
            fwrite(STDERR, 'FAIL: ' . basename($file) . " contains an accented letter (Portuguese check)\n");
        }
        continue;
    }
    if (preg_match('/\b(DESKTOP|LAPTOP)-[A-Z0-9]{5,}\b/i', $text)) {
        $failures++;
        fwrite(STDERR, 'FAIL: ' . basename($file) . " contains a default Windows computer name\n");
    }
    if (preg_match('/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i', $text)) {
        $failures++;
        fwrite(STDERR, 'FAIL: ' . basename($file) . " contains an e-mail address\n");
    }
    if (preg_match('/\b([0-9A-F]{2}[:-]){5}[0-9A-F]{2}\b/i', $text)) {
        $failures++;
        fwrite(STDERR, 'FAIL: ' . basename($file) . " contains a MAC address\n");
    }
}
echo 'fixtures pii: ' . count($allFiles) . ' files, ' . ($failures ? "$failures problems" : 'clean') . "\n";
exit($failures ? 1 : 0);
