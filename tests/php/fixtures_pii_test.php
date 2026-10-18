<?php
/**
 * The system-report fixtures come from a real PC. Fail if any personal identifier survived.
 * Forbidden names come from the environment of the machine that runs the test, plus fixed strings that
 * guard on any machine: the owner's surname and account name, and the banking security modules the
 * owner's PC has installed (the fixture generator renames them to ExampleApp.exe).
 * Run: php tests/php/fixtures_pii_test.php
 */

/** Every e-mail, MAC and IPv4/IPv6 in a Linux fixture must be a planted one. Returns the number of problems. */
function linux_check($file, $text, $planted)
{
    $bad = 0;
    $name = basename($file);
    $found = array(
        'emails' => array(),
        'macs' => array(),
        'ips' => array(),
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
$linuxDir = $dir . 'linux/';
$linuxFiles = array();
$planted = array();
if (!is_dir($linuxDir) || !is_file($linuxDir . 'PLANTED.json')) {
    $failures++;
    fwrite(STDERR, "FAIL: tests/fixtures/sys/linux/ or its PLANTED.json is missing
");
} else {
    $linuxFiles = glob($linuxDir . '*.txt');
    $decoded = json_decode(file_get_contents($linuxDir . 'PLANTED.json'), true);
    if (!is_array($decoded)) {
        $failures++;
        fwrite(STDERR, "FAIL: linux/PLANTED.json is not valid JSON
");
    } else {
        foreach (array('emails', 'macs', 'ips') as $k) {
            foreach (isset($decoded[$k]) ? $decoded[$k] : array() as $v) {
                $planted[$k][strtolower($v)] = true;
            }
        }
    }
}
$allFiles = array_merge($files, $linuxFiles);
foreach ($allFiles as $file) {
    $isLinux = strpos($file, $linuxDir) === 0;
    $raw = file_get_contents($file);
    $text = (substr($raw, 0, 2) === "\xFF\xFE") ? mb_convert_encoding(substr($raw, 2), 'UTF-8', 'UTF-16LE') : $raw;
    foreach ($forbidden as $word) {
        if (stripos($text, $word) !== false) {
            $failures++;
            fwrite(STDERR, 'FAIL: ' . basename($file) . " contains a personal name\n");
        }
    }
    if ($isLinux) {
        $failures += linux_check($file, $text, $planted);
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
