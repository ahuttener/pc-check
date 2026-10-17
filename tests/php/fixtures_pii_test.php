<?php
/**
 * The system-report fixtures come from a real PC. Fail if any personal identifier survived.
 * Forbidden names come from the environment of the machine that made them, so this file holds none.
 * Run: php tests/php/fixtures_pii_test.php
 */

$dir = __DIR__ . '/../fixtures/sys/';
$files = glob($dir . '*');
$failures = 0;
if (!$files) {
    fwrite(STDERR, "FAIL: no fixtures in tests/fixtures/sys\n");
    exit(1);
}

$forbidden = array_filter(array(getenv('COMPUTERNAME'), getenv('USERNAME'), 'huttener'));
foreach ($files as $file) {
    $raw = file_get_contents($file);
    $text = (substr($raw, 0, 2) === "\xFF\xFE") ? mb_convert_encoding(substr($raw, 2), 'UTF-8', 'UTF-16LE') : $raw;
    foreach ($forbidden as $word) {
        if (stripos($text, $word) !== false) {
            $failures++;
            fwrite(STDERR, 'FAIL: ' . basename($file) . " contains a personal name\n");
        }
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
echo 'fixtures pii: ' . count($files) . ' files, ' . ($failures ? "$failures problems" : 'clean') . "\n";
exit($failures ? 1 : 0);
