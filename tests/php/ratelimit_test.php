<?php
/**
 * Rate limiter test. Run: php tests/php/ratelimit_test.php
 */

define('BSC_API', true);
require __DIR__ . '/../../api/_lib.php';

$failures = 0;
$bucket = 'test' . mt_rand(100000, 999999);
$_SERVER['REMOTE_ADDR'] = '198.51.100.23';

for ($i = 1; $i <= 3; $i++) {
    if (bsc_rate_limit($bucket, 3, 60) !== 0) {
        $failures++;
        fwrite(STDERR, "FAIL: request $i should pass\n");
    }
}
$wait = bsc_rate_limit($bucket, 3, 60);
if ($wait < 1 || $wait > 60) {
    $failures++;
    fwrite(STDERR, "FAIL: 4th request should wait 1..60 s, got $wait\n");
}

$_SERVER['REMOTE_ADDR'] = '198.51.100.24';
if (bsc_rate_limit($bucket, 3, 60) !== 0) {
    $failures++;
    fwrite(STDERR, "FAIL: another IP has its own window\n");
}

$files = glob(bsc_cache_dir() . '/rl/' . $bucket . '-*');
foreach ($files as $f) {
    if (strpos(file_get_contents($f), '198.51.100') !== false || strpos($f, '198.51.100') !== false) {
        $failures++;
        fwrite(STDERR, "FAIL: IP stored in clear in $f\n");
    }
    unlink($f);
}
if (count($files) !== 2) {
    $failures++;
    fwrite(STDERR, "FAIL: expected 2 window files, got " . count($files) . "\n");
}

echo 'ratelimit: ' . ($failures ? "$failures failed" : 'all passed') . "\n";
exit($failures ? 1 : 0);
