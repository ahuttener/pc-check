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

// Strict mode (paid key): IPv6 counts by /64, and an unusable window file refuses the call.
$strictBucket = 'tests' . mt_rand(100000, 999999);
$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::1';
bsc_rate_limit($strictBucket, 2, 60, true);
$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2:aaaa:bbbb:cccc:dddd';
bsc_rate_limit($strictBucket, 2, 60, true);
if (bsc_rate_limit($strictBucket, 2, 60, true) < 1) {
    $failures++;
    fwrite(STDERR, "FAIL: strict: addresses in the same IPv6 /64 share one window\n");
}
$_SERVER['REMOTE_ADDR'] = '2001:db8:1:3::1';
if (bsc_rate_limit($strictBucket, 2, 60, true) !== 0) {
    $failures++;
    fwrite(STDERR, "FAIL: strict: another /64 has its own window\n");
}
$_SERVER['REMOTE_ADDR'] = '2001:db8:1:2::1';
if (bsc_rate_limit_file($strictBucket, false) === bsc_rate_limit_file($strictBucket, true)) {
    $failures++;
    fwrite(STDERR, "FAIL: non-strict mode keeps the full IPv6 address\n");
}
// An IPv4-mapped IPv6 address (dual-stack servers report IPv4 clients this way) is the IPv4 address,
// not a /64 shared with every other IPv4 client.
$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.7';
$mapped = bsc_rate_limit_ip(true);
$_SERVER['REMOTE_ADDR'] = '::FFFF:198.51.100.8';
$mappedOther = bsc_rate_limit_ip(true);
if ($mapped !== '198.51.100.7' || $mappedOther !== '198.51.100.8') {
    $failures++;
    fwrite(STDERR, "FAIL: strict: IPv4-mapped IPv6 counts as the IPv4 address, got $mapped / $mappedOther\n");
}
$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.7';
$mappedFile = bsc_rate_limit_file($strictBucket, true);
$_SERVER['REMOTE_ADDR'] = '198.51.100.7';
if ($mappedFile !== bsc_rate_limit_file($strictBucket, true)) {
    $failures++;
    fwrite(STDERR, "FAIL: strict: ::ffff:a.b.c.d and a.b.c.d share one window\n");
}
$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.7';
bsc_rate_limit($strictBucket, 1, 60, true);
$_SERVER['REMOTE_ADDR'] = '::ffff:198.51.100.8';
if (bsc_rate_limit($strictBucket, 1, 60, true) !== 0) {
    $failures++;
    fwrite(STDERR, "FAIL: strict: two IPv4-mapped clients must not share a window\n");
}
foreach ((array) glob(bsc_cache_dir() . '/rl/' . $strictBucket . '-*') as $f) {
    unlink($f);
}
// Make the window file unusable (a directory in its place).
$_SERVER['REMOTE_ADDR'] = '198.51.100.99';
$blocked = bsc_rate_limit_file($strictBucket, true);
mkdir($blocked);
if (bsc_rate_limit($strictBucket, 2, 60, true) < 1) {
    $failures++;
    fwrite(STDERR, "FAIL: strict: unusable window file must fail closed\n");
}
if (bsc_rate_limit($strictBucket, 2, 60, false) !== 0) {
    $failures++;
    fwrite(STDERR, "FAIL: non-strict: unusable window file must fail open\n");
}
rmdir($blocked);

echo 'ratelimit: ' . ($failures ? "$failures failed" : 'all passed') . "\n";
exit($failures ? 1 : 0);
