<?php
/**
 * GET api/versions.php
 * Latest stable Chrome per platform and latest/ESR Firefox, cached for 6 hours.
 */

define('BSC_API', true);
require __DIR__ . '/_lib.php';

bsc_require_get();

$ttl = 6 * 3600;
$age = 0;
$cached = bsc_cache_read('versions', $age);
if ($cached !== null && $age < $ttl) {
    bsc_json(200, $cached, 'public, max-age=3600');
}

$out = array('chrome' => array(), 'firefox' => null, 'updated' => gmdate('Y-m-d\TH:i:s\Z'));
$complete = true;

foreach (array('win', 'mac', 'linux', 'android') as $platform) {
    $base = 'https://versionhistory.googleapis.com/v1/chrome/platforms/' . $platform . '/channels/stable/versions';
    // Prefer the newest version Google is actually serving (a listed version can be at 0 % rollout).
    $body = bsc_http_get($base . '/all/releases?filter=endtime=none');
    $parsed = $body === null ? null : bsc_parse_chrome_releases($body);
    if ($parsed === null) {
        $body = bsc_http_get($base . '?order_by=version%20desc');
        $parsed = $body === null ? null : bsc_parse_chrome_versions($body);
        if ($parsed !== null) {
            $parsed['released'] = null;
        }
    }
    if ($parsed === null) {
        $complete = false;
        continue;
    }
    $out['chrome'][$platform] = $parsed;
}

$body = bsc_http_get('https://product-details.mozilla.org/1.0/firefox_versions.json');
$out['firefox'] = $body === null ? null : bsc_parse_firefox_versions($body);
if ($out['firefox'] === null) {
    $complete = false;
}

if ($complete) {
    bsc_cache_write('versions', $out);
    bsc_json(200, $out, 'public, max-age=3600');
}

// Origin failed: an older full answer beats a partial new one.
if ($cached !== null) {
    bsc_json(200, $cached, 'public, max-age=600');
}

if (!empty($out['chrome']) || $out['firefox'] !== null) {
    if (empty($out['chrome'])) {
        $out['chrome'] = null;
    }
    bsc_json(200, $out, 'no-store');
}

bsc_json(502, array('error' => 'upstream'));
