<?php
/**
 * PC Check | CyberSecInfo
 * Shared helpers for the two API endpoints. MIT License.
 * PHP 7.4+ on purpose: no match, no str_contains, no nullsafe operator.
 */

if (!defined('BSC_API')) {
    http_response_code(404);
    exit;
}

define('BSC_USER_AGENT', 'CyberSecInfo-PCCheck/1.0 (+https://cybersecinfo.com/pccheck/)');
define('BSC_MAX_BYTES', 1048576);
define('BSC_TIMEOUT', 9);

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

function bsc_json($status, $data, $cacheControl = 'no-store', $extraHeaders = array())
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: ' . $cacheControl);
    foreach ($extraHeaders as $name => $value) {
        header($name . ': ' . $value);
    }
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function bsc_require_get()
{
    $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    if ($method !== 'GET' && $method !== 'HEAD') {
        bsc_json(405, array('error' => 'method_not_allowed'), 'no-store', array('Allow' => 'GET'));
    }
}

function bsc_require_post()
{
    $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
    if ($method !== 'POST') {
        bsc_json(405, array('error' => 'method_not_allowed'), 'no-store', array('Allow' => 'POST'));
    }
}

// ---------------------------------------------------------------------------
// Outbound HTTP: HTTPS only, certificate checked, no redirects, timeout, size cap
// ---------------------------------------------------------------------------

function bsc_is_https_url($url)
{
    return is_string($url) && stripos($url, 'https://') === 0;
}

function bsc_http_request($url, $postFields = null)
{
    if (!bsc_is_https_url($url)) {
        return null;
    }
    $body = is_array($postFields) ? http_build_query($postFields, '', '&') : null;

    if (function_exists('curl_init')) {
        $buffer = '';
        $tooBig = false;
        $ch = curl_init($url);
        $opts = array(
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => BSC_TIMEOUT,
            CURLOPT_USERAGENT => BSC_USER_AGENT,
            CURLOPT_HTTPHEADER => array('Accept: application/json'),
            CURLOPT_WRITEFUNCTION => function ($handle, $chunk) use (&$buffer, &$tooBig) {
                if (strlen($buffer) + strlen($chunk) > BSC_MAX_BYTES) {
                    $tooBig = true;
                    return -1;
                }
                $buffer .= $chunk;
                return strlen($chunk);
            },
        );
        if ($body !== null) {
            $opts[CURLOPT_POST] = true;
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($ok === false || $tooBig || $code !== 200) {
            return null;
        }
        return $buffer;
    }

    $http = array(
        'method' => $body !== null ? 'POST' : 'GET',
        'timeout' => BSC_TIMEOUT,
        'follow_location' => 0,
        'max_redirects' => 0,
        'ignore_errors' => true,
        'header' => "User-Agent: " . BSC_USER_AGENT . "\r\nAccept: application/json\r\n"
            . ($body !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : ''),
    );
    if ($body !== null) {
        $http['content'] = $body;
    }
    $context = stream_context_create(array(
        'http' => $http,
        'ssl' => array('verify_peer' => true, 'verify_peer_name' => true),
    ));
    $data = @file_get_contents($url, false, $context, 0, BSC_MAX_BYTES + 1);
    if ($data === false || strlen($data) > BSC_MAX_BYTES) {
        return null;
    }
    $statusLine = isset($http_response_header[0]) ? $http_response_header[0] : '';
    if (!preg_match('#^HTTP/\S+\s+200\b#', $statusLine)) {
        return null;
    }
    return $data;
}

function bsc_http_get($url)
{
    return bsc_http_request($url, null);
}

function bsc_http_post_form($url, $fields)
{
    return bsc_http_request($url, $fields);
}

/**
 * POST a JSON body (array or already-encoded string) with extra headers ('Name: value' lines).
 * Same rules as bsc_http_request (HTTPS only, certificate checked, no redirects, size cap) but a
 * longer timeout, because a language model answer takes several seconds.
 * Returns the response body on HTTP 200, otherwise null. Nothing is logged.
 */
function bsc_http_post_json($url, $headers, $body, $timeout = 40)
{
    if (!bsc_is_https_url($url)) {
        return null;
    }
    $payload = is_string($body) ? $body : json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    if (!is_string($payload)) {
        return null;
    }
    $headers = array_values((array) $headers);
    $given = strtolower(implode("\n", $headers));
    foreach (array('Accept: application/json', 'Content-Type: application/json') as $default) {
        if (strpos($given, strtolower(strtok($default, ':')) . ':') === false) {
            $headers[] = $default;
        }
    }

    if (function_exists('curl_init')) {
        $buffer = '';
        $tooBig = false;
        $ch = curl_init($url);
        curl_setopt_array($ch, array(
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => (int) $timeout,
            CURLOPT_USERAGENT => BSC_USER_AGENT,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_WRITEFUNCTION => function ($handle, $chunk) use (&$buffer, &$tooBig) {
                if (strlen($buffer) + strlen($chunk) > BSC_MAX_BYTES) {
                    $tooBig = true;
                    return -1;
                }
                $buffer .= $chunk;
                return strlen($chunk);
            },
        ));
        $ok = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if ($ok === false || $tooBig || $code !== 200) {
            return null;
        }
        return $buffer;
    }

    $context = stream_context_create(array(
        'http' => array(
            'method' => 'POST',
            'timeout' => (int) $timeout,
            'follow_location' => 0,
            'max_redirects' => 0,
            'ignore_errors' => true,
            'header' => 'User-Agent: ' . BSC_USER_AGENT . "\r\n" . implode("\r\n", $headers) . "\r\n",
            'content' => $payload,
        ),
        'ssl' => array('verify_peer' => true, 'verify_peer_name' => true),
    ));
    $data = @file_get_contents($url, false, $context, 0, BSC_MAX_BYTES + 1);
    if ($data === false || strlen($data) > BSC_MAX_BYTES) {
        return null;
    }
    $statusLine = isset($http_response_header[0]) ? $http_response_header[0] : '';
    if (!preg_match('#^HTTP/\S+\s+200\b#', $statusLine)) {
        return null;
    }
    return $data;
}

// ---------------------------------------------------------------------------
// File cache and rate limit (api/cache/, denied by .htaccess; falls back to the system temp dir)
// ---------------------------------------------------------------------------

function bsc_cache_dir()
{
    static $dir = null;
    if ($dir !== null) {
        return $dir;
    }
    $local = __DIR__ . DIRECTORY_SEPARATOR . 'cache';
    if ((is_dir($local) || @mkdir($local, 0750, true)) && is_writable($local)) {
        $dir = $local;
    } else {
        $dir = rtrim(sys_get_temp_dir(), '/\\') . DIRECTORY_SEPARATOR . 'bsc-cache';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
    }
    return $dir;
}

function bsc_cache_read($key, &$ageSeconds)
{
    $file = bsc_cache_dir() . DIRECTORY_SEPARATOR . $key . '.json';
    if (!is_file($file)) {
        return null;
    }
    $raw = @file_get_contents($file);
    $data = is_string($raw) ? json_decode($raw, true) : null;
    if (!is_array($data)) {
        return null;
    }
    $ageSeconds = time() - (int) @filemtime($file);
    return $data;
}

function bsc_cache_write($key, $data)
{
    $file = bsc_cache_dir() . DIRECTORY_SEPARATOR . $key . '.json';
    $tmp = $file . '.' . getmypid() . '.tmp';
    if (@file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_SLASHES)) !== false) {
        @rename($tmp, $file);
    }
}

function bsc_client_ip()
{
    return isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}

/**
 * Sliding window per IP. The IP is stored only as a salted SHA-256 hash.
 * Returns 0 when allowed, or the number of seconds to wait.
 */
/**
 * The client key used by the per-IP limit. In strict mode an IPv6 address counts by its /64 prefix,
 * because one connection usually gets a whole /64 and could rotate addresses inside it.
 */
function bsc_rate_limit_ip($strict)
{
    $ip = bsc_client_ip();
    if ($strict && strpos($ip, ':') !== false) {
        $bin = @inet_pton($ip);
        if ($bin !== false && strlen($bin) === 16) {
            return inet_ntop(substr($bin, 0, 8) . str_repeat(chr(0), 8)) . '/64';
        }
    }
    return $ip;
}

/** Window file for this client and bucket (only a salted hash of the IP is used in the name). */
function bsc_rate_limit_file($bucket, $strict = false)
{
    $hash = hash('sha256', $bucket . '|' . bsc_rate_limit_ip($strict) . '|' . __DIR__);
    return bsc_cache_dir() . DIRECTORY_SEPARATOR . 'rl' . DIRECTORY_SEPARATOR . $bucket . '-' . substr($hash, 0, 40);
}

/**
 * $strict = true is for endpoints that spend a paid API key: IPv6 is limited per /64 and,
 * if the window file cannot be opened, the call is refused (fail closed) instead of allowed.
 */
function bsc_rate_limit($bucket, $max, $windowSeconds, $strict = false)
{
    $dir = bsc_cache_dir() . DIRECTORY_SEPARATOR . 'rl';
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }
    if (mt_rand(1, 100) === 1) {
        // Now and then, drop windows nobody has touched for a while.
        foreach ((array) glob($dir . DIRECTORY_SEPARATOR . $bucket . '-*') as $old) {
            if (is_file($old) && filemtime($old) < time() - 2 * $windowSeconds) {
                @unlink($old);
            }
        }
    }
    $file = bsc_rate_limit_file($bucket, $strict);
    $fh = is_dir($file) ? false : @fopen($file, 'c+');
    if (!$fh) {
        // Free upstreams: fail open, the limit protects them, not the visitor. Paid key: fail closed.
        return $strict ? (int) $windowSeconds : 0;
    }
    flock($fh, LOCK_EX);
    $now = time();
    $raw = stream_get_contents($fh);
    $hits = array();
    foreach (explode(',', (string) $raw) as $t) {
        $t = (int) $t;
        if ($t > $now - $windowSeconds) {
            $hits[] = $t;
        }
    }
    $wait = 0;
    if (count($hits) >= $max) {
        $wait = max(1, $hits[0] + $windowSeconds - $now);
    } else {
        $hits[] = $now;
    }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode(',', $hits));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return $wait;
}

/**
 * Global counter per UTC day (cache/daily/<name>-YYYYMMDD), shared by every visitor.
 * Returns true and counts the call when under $max, false once $max calls were counted today.
 * Fails closed: if the counter cannot be opened, the call is refused (it protects a paid API).
 */
function bsc_daily_cap($name, $max)
{
    $name = preg_replace('/[^a-z0-9_]/i', '', (string) $name);
    $dir = bsc_cache_dir() . DIRECTORY_SEPARATOR . 'daily';
    if (!is_dir($dir)) {
        @mkdir($dir, 0750, true);
    }
    $today = gmdate('Ymd');
    $file = $dir . DIRECTORY_SEPARATOR . $name . '-' . $today;
    if (mt_rand(1, 50) === 1) {
        foreach ((array) glob($dir . DIRECTORY_SEPARATOR . $name . '-*') as $old) {
            if ($old !== $file && is_file($old) && filemtime($old) < time() - 3 * 86400) {
                @unlink($old);
            }
        }
    }
    $fh = @fopen($file, 'c+');
    if (!$fh) {
        return false;
    }
    flock($fh, LOCK_EX);
    $count = (int) trim((string) stream_get_contents($fh));
    $allowed = $count < (int) $max;
    if ($allowed) {
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, (string) ($count + 1));
        fflush($fh);
    }
    flock($fh, LOCK_UN);
    fclose($fh);
    return $allowed;
}

// ---------------------------------------------------------------------------
// AI summary whitelist: exactly the shape of PCSys.buildSummary() in assets/sysreport.js
// ---------------------------------------------------------------------------

define('BSC_SUMMARY_FINDING_IDS', 'shutdowns,hardware,crashes,stability,updates,old_report,battery,windows10,devices');
define('BSC_SUMMARY_SEVERITIES', 'risk,warn,info');

function bsc_is_list($value)
{
    return is_array($value) && ($value === array() || array_keys($value) === range(0, count($value) - 1));
}

function bsc_has_exact_keys($value, $keys)
{
    if (!is_array($value) || bsc_is_list($value) && $value !== array()) {
        return false;
    }
    $got = array_keys($value);
    sort($got);
    sort($keys);
    return $got === $keys;
}

/** Short printable string: at most 80 characters, valid UTF-8, no control or format characters (bidi, zero-width). */
function bsc_summary_string($value)
{
    if (!is_string($value) || !preg_match('//u', $value) || preg_match('/\p{Cc}|\p{Cf}/u', $value)) {
        return false;
    }
    $len = function_exists('mb_strlen') ? mb_strlen($value, 'UTF-8') : preg_match_all('/./us', $value);
    return $len <= 80;
}

function bsc_summary_number($value, $min, $max)
{
    return (is_int($value) || is_float($value)) && is_finite((float) $value) && $value >= $min && $value <= $max;
}

function bsc_summary_count($value, $max)
{
    return is_int($value) && $value >= 0 && $value <= $max;
}

/**
 * Validates the summary the browser wants explained. Every key must be present, no other key is
 * allowed, and every value must have the type and range buildSummary() produces.
 * Returns the summary (unchanged) or null.
 */
function bsc_validate_summary($s)
{
    $keys = array('os', 'model', 'ramGb', 'score', 'findings', 'topCrashApps',
        'batteryHealthPct', 'shutdowns30d', 'hardwareErrors30d', 'stabilityNow');
    if (!bsc_has_exact_keys($s, $keys)) {
        return null;
    }
    foreach (array('os', 'model') as $k) {
        if ($s[$k] !== null && !bsc_summary_string($s[$k])) {
            return null;
        }
    }
    if ($s['ramGb'] !== null && !bsc_summary_number($s['ramGb'], 0, 65536)) {
        return null;
    }
    if (!bsc_summary_count($s['score'], 100)) {
        return null;
    }
    if ($s['batteryHealthPct'] !== null && !bsc_summary_number($s['batteryHealthPct'], 0, 200)) {
        return null;
    }
    if ($s['stabilityNow'] !== null && !bsc_summary_number($s['stabilityNow'], 0, 10)) {
        return null;
    }
    foreach (array('shutdowns30d', 'hardwareErrors30d') as $k) {
        if ($s[$k] !== null && !bsc_summary_count($s[$k], 100000)) {
            return null;
        }
    }
    if (!bsc_is_list($s['findings']) || count($s['findings']) > 20) {
        return null;
    }
    $ids = explode(',', BSC_SUMMARY_FINDING_IDS);
    $severities = explode(',', BSC_SUMMARY_SEVERITIES);
    foreach ($s['findings'] as $f) {
        if (!bsc_has_exact_keys($f, array('id', 'severity'))
            || !in_array($f['id'], $ids, true) || !in_array($f['severity'], $severities, true)) {
            return null;
        }
    }
    if (!bsc_is_list($s['topCrashApps']) || count($s['topCrashApps']) > 3) {
        return null;
    }
    foreach ($s['topCrashApps'] as $a) {
        if (!bsc_has_exact_keys($a, array('name', 'count')) || !bsc_summary_string($a['name'])
            || !bsc_summary_count($a['count'], 1000000)) {
            return null;
        }
    }
    return $s;
}

// ---------------------------------------------------------------------------
// Parsers (pure functions, covered by tests/php/parsers_test.php)
// ---------------------------------------------------------------------------

function bsc_clean_text($value, $maxLen)
{
    if (!is_string($value) && !is_numeric($value)) {
        return '';
    }
    $value = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string) $value);
    if ($value === null) {
        return ''; // invalid UTF-8
    }
    $value = trim(preg_replace('/ {2,}/', ' ', $value));
    if (function_exists('mb_substr')) {
        return mb_substr($value, 0, $maxLen, 'UTF-8');
    }
    return preg_replace('/^(.{0,' . (int) $maxLen . '}).*$/us', '$1', $value);
}

function bsc_is_version($v)
{
    return is_string($v) && preg_match('/^\d{1,4}(\.\d{1,6}){0,3}$/', $v);
}

/** versionhistory.googleapis.com body -> array('version' => ..., 'major' => int) or null */
function bsc_parse_chrome_versions($json)
{
    $data = json_decode((string) $json, true);
    if (!is_array($data) || !isset($data['versions']) || !is_array($data['versions'])) {
        return null;
    }
    $best = null;
    foreach ($data['versions'] as $row) {
        $v = is_array($row) && isset($row['version']) ? $row['version'] : null;
        if (!bsc_is_version($v)) {
            continue;
        }
        if ($best === null || version_compare($v, $best, '>')) {
            $best = $v;
        }
    }
    if ($best === null) {
        return null;
    }
    return array('version' => $best, 'major' => (int) $best);
}

/** 'YYYY-MM-DDTHH:MM:SS(.fraction)Z' -> 'YYYY-MM-DDTHH:MM:SSZ', anything else -> null */
function bsc_iso_utc($value)
{
    if (is_string($value) && preg_match('/^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d+)?Z$/', $value, $m)) {
        return $m[1] . 'Z';
    }
    return null;
}

/**
 * versionhistory .../releases?filter=endtime=none body -> newest version actually served
 * (fraction > 0) as array('version', 'major', 'released'), or null.
 * A listed version with fraction 0 is published but reaches nobody yet.
 */
function bsc_parse_chrome_releases($json)
{
    $data = json_decode((string) $json, true);
    if (!is_array($data) || !isset($data['releases']) || !is_array($data['releases'])) {
        return null;
    }
    $best = null;
    foreach ($data['releases'] as $row) {
        if (!is_array($row) || !isset($row['version']) || !bsc_is_version($row['version'])) {
            continue;
        }
        if (!isset($row['fraction']) || !is_numeric($row['fraction']) || $row['fraction'] <= 0) {
            continue;
        }
        if ($best === null || version_compare($row['version'], $best['version'], '>')) {
            $best = $row;
        }
    }
    if ($best === null) {
        return null;
    }
    $start = isset($best['serving']['startTime']) ? $best['serving']['startTime'] : null;
    return array('version' => $best['version'], 'major' => (int) $best['version'], 'released' => bsc_iso_utc($start));
}

/** product-details firefox_versions.json body -> latest/esr or null */
function bsc_parse_firefox_versions($json)
{
    $data = json_decode((string) $json, true);
    if (!is_array($data)) {
        return null;
    }
    $latest = isset($data['LATEST_FIREFOX_VERSION']) ? $data['LATEST_FIREFOX_VERSION'] : null;
    $esr = isset($data['FIREFOX_ESR']) ? preg_replace('/esr$/i', '', (string) $data['FIREFOX_ESR']) : null;
    if (!bsc_is_version($latest)) {
        return null;
    }
    $date = isset($data['LAST_RELEASE_DATE']) ? $data['LAST_RELEASE_DATE'] : null;
    $out = array('latest' => $latest, 'latest_major' => (int) $latest, 'esr' => null, 'esr_major' => null,
        'released' => is_string($date) && preg_match('/^\d{4}-\d\d-\d\d$/', $date) ? $date : null);
    if (bsc_is_version($esr)) {
        $out['esr'] = $esr;
        $out['esr_major'] = (int) $esr;
    }
    return $out;
}

function bsc_conclusion_code($text)
{
    $t = strtolower((string) $text);
    if (strpos($t, 'not leaking') !== false || strpos($t, 'no leak') !== false) {
        return 'no_leak';
    }
    if (strpos($t, 'may be leaking') !== false || strpos($t, 'leak') !== false) {
        return 'leak';
    }
    return 'unknown';
}

/** bash.ws dnsleak JSON body -> array('servers', 'conclusion', 'conclusion_code') or null on error */
function bsc_parse_dnsleak($json)
{
    $data = json_decode((string) $json, true);
    if (!is_array($data) || isset($data['error'])) {
        return null;
    }
    $servers = array();
    $conclusion = '';
    foreach ($data as $row) {
        if (!is_array($row) || !isset($row['type'])) {
            continue;
        }
        if ($row['type'] === 'dns') {
            if (count($servers) >= 30) {
                continue;
            }
            $ip = isset($row['ip']) ? filter_var($row['ip'], FILTER_VALIDATE_IP) : false;
            if ($ip === false) {
                continue;
            }
            $country = isset($row['country']) ? strtoupper(bsc_clean_text($row['country'], 2)) : '';
            $servers[] = array(
                'ip' => $ip,
                'country' => preg_match('/^[A-Z]{2}$/', $country) ? $country : '',
                'country_name' => bsc_clean_text(isset($row['country_name']) ? $row['country_name'] : '', 80),
                'asn' => bsc_clean_text(isset($row['asn']) ? $row['asn'] : '', 120),
            );
        } elseif ($row['type'] === 'conclusion' && $conclusion === '') {
            $conclusion = bsc_clean_text(isset($row['ip']) ? $row['ip'] : '', 200);
        }
    }
    return array(
        'servers' => $servers,
        'conclusion' => $conclusion,
        'conclusion_code' => $conclusion === '' ? 'unknown' : bsc_conclusion_code($conclusion),
    );
}
