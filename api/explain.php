<?php
/**
 * POST api/explain.php   body: {"summary": <exactly what PCSys.buildSummary() returns>}
 * Asks Claude (Anthropic) for a plain-English explanation of an anonymised Windows or Linux report summary.
 * The API key lives in grcaudit-config.php OUTSIDE public_html and is never sent to the browser.
 * Nothing is stored except the per-IP rate-limit hashes and the daily counter; bodies are never logged.
 */

define('BSC_API', true);
require __DIR__ . '/_lib.php';
@ini_set('display_errors', '0');

define('BSC_EXPLAIN_MAX_BODY', 8192);
define('BSC_EXPLAIN_PER_IP_HOUR', 5);
define('BSC_EXPLAIN_DAILY_CAP', 200);

// 1. Method
bsc_require_post();

// 1b. Only our own page may spend the key. A cross-site page can still make a visitor's browser send a
// "simple" request (text/plain, form) without a CORS preflight, which would drain the global daily cap.
// Requiring application/json forces a preflight that we never answer; Origin and Sec-Fetch-Site catch the rest.
$contentType = isset($_SERVER['CONTENT_TYPE']) ? strtolower(trim((string) $_SERVER['CONTENT_TYPE'])) : '';
if (!preg_match('#^application/json\s*(;|$)#', $contentType)) {
    bsc_json(415, array('error' => 'unsupported_media_type'));
}
if (isset($_SERVER['HTTP_SEC_FETCH_SITE']) && strtolower((string) $_SERVER['HTTP_SEC_FETCH_SITE']) !== 'same-origin') {
    bsc_json(403, array('error' => 'forbidden_origin'));
}
if (isset($_SERVER['HTTP_ORIGIN'])) {
    $origin = parse_url((string) $_SERVER['HTTP_ORIGIN']);
    $originHost = is_array($origin) && isset($origin['host']) ? strtolower($origin['host']) . (isset($origin['port']) ? ':' . $origin['port'] : '') : '';
    $host = isset($_SERVER['HTTP_HOST']) ? strtolower((string) $_SERVER['HTTP_HOST']) : '';
    if ($originHost === '' || $originHost !== $host) {
        bsc_json(403, array('error' => 'forbidden_origin'));
    }
}

// 2. Size (declared length first, then what actually arrives)
$declared = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
if ($declared > BSC_EXPLAIN_MAX_BODY) {
    bsc_json(413, array('error' => 'too_large'));
}
$in = @fopen('php://input', 'rb');
$raw = $in ? (string) stream_get_contents($in, BSC_EXPLAIN_MAX_BODY + 1) : '';
if ($in) {
    fclose($in);
}
if (strlen($raw) > BSC_EXPLAIN_MAX_BODY) {
    bsc_json(413, array('error' => 'too_large'));
}

// 3. JSON and strict schema
$body = json_decode($raw, true);
if (!is_array($body) || array_keys($body) !== array('summary')) {
    bsc_json(400, array('error' => 'bad_request'));
}
$summary = bsc_validate_summary($body['summary']);
if ($summary === null) {
    bsc_json(400, array('error' => 'bad_request'));
}

// 4. Configuration: ~/domains/cybersecinfo.com/grcaudit-config.php (page is in public_html/pccheck/api/)
$configFile = dirname(__DIR__, 3) . DIRECTORY_SEPARATOR . 'grcaudit-config.php';
// Tests only: PHP's built-in server (never used in production) may point elsewhere, so the test
// suite can guarantee there is no key and the paid upstream is never reached.
if (PHP_SAPI === 'cli-server' && is_string(getenv('BSC_EXPLAIN_CONFIG')) && getenv('BSC_EXPLAIN_CONFIG') !== '') {
    $configFile = getenv('BSC_EXPLAIN_CONFIG');
}
// Array, define() or variables: see bsc_explain_load_config(). The placeholder key counts as missing.
$config = bsc_explain_load_config($configFile);
$apiKey = $config['key'];
$model = $config['model'];
unset($config);
if ($apiKey === '') {
    bsc_json(503, array('error' => 'not_configured'));
}

// 5. Per-IP limit, then 6. the global daily cap (counted only for requests that reach this point)
$wait = bsc_rate_limit('explain', BSC_EXPLAIN_PER_IP_HOUR, 3600, true);
if ($wait > 0) {
    bsc_json(429, array('error' => 'rate_limited'), 'no-store', array('Retry-After' => (string) $wait));
}
if (!bsc_daily_cap('explain', BSC_EXPLAIN_DAILY_CAP)) {
    bsc_json(429, array('error' => 'daily_limit'));
}

// 7. Upstream
$system = bsc_explain_system_prompt(isset($summary['platform']) ? 'linux' : 'windows');

$request = array(
    'model' => $model,
    // Haiku 5.5 thinks by default and thinking counts against max_tokens,
    // so keep effort low and leave room for the ~180-word answer.
    'max_tokens' => 3000,
    'output_config' => array('effort' => 'low'),
    'system' => $system,
    'messages' => array(
        array('role' => 'user', 'content' => json_encode($summary, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)),
    ),
);
$response = bsc_http_post_json('https://api.anthropic.com/v1/messages', array(
    'x-api-key: ' . $apiKey,
    'anthropic-version: 2023-06-01',
    'content-type: application/json',
), $request);
unset($apiKey);

$data = $response === null ? null : json_decode($response, true);
$text = '';
if (is_array($data) && isset($data['content']) && is_array($data['content'])) {
    foreach ($data['content'] as $block) {
        if (is_array($block) && isset($block['type'], $block['text']) && $block['type'] === 'text' && is_string($block['text'])) {
            $text .= $block['text'];
        }
    }
}
$text = trim($text);
if ($text === '') {
    bsc_json(502, array('error' => 'upstream'));
}
if (function_exists('mb_substr')) {
    $text = mb_substr($text, 0, 4000, 'UTF-8');
}

bsc_json(200, array('explanation' => $text, 'model' => $model));
