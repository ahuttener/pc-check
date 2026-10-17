<?php
/**
 * GET api/dnsleak.php?id=123456789[&ip=203.0.113.7]
 * Asks bash.ws which DNS servers resolved the visitor's 20 test names.
 * Same integration as the official bash.ws plugin (github.com/macvk/wp-vpn-leak-tests).
 */

define('BSC_API', true);
require __DIR__ . '/_lib.php';

bsc_require_get();

$id = isset($_GET['id']) ? (string) $_GET['id'] : '';
if (!preg_match('/^[1-9][0-9]{8}$/', $id)) {
    bsc_json(400, array('error' => 'bad_request'));
}

$wait = bsc_rate_limit('dns', 30, 600);
if ($wait > 0) {
    bsc_json(429, array('error' => 'rate_limited'), 'no-store', array('Retry-After' => (string) $wait));
}

$ip = isset($_GET['ip']) ? filter_var((string) $_GET['ip'], FILTER_VALIDATE_IP,
    FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) : false;
if ($ip === false) {
    $ip = bsc_client_ip();
}

$body = bsc_http_post_form('https://bash.ws/dnsleak/test/' . $id . '?json', array('ip' => $ip));
$result = $body === null ? null : bsc_parse_dnsleak($body);
if ($result === null) {
    bsc_json(502, array('error' => 'upstream'));
}

bsc_json(200, $result);
