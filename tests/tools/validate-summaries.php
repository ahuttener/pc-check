<?php
/**
 * Reads a JSON array of summaries on stdin and prints (JSON) one boolean per summary: whether the
 * server's whitelist (bsc_validate_summary in api/_lib.php) accepts it. The e2e suite uses it to prove
 * that what the browser builds is exactly what the server accepts.
 * Run: echo '[{...}]' | php tests/tools/validate-summaries.php
 */
define('BSC_API', true);
require __DIR__ . '/../../api/_lib.php';

$in = json_decode(stream_get_contents(STDIN), true);
$out = array();
foreach (is_array($in) ? $in : array() as $s) {
    $out[] = is_array(bsc_validate_summary($s));
}
echo json_encode($out);
