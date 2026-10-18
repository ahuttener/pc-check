<?php
/**
 * Prints (JSON) every Unicode code point that the server's summary whitelist rejects on its own
 * (bsc_summary_string, i.e. \p{Cc} or \p{Cf} in this PHP's PCRE). The e2e suite checks that the
 * browser's cap() removes every one of them. Run: php tests/tools/rejected-codepoints.php
 */
define('BSC_API', true);
require __DIR__ . '/../../api/_lib.php';

function utf8_of($c)
{
    if ($c < 0x80) return chr($c);
    if ($c < 0x800) return chr(0xC0 | ($c >> 6)) . chr(0x80 | ($c & 0x3F));
    if ($c < 0x10000) return chr(0xE0 | ($c >> 12)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F));
    return chr(0xF0 | ($c >> 18)) . chr(0x80 | (($c >> 12) & 0x3F)) . chr(0x80 | (($c >> 6) & 0x3F)) . chr(0x80 | ($c & 0x3F));
}

$out = array();
for ($c = 0; $c <= 0x10FFFF; $c++) {
    if ($c >= 0xD800 && $c <= 0xDFFF) continue; // not encodable in UTF-8
    if (!bsc_summary_string(utf8_of($c))) $out[] = $c;
}
echo json_encode($out);
