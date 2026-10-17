<?php
/**
 * Parser tests with saved upstream answers. Run: php tests/php/parsers_test.php
 */

define('BSC_API', true);
require __DIR__ . '/../../api/_lib.php';

$fixtures = __DIR__ . '/../fixtures/';
$failures = 0;
$passes = 0;

function check($name, $condition, $extra = null)
{
    global $failures, $passes;
    if ($condition) {
        $passes++;
    } else {
        $failures++;
        fwrite(STDERR, "FAIL: $name" . ($extra !== null ? ' -> ' . json_encode($extra) : '') . "\n");
    }
}

function fixture($file)
{
    global $fixtures;
    return file_get_contents($fixtures . $file);
}

// Chrome (real answer from versionhistory.googleapis.com)
$real = json_decode(fixture('chrome-win.json'), true);
$chrome = bsc_parse_chrome_versions(fixture('chrome-win.json'));
check('chrome real: parsed', is_array($chrome));
check('chrome real: version is the first (highest) entry', $chrome['version'] === $real['versions'][0]['version']);
check('chrome real: major is int of version', $chrome['major'] === (int) $real['versions'][0]['version']);

// Chrome: order is not trusted, garbage is skipped
$unsorted = bsc_parse_chrome_versions(fixture('chrome-unsorted.json'));
check('chrome unsorted: picks highest by version_compare', $unsorted['version'] === '141.0.7390.66');
check('chrome unsorted: major 141', $unsorted['major'] === 141);
check('chrome: empty list -> null', bsc_parse_chrome_versions('{"versions":[]}') === null);
check('chrome: not JSON -> null', bsc_parse_chrome_versions('<html>') === null);
check('chrome: missing versions -> null', bsc_parse_chrome_versions('{"error":{"code":500}}') === null);

// Firefox (real answer from product-details.mozilla.org)
$realFx = json_decode(fixture('firefox.json'), true);
$fx = bsc_parse_firefox_versions(fixture('firefox.json'));
check('firefox real: parsed', is_array($fx));
check('firefox real: latest', $fx['latest'] === $realFx['LATEST_FIREFOX_VERSION']);
check('firefox real: latest_major', $fx['latest_major'] === (int) $realFx['LATEST_FIREFOX_VERSION']);
check('firefox real: esr without suffix', $fx['esr'] === preg_replace('/esr$/', '', $realFx['FIREFOX_ESR']));
check('firefox real: esr_major', $fx['esr_major'] === (int) $realFx['FIREFOX_ESR']);
check('firefox: no latest -> null', bsc_parse_firefox_versions('{"FIREFOX_ESR":"140.4.0esr"}') === null);
check('firefox: not JSON -> null', bsc_parse_firefox_versions('nope') === null);
$noEsr = bsc_parse_firefox_versions('{"LATEST_FIREFOX_VERSION":"144.0"}');
check('firefox: missing esr keeps latest', $noEsr['latest_major'] === 144 && $noEsr['esr'] === null);

// bash.ws: no leak
$ok = bsc_parse_dnsleak(fixture('dnsleak-noleak.json'));
check('dns no leak: parsed', is_array($ok));
check('dns no leak: only type=dns rows become servers', count($ok['servers']) === 2);
check('dns no leak: IPv6 kept', $ok['servers'][1]['ip'] === '2001:4860:4860::8888');
check('dns no leak: fields', $ok['servers'][0] === array('ip' => '8.8.8.8', 'country' => 'US', 'country_name' => 'United States', 'asn' => 'Google LLC'));
check('dns no leak: conclusion text comes from the ip field', $ok['conclusion'] === 'DNS is not leaking.');
check('dns no leak: code', $ok['conclusion_code'] === 'no_leak');

// bash.ws: leak
$leak = bsc_parse_dnsleak(fixture('dnsleak-leak.json'));
check('dns leak: code', $leak['conclusion_code'] === 'leak');
check('dns leak: one server', count($leak['servers']) === 1);

// bash.ws: error record
check('dns error record -> null', bsc_parse_dnsleak(fixture('dnsleak-error.json')) === null);
check('dns not JSON -> null', bsc_parse_dnsleak('<html>502</html>') === null);

// bash.ws: hostile answer is cleaned and capped
$bad = bsc_parse_dnsleak(fixture('dnsleak-hostile.json'));
check('dns hostile: at most 30 servers', count($bad['servers']) === 30);
check('dns hostile: invalid IP dropped', !in_array('999.1.1.1', array_column($bad['servers'], 'ip'), true));
check('dns hostile: no control characters', !preg_match('/[\x00-\x1F\x7F]/', json_encode($bad, JSON_UNESCAPED_UNICODE)));
check('dns hostile: country normalised to 2 upper letters', $bad['servers'][0]['country'] === 'US');
check('dns hostile: asn capped at 120', strlen($bad['servers'][0]['asn']) === 120);
check('dns hostile: conclusion cleaned', $bad['conclusion'] === 'Conclusion text');
check('dns hostile: unknown conclusion code', $bad['conclusion_code'] === 'unknown');
check('dns: no conclusion -> unknown', bsc_parse_dnsleak('[{"type":"dns","ip":"8.8.8.8"}]')['conclusion_code'] === 'unknown');

// Conclusion codes
check('code: not leaking', bsc_conclusion_code('DNS is not leaking.') === 'no_leak');
check('code: no leak', bsc_conclusion_code('No leak detected') === 'no_leak');
check('code: may be leaking', bsc_conclusion_code('DNS may be leaking.') === 'leak');
check('code: other', bsc_conclusion_code('Something else') === 'unknown');

// Chrome releases actually being served (real answer from versionhistory .../releases?filter=endtime=none)
$rel = bsc_parse_chrome_releases(fixture('chrome-releases-win.json'));
check('chrome releases: parsed', is_array($rel));
check('chrome releases: newest served version, not the unserved 156', $rel['version'] === '155.0.8059.85', $rel);
check('chrome releases: major', $rel['major'] === 155);
check('chrome releases: released = startTime of that release, seconds precision', $rel['released'] === '2026-10-15T20:38:35Z', $rel);
check('chrome releases: all fractions 0 -> null', bsc_parse_chrome_releases('{"releases":[{"version":"9.0.0.1","fraction":0,"serving":{"startTime":"2026-01-01T00:00:00Z"}}]}') === null);
check('chrome releases: empty -> null', bsc_parse_chrome_releases('{"releases":[]}') === null);
check('chrome releases: not JSON -> null', bsc_parse_chrome_releases('<html>') === null);
$noTime = bsc_parse_chrome_releases('{"releases":[{"version":"150.0.1.2","fraction":1}]}');
check('chrome releases: missing startTime -> released null', $noTime['version'] === '150.0.1.2' && $noTime['released'] === null);

// Firefox release date
check('firefox real: released', $fx['released'] === $realFx['LAST_RELEASE_DATE']);
check('firefox: missing release date -> null', bsc_parse_firefox_versions('{"LATEST_FIREFOX_VERSION":"144.0"}')['released'] === null);
check('firefox: bad release date -> null', bsc_parse_firefox_versions('{"LATEST_FIREFOX_VERSION":"144.0","LAST_RELEASE_DATE":"soon"}')['released'] === null);

// Helpers
check('https only', bsc_is_https_url('https://x') && !bsc_is_https_url('http://x') && !bsc_is_https_url('file:///etc/passwd'));
check('http_get refuses http://', bsc_http_get('http://example.com/') === null);

echo "parsers: $passes passed, $failures failed\n";
exit($failures ? 1 : 0);
