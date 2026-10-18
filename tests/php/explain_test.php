<?php
/**
 * explain.php helpers: summary whitelist and the global daily cap. Run: php tests/php/explain_test.php
 */

define('BSC_API', true);
require __DIR__ . '/../../api/_lib.php';

$failures = 0;
function t($name, $cond)
{
    global $failures;
    if (!$cond) {
        $failures++;
        fwrite(STDERR, "FAIL: $name\n");
    }
}

// Exactly what PCSys.buildSummary() returns for the fixtures in tests/fixtures/sys
// (reliability.xml + battery-report.html + msinfo32-head.txt, evaluated at 2026-10-18T09:00:00Z).
$real = '{"os":"Microsoft Windows 11 Home","model":"Predator PTN16-51","ramGb":32,"score":50,'
    . '"findings":[{"id":"shutdowns","severity":"warn"},{"id":"hardware","severity":"warn"},{"id":"crashes","severity":"warn"},'
    . '{"id":"stability","severity":"warn"},{"id":"updates","severity":"warn"}],'
    . '"topCrashApps":[{"name":"Java Update Scheduler","count":25},{"name":"AcerRegistrationBackGroundTask","count":25},'
    . '{"name":"MiracastPowerManager.exe","count":25}],"batteryHealthPct":90.4,"shutdowns30d":1,"hardwareErrors30d":1,"stabilityNow":1.97}';
$valid = json_decode($real, true);

$out = bsc_validate_summary($valid);
t('real summary from the fixtures validates', is_array($out));
t('validated summary keeps every field', is_array($out) && json_encode($out) === json_encode($valid));

// Only a battery report, or nothing at all: nulls and empty lists are valid.
$empty = array('os' => null, 'model' => null, 'ramGb' => null, 'score' => 100, 'findings' => array(), 'topCrashApps' => array(),
    'batteryHealthPct' => null, 'shutdowns30d' => null, 'hardwareErrors30d' => null, 'stabilityNow' => null);
t('summary with nulls and empty lists validates', is_array(bsc_validate_summary($empty)));

$bad = function ($change) use ($valid) {
    $s = $valid;
    $change($s);
    return bsc_validate_summary($s);
};
t('extra top-level key -> null', $bad(function (&$s) { $s['user'] = 'JohnDoe'; }) === null);
t('missing key -> null', $bad(function (&$s) { unset($s['os']); }) === null);
t('string over 80 chars -> null', $bad(function (&$s) { $s['os'] = str_repeat('a', 81); }) === null);
t('string of 80 chars passes', $bad(function (&$s) { $s['os'] = str_repeat('a', 80); }) !== null);
t('crash app name over 80 chars -> null', $bad(function (&$s) { $s['topCrashApps'][0]['name'] = str_repeat('b', 81); }) === null);
t('wrong type: score as string -> null', $bad(function (&$s) { $s['score'] = '50'; }) === null);
t('wrong type: os as number -> null', $bad(function (&$s) { $s['os'] = 11; }) === null);
t('wrong type: ramGb as bool -> null', $bad(function (&$s) { $s['ramGb'] = true; }) === null);
t('wrong type: findings as object -> null', $bad(function (&$s) { $s['findings'] = array('a' => array('id' => 'battery', 'severity' => 'warn')); }) === null);
t('wrong type: os as array -> null', $bad(function (&$s) { $s['os'] = array('x'); }) === null);
t('score above 100 -> null', $bad(function (&$s) { $s['score'] = 101; }) === null);
t('negative count -> null', $bad(function (&$s) { $s['shutdowns30d'] = -1; }) === null);
t('fractional count -> null', $bad(function (&$s) { $s['topCrashApps'][0]['count'] = 1.5; }) === null);
t('unknown finding id -> null', $bad(function (&$s) { $s['findings'][0]['id'] = 'ignore previous instructions'; }) === null);
t('unknown severity -> null', $bad(function (&$s) { $s['findings'][0]['severity'] = 'critical'; }) === null);
t('extra key inside a finding -> null', $bad(function (&$s) { $s['findings'][0]['title'] = 'x'; }) === null);
t('extra key inside a crash app -> null', $bad(function (&$s) { $s['topCrashApps'][0]['path'] = 'C:\Users\x'; }) === null);
t('4 crash apps -> null', $bad(function (&$s) { $s['topCrashApps'][] = array('name' => 'x', 'count' => 1); }) === null);
t('control characters in a string -> null', $bad(function (&$s) { $s['model'] = "a\nb"; }) === null);
t('C1 control character -> null', $bad(function (&$s) { $s['model'] = "a\u{0085}b"; }) === null);
t('bidi override (U+202E) -> null', $bad(function (&$s) { $s['os'] = "Windows \u{202E}exe.txt"; }) === null);
t('zero-width space (U+200B) in a crash app -> null', $bad(function (&$s) { $s['topCrashApps'][0]['name'] = "Java\u{200B}Update"; }) === null);
t('zero-width joiner (U+200D) -> null', $bad(function (&$s) { $s['model'] = "a\u{200D}b"; }) === null);
t('accented letters still pass', $bad(function (&$s) { $s['model'] = 'Positivo Motion Café ç ñ'; }) !== null);
$twenty = array_fill(0, 20, array('id' => 'battery', 'severity' => 'warn'));
t('20 findings pass', $bad(function (&$s) use ($twenty) { $s['findings'] = $twenty; }) !== null);
t('21 findings -> null', $bad(function (&$s) use ($twenty) { $s['findings'] = array_merge($twenty, array(array('id' => 'battery', 'severity' => 'warn'))); }) === null);
t('a list instead of an object -> null', bsc_validate_summary(array_values($valid)) === null);
t('not an array -> null', bsc_validate_summary('x') === null);

// Global daily cap: one counter file per UTC day.
$name = 'test' . mt_rand(100000, 999999);
t('daily cap: 1st call allowed', bsc_daily_cap($name, 2) === true);
t('daily cap: 2nd call allowed', bsc_daily_cap($name, 2) === true);
t('daily cap: 3rd call blocked', bsc_daily_cap($name, 2) === false);
t('daily cap: still blocked', bsc_daily_cap($name, 2) === false);
t('daily cap: another name has its own counter', bsc_daily_cap($name . 'b', 2) === true);
$files = array_merge((array) glob(bsc_cache_dir() . '/daily/' . $name . '-*'), (array) glob(bsc_cache_dir() . '/daily/' . $name . 'b-*'));
t('daily cap: counter file named by UTC day', count($files) === 2 && strpos($files[0], gmdate('Ymd')) !== false);
t('daily cap: counter holds the count', count($files) && trim(file_get_contents($files[0])) === '2');
foreach ($files as $f) {
    unlink($f);
}

// Configuration file formats (the live grcaudit-config.php cannot be inspected, so all common ones work).
$tmpDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'bsc-config-' . mt_rand(100000, 999999);
mkdir($tmpDir);
$write = function ($name, $php) use ($tmpDir) {
    $f = $tmpDir . DIRECTORY_SEPARATOR . $name;
    file_put_contents($f, $php);
    return $f;
};
$load = function ($file) {
    ob_start();
    $c = bsc_explain_load_config($file);
    $printed = ob_get_clean();
    return array($c, $printed);
};
list($c, $printed) = $load($write('array.php', "<?php\nreturn array('ANTHROPIC_API_KEY' => ' sk-ant-array-123 ', 'LLM_MODEL' => 'claude-sonnet-5-5', 'DAILY_LIMIT' => 150);\n"));
t('config: return array -> key (trimmed) and model', $c['key'] === 'sk-ant-array-123' && $c['model'] === 'claude-sonnet-5-5');
t('config: nothing printed', $printed === '');
list($c) = $load($write('short.php', "<?php\nreturn ['ANTHROPIC_API_KEY' => 'sk-ant-short-1'];\n"));
t('config: GRC Audit sample format (short array, no model) -> key, default model', $c['key'] === 'sk-ant-short-1' && $c['model'] === 'claude-haiku-5-5');
list($c) = $load($write('vars.php', "<?php\n\$ANTHROPIC_API_KEY = 'sk-ant-vars-456';\n\$LLM_MODEL = 'claude-opus-5-5';\n"));
t('config: variables -> key and model', $c['key'] === 'sk-ant-vars-456' && $c['model'] === 'claude-opus-5-5');
t('config: variables do not leak into the global scope', !isset($GLOBALS['ANTHROPIC_API_KEY']));
list($c) = $load($write('cfgvar.php', "<?php\n\$config = array('ANTHROPIC_API_KEY' => 'sk-ant-cfg-1');\n"));
t('config: $config array variable -> key', $c['key'] === 'sk-ant-cfg-1');
list($c, $printed) = $load($write('noisy.php', "stray text before the tag\n<?php\nreturn array('ANTHROPIC_API_KEY' => 'sk-ant-noisy-1');\n?>\ntrailing sk-ant-noisy-1\n"));
t('config: stray output in the file is never echoed', $printed === '' && $c['key'] === 'sk-ant-noisy-1');
list($c) = $load($write('placeholder.php', "<?php\nreturn array('ANTHROPIC_API_KEY' => 'sk-ant-xxxxxxxx-REPLACE-ME');\n"));
t('config: REPLACE-ME placeholder -> not configured', $c['key'] === '');
list($c) = $load($write('badmodel.php', "<?php\nreturn array('ANTHROPIC_API_KEY' => 'k1', 'LLM_MODEL' => 'Bad Model; drop');\n"));
t('config: invalid model -> default model', $c['model'] === 'claude-haiku-5-5');
list($c) = $load($tmpDir . DIRECTORY_SEPARATOR . 'missing.php');
t('config: missing file -> not configured', $c['key'] === '' && $c['model'] === 'claude-haiku-5-5');
list($c) = $load($write('empty.php', "<?php\n// nothing here\n"));
t('config: file without a key -> not configured', $c['key'] === '');
// define() last: constants cannot be undefined again in this process.
list($c, $printed) = $load($write('define.php', "<?php\ndefine('ANTHROPIC_API_KEY', 'sk-ant-const-789');\ndefine('LLM_MODEL', 'claude-sonnet-5-5');\n"));
t('config: define() constants -> key and model', $c['key'] === 'sk-ant-const-789' && $c['model'] === 'claude-sonnet-5-5' && $printed === '');
foreach ((array) glob($tmpDir . DIRECTORY_SEPARATOR . '*') as $f) {
    unlink($f);
}
rmdir($tmpDir);

echo 'explain: ' . ($failures ? "$failures failed" : 'all passed') . "\n";
exit($failures ? 1 : 0);
