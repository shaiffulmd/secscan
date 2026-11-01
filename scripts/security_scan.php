<?php

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("This script is CLI-only.\n");
}

require_once dirname(__DIR__) . '/src/CodebaseScanner.php';

$json = false;
$strict = false;
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--json') {
        $json = true;
    } elseif ($arg === '--strict') {
        $strict = true;
    } elseif ($arg === '--help' || $arg === '-h') {
        echo "SecScan codebase audit (read-only)\n\n";
        echo "Usage: php scripts/security_scan.php [--json] [--strict]\n\n";
        echo "  --json    Output machine-readable JSON without source snippets or secrets\n";
        echo "  --strict  Return exit code 2 when warnings are present\n";
        exit(0);
    } else {
        fwrite(STDERR, "Unknown option: {$arg}\n");
        exit(64);
    }
}

$root = dirname(__DIR__);
$report = (new CodebaseScanner())->scan($root);
$findings = $report['findings'];
$counts = ['critical' => 0, 'warning' => 0, 'info' => 0, 'pass' => 0];
foreach ($findings as $finding) {
    $severity = (string)($finding['severity'] ?? 'info');
    $counts[$severity] = ($counts[$severity] ?? 0) + 1;
}

$report['summary'] = $counts;
$report['exit_code'] = $counts['critical'] > 0 ? 2 : ($counts['warning'] > 0 ? 1 : 0);

if ($json) {
    echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR) . PHP_EOL;
    exit($strict && $report['exit_code'] === 1 ? 2 : $report['exit_code']);
}

echo "============================================================\n";
echo "  SecScan Codebase Audit (read-only)\n";
echo "  Root : {$report['root']}\n";
echo "  Masa : {$report['scanned_at']}\n";
echo "============================================================\n";
echo "  Fail disemak: {$report['stats']['files']} ({$report['stats']['php_files']} PHP)\n\n";

foreach ($findings as $finding) {
    $severity = strtoupper((string)($finding['severity'] ?? 'info'));
    $label = str_pad($severity, 8, ' ', STR_PAD_RIGHT);
    $location = '';
    if (!empty($finding['file'])) {
        $location = ' [' . $finding['file'] . (!empty($finding['line']) ? ':' . $finding['line'] : '') . ']';
    }
    echo "  [{$label}] {$finding['category']}: {$finding['title']}{$location}\n";
    if (($finding['detail'] ?? '') !== '') {
        echo "             {$finding['detail']}\n";
    }
    if (($finding['recommendation'] ?? '') !== '') {
        echo "             -> {$finding['recommendation']}\n";
    }
}

echo "\n============================================================\n";
echo "  Ringkasan: {$counts['pass']} PASS, {$counts['info']} INFO, {$counts['warning']} WARN, {$counts['critical']} CRITICAL\n";
echo "  Exit code: {$report['exit_code']} (gunakan --strict untuk jadikan WARN sebagai gagal CI)\n";
echo "============================================================\n";

exit($strict && $report['exit_code'] === 1 ? 2 : $report['exit_code']);
