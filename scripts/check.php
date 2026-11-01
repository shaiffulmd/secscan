<?php

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('This script is CLI-only.');
}

if (!function_exists('exec')) {
    fwrite(STDERR, "PHP exec() is unavailable; use scripts/security_scan.php for an in-process syntax audit.\n");
    exit(2);
}

$root = dirname(__DIR__);
$rii = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS)
);

$phpFiles = [];
foreach ($rii as $file) {
    if (!$file->isFile() || $file->getExtension() !== 'php') {
        continue;
    }

    $path = $file->getPathname();
    if (str_contains($path, DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR)) {
        continue;
    }
    $phpFiles[] = $path;
}

sort($phpFiles);
$failed = false;
foreach ($phpFiles as $file) {
    $cmd = escapeshellcmd(PHP_BINARY) . ' -l ' . escapeshellarg($file);
    exec($cmd, $output, $code);
    foreach ($output as $line) {
        echo $line . PHP_EOL;
    }
    $output = [];
    if ($code !== 0) {
        $failed = true;
    }
}

exit($failed ? 1 : 0);
